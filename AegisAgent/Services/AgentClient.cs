using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Net.Http.Json;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading.Tasks;
using System.Net;
using AegisAgent.Models;

namespace AegisAgent.Services
{
    public class AgentClient
    {
        private readonly string _serverUrl;
        private readonly string _agentId;
        private readonly string _hostname;
        private readonly HttpClient _httpClient;

        public AgentClient(string serverUrl, string agentId)
        {
            _serverUrl = serverUrl.TrimEnd('/');
            _agentId = agentId;
            _hostname = Environment.MachineName;
            
            _httpClient = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(10)
            };
        }

        public async Task<bool> RegisterAsync()
        {
            try
            {
                var payload = new AgentRegistration
                {
                    id = _agentId,
                    hostname = _hostname,
                    ip_address = GetLocalIPAddress(),
                    os_version = Environment.OSVersion.ToString()
                };

                var response = await _httpClient.PostAsJsonAsync($"{_serverUrl}/api/agent/register", payload);
                if (response.IsSuccessStatusCode)
                {
                    Console.WriteLine("[*] Agent registered successfully with AegisServer.");
                    return true;
                }
                
                Console.WriteLine($"[!] Registration failed. Server status: {response.StatusCode}");
                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Failed to connect to AegisServer during registration: {ex.Message}");
                return false;
            }
        }

        public async Task PollHeartbeatAndCommandsAsync()
        {
            try
            {
                var payload = new AgentHeartbeat
                {
                    id = _agentId,
                    hostname = _hostname,
                    ip_address = GetLocalIPAddress(),
                    os_version = Environment.OSVersion.ToString()
                };

                var response = await _httpClient.PostAsJsonAsync($"{_serverUrl}/api/agent/heartbeat", payload);
                if (!response.IsSuccessStatusCode)
                {
                    Console.WriteLine($"[!] Heartbeat failed. Server status: {response.StatusCode}");
                    return;
                }

                var result = await response.Content.ReadFromJsonAsync<HeartbeatResponse>();
                if (result != null && result.commands != null && result.commands.Count > 0)
                {
                    foreach (var cmd in result.commands)
                    {
                        Console.WriteLine($"[*] Received Server Command: {cmd.command_type} (Args: {cmd.arguments})");
                        // Run async so we don't block heartbeat polling
                        _ = Task.Run(() => ExecuteCommandAsync(cmd));
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error during heartbeat poll: {ex.Message}");
            }
        }

        public async Task SendAlertAsync(AlertPayload alert)
        {
            try
            {
                var response = await _httpClient.PostAsJsonAsync($"{_serverUrl}/api/agent/telemetry", alert);
                if (response.IsSuccessStatusCode)
                {
                    Console.WriteLine($"[*] Sent alert to server: {alert.description} ({alert.severity})");
                }
                else
                {
                    Console.WriteLine($"[!] Failed to send alert: {response.StatusCode}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Network error sending alert to server: {ex.Message}");
            }
        }

        private async Task ExecuteCommandAsync(ServerCommand cmd)
        {
            var resultPayload = new CommandResultPayload
            {
                command_id = cmd.id,
                status = "COMPLETED"
            };

            try
            {
                switch (cmd.command_type.ToUpper())
                {
                    case "KILL_PROCESS":
                        resultPayload.result = KillProcess(cmd.arguments);
                        break;
                    case "ISOLATE_NETWORK":
                        resultPayload.result = ToggleNetworkIsolation(cmd.arguments);
                        break;
                    case "DIAGNOSTIC":
                        resultPayload.result = RunDiagnostic();
                        break;
                    default:
                        resultPayload.status = "FAILED";
                        resultPayload.result = $"Unknown command type: {cmd.command_type}";
                        break;
                }
            }
            catch (Exception ex)
            {
                resultPayload.status = "FAILED";
                resultPayload.result = $"Execution Error: {ex.Message}";
            }

            // Report execution result back to server
            try
            {
                var response = await _httpClient.PostAsJsonAsync($"{_serverUrl}/api/agent/command/result", resultPayload);
                if (response.IsSuccessStatusCode)
                {
                    Console.WriteLine($"[*] Successfully reported command execution: {cmd.id}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Network error reporting command execution result: {ex.Message}");
            }
        }

        private string KillProcess(string arg)
        {
            if (!int.TryParse(arg, out int pid))
            {
                return $"Error: PID '{arg}' is not a valid integer.";
            }

            try
            {
                using var proc = Process.GetProcessById(pid);
                string procName = proc.ProcessName;
                proc.Kill(true); // Terminate process and all descendants
                return $"Success: Terminated process '{procName}' (PID: {pid}) and its child processes.";
            }
            catch (ArgumentException)
            {
                return $"Error: Process with PID {pid} is not currently running.";
            }
            catch (Exception ex)
            {
                return $"Error: Failed to terminate process {pid}. Reason: {ex.Message}";
            }
        }

        private string ToggleNetworkIsolation(string arg)
        {
            bool isolate = arg.Trim().ToUpper() == "ON";
            string agentExePath = Process.GetCurrentProcess().MainModule?.FileName ?? "";

            if (string.IsNullOrEmpty(agentExePath))
            {
                return "Error: Could not retrieve current agent executable path.";
            }

            try
            {
                if (isolate)
                {
                    // Add firewall blocks
                    RunShellCommand("netsh", "advfirewall firewall add rule name=\"Aegis_Block_All_Out\" dir=out action=block profile=any");
                    RunShellCommand("netsh", "advfirewall firewall add rule name=\"Aegis_Block_All_In\" dir=in action=block profile=any");
                    
                    // Add exclude rule for AegisAgent itself so it stays connected to control panel
                    RunShellCommand("netsh", $"advfirewall firewall add rule name=\"Aegis_Allow_Agent_Out\" dir=out action=allow program=\"{agentExePath}\" profile=any");
                    RunShellCommand("netsh", $"advfirewall firewall add rule name=\"Aegis_Allow_Agent_In\" dir=in action=allow program=\"{agentExePath}\" profile=any");

                    return "Success: Host isolated from network. All network connections blocked except AegisAgent client traffic.";
                }
                else
                {
                    // Remove firewall rules
                    RunShellCommand("netsh", "advfirewall firewall delete rule name=\"Aegis_Block_All_Out\"");
                    RunShellCommand("netsh", "advfirewall firewall delete rule name=\"Aegis_Block_All_In\"");
                    RunShellCommand("netsh", "advfirewall firewall delete rule name=\"Aegis_Allow_Agent_Out\"");
                    RunShellCommand("netsh", "advfirewall firewall delete rule name=\"Aegis_Allow_Agent_In\"");

                    return "Success: Network isolation removed. Full network connectivity restored.";
                }
            }
            catch (Exception ex)
            {
                return $"Error: Failed to apply network isolation rules. Reason: {ex.Message} (Ensure agent runs with Administrator privileges)";
            }
        }

        private string RunDiagnostic()
        {
            var writer = new StringWriter();
            writer.WriteLine("--- Sentinel AegisEDR Endpoint Diagnostics ---");
            writer.WriteLine($"Timestamp: {DateTime.UtcNow} UTC");
            writer.WriteLine($"Host Name: {Environment.MachineName}");
            writer.WriteLine($"OS Version: {Environment.OSVersion}");
            writer.WriteLine($"Architecture: {Environment.OSVersion.Platform} (64-bit: {Environment.Is64BitOperatingSystem})");
            writer.WriteLine($"Agent PID: {Process.GetCurrentProcess().Id}");
            
            // Log local IPs
            writer.WriteLine("Local IP Addresses:");
            foreach (var ip in Dns.GetHostAddresses(Dns.GetHostName()))
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    writer.WriteLine($"  - {ip}");
                }
            }

            // Count running processes
            var processes = Process.GetProcesses();
            writer.WriteLine($"Active Processes Count: {processes.Length}");

            // Quick disk space
            writer.WriteLine("Storage Devices:");
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (drive.IsReady)
                {
                    writer.WriteLine($"  - Drive {drive.Name} ({drive.DriveFormat}): {drive.AvailableFreeSpace / (1024 * 1024 * 1024)} GB free / {drive.TotalSize / (1024 * 1024 * 1024)} GB total");
                }
            }

            return writer.ToString();
        }

        private void RunShellCommand(string cmd, string args)
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = cmd,
                Arguments = args,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardError = true,
                RedirectStandardOutput = true
            };

            using var process = Process.Start(startInfo);
            process?.WaitForExit();
            
            if (process?.ExitCode != 0)
            {
                string error = process?.StandardError.ReadToEnd() ?? "";
                throw new Exception($"Shell command '{cmd} {args}' exited with code {process?.ExitCode}. Error: {error}");
            }
        }

        private string GetLocalIPAddress()
        {
            try
            {
                // Retrieve local active IPv4 address
                foreach (var netInterface in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (netInterface.OperationalStatus == OperationalStatus.Up && 
                        netInterface.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    {
                        var ipProps = netInterface.GetIPProperties();
                        foreach (var addr in ipProps.UnicastAddresses)
                        {
                            if (addr.Address.AddressFamily == AddressFamily.InterNetwork)
                            {
                                return addr.Address.ToString();
                            }
                        }
                    }
                }
            }
            catch
            {
                // Fallback
            }
            return "127.0.0.1";
        }
    }
}
