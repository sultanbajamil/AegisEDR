using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisAgent.Models;
using AegisAgent.Services;

namespace AegisAgent
{
    public static class Program
    {
        private static string _agentId = string.Empty;
        private static readonly string ServerUrl = "http://127.0.0.1:8000"; // Local FastAPI dev server URL
        private static readonly string ConfigFileName = "agent_id.txt";

        private static ProcessMonitor? _processMonitor;
        private static RegistryMonitor? _registryMonitor;
        private static FileMonitor? _fileMonitor;
        private static NetworkMonitor? _networkMonitor;
        private static AgentClient? _agentClient;
        private static Timer? _heartbeatTimer;
        private static readonly CancellationTokenSource Cts = new();

        public static async Task Main(string[] args)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("=================================================================");
            Console.WriteLine("                   AEGIS LIGHTWEIGHT EDR AGENT                   ");
            Console.WriteLine("=================================================================");
            Console.ResetColor();

            // 1. Initialize or load unique Agent ID
            LoadOrCreateAgentId();
            Console.WriteLine($"[*] Agent Identifier: {_agentId}");

            // 2. Initialize Agent API Client
            _agentClient = new AgentClient(ServerUrl, _agentId);

            // 3. Register with Central Server
            Console.WriteLine("[*] Registering agent with server...");
            bool registered = await _agentClient.RegisterAsync();
            if (!registered)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("[!] AegisServer was unreachable during startup. Running in offline fallback mode (will keep retrying).");
                Console.ResetColor();
            }

            // 4. Initialize and start monitors
            Console.WriteLine("[*] Initializing telemetry monitors...");
            
            // Callback to report alerts to the server
            Action<AlertPayload> alertHandler = async (alert) =>
            {
                // Print alert to local agent console
                PrintAlertToConsole(alert);
                
                // Send alert to server
                if (_agentClient != null)
                {
                    await _agentClient.SendAlertAsync(alert);
                }
            };

            _processMonitor = new ProcessMonitor(_agentId, alertHandler);
            _registryMonitor = new RegistryMonitor(_agentId, alertHandler);
            _fileMonitor = new FileMonitor(_agentId, alertHandler);
            _networkMonitor = new NetworkMonitor(_agentId, alertHandler);

            // Start monitors
            _processMonitor.Start();
            _registryMonitor.Start();
            _fileMonitor.Start();
            _networkMonitor.Start();

            // 5. Start periodic heartbeat and command polling
            _heartbeatTimer = new Timer(async (state) =>
            {
                if (_agentClient != null)
                {
                    await _agentClient.PollHeartbeatAndCommandsAsync();
                }
            }, null, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(5));

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("[*] Aegis EDR Agent is active and monitoring.");
            Console.WriteLine("[*] Press Ctrl+C to terminate the agent cleanly.");
            Console.ResetColor();
            Console.WriteLine("=================================================================");

            // Setup graceful exit
            Console.CancelKeyPress += (sender, eventArgs) =>
            {
                eventArgs.Cancel = true;
                Cts.Cancel();
            };

            // Keep the main thread alive until cancelled
            try
            {
                await Task.Delay(Timeout.Infinite, Cts.Token);
            }
            catch (TaskCanceledException)
            {
                // Normal shutdown flow
            }

            // Clean shutdown
            Shutdown();
        }

        private static void LoadOrCreateAgentId()
        {
            try
            {
                if (File.Exists(ConfigFileName))
                {
                    _agentId = File.ReadAllText(ConfigFileName).Trim();
                }

                // If file is empty or missing, generate a new one
                if (string.IsNullOrEmpty(_agentId))
                {
                    _agentId = Guid.NewGuid().ToString();
                    File.WriteAllText(ConfigFileName, _agentId);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error loading agent ID, generating volatile fallback: {ex.Message}");
                _agentId = Guid.NewGuid().ToString();
            }
        }

        private static void PrintAlertToConsole(AlertPayload alert)
        {
            lock (Console.Out)
            {
                Console.WriteLine();
                if (alert.severity == "CRITICAL")
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.Write("[CRITICAL] ");
                }
                else if (alert.severity == "WARNING")
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.Write("[WARNING] ");
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Blue;
                    Console.Write("[INFO] ");
                }

                Console.ResetColor();
                Console.WriteLine($"{alert.alert_type} Alert: {alert.description}");
                
                if (alert.details != null)
                {
                    foreach (var pair in alert.details)
                    {
                        if (pair.Value != null && !string.IsNullOrWhiteSpace(pair.Value.ToString()))
                        {
                            Console.WriteLine($"  -> {pair.Key}: {pair.Value}");
                        }
                    }
                }
                Console.WriteLine();
            }
        }

        private static void Shutdown()
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n[*] Shutting down Aegis Agent...");
            Console.ResetColor();

            _heartbeatTimer?.Change(Timeout.Infinite, Timeout.Infinite);
            _heartbeatTimer?.Dispose();

            _processMonitor?.Stop();
            _registryMonitor?.Stop();
            _fileMonitor?.Stop();
            _networkMonitor?.Stop();

            Console.WriteLine("[*] Aegis Agent stopped cleanly.");
        }
    }
}
