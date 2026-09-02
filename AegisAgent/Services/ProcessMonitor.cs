using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using AegisAgent.Models;

namespace AegisAgent.Services
{
    public class ProcessMonitor
    {
        private ManagementEventWatcher? _startWatcher;
        private readonly Action<AlertPayload> _onAlertDetected;
        private readonly string _agentId;

        public ProcessMonitor(string agentId, Action<AlertPayload> onAlertDetected)
        {
            _agentId = agentId;
            _onAlertDetected = onAlertDetected;
        }

        public void Start()
        {
            try
            {
                // Query process start events every 1 second
                var startQuery = new WqlEventQuery(
                    "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'");
                
                _startWatcher = new ManagementEventWatcher(startQuery);
                _startWatcher.EventArrived += ProcessStarted;
                _startWatcher.Start();
                
                Console.WriteLine("[*] Process Monitor started successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error starting Process Monitor: {ex.Message}");
            }
        }

        public void Stop()
        {
            if (_startWatcher != null)
            {
                _startWatcher.Stop();
                _startWatcher.Dispose();
                Console.WriteLine("[*] Process Monitor stopped.");
            }
        }

        private void ProcessStarted(object sender, EventArrivedEventArgs e)
        {
            try
            {
                var targetInstance = (ManagementBaseObject)e.NewEvent["TargetInstance"];
                
                string processName = targetInstance["Name"]?.ToString() ?? "Unknown";
                string pidStr = targetInstance["ProcessId"]?.ToString() ?? "0";
                string ppidStr = targetInstance["ParentProcessId"]?.ToString() ?? "0";
                string commandLine = targetInstance["CommandLine"]?.ToString() ?? "";
                string exePath = targetInstance["ExecutablePath"]?.ToString() ?? "";

                int pid = int.Parse(pidStr);
                int ppid = int.Parse(ppidStr);

                string parentName = GetProcessNameById(ppid);

                // Run security checks on the new process
                AnalyzeProcess(processName, pid, parentName, ppid, commandLine, exePath);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error handling process start event: {ex.Message}");
            }
        }

        private void AnalyzeProcess(string processName, int pid, string parentName, int ppid, string commandLine, string exePath)
        {
            string severity = "INFO";
            string description = $"Process spawned: {processName} (PID: {pid})";
            bool isSuspicious = false;

            string cmdLower = commandLine.ToLower();
            string procLower = processName.ToLower();
            string parentLower = parentName.ToLower();

            // Rule 1: Office document or Web Server spawning a shell (Web Shell or Phishing Macro execution)
            var webAndOfficeProcs = new List<string> { "w3wp.exe", "httpd.exe", "nginx.exe", "sqlservr.exe", "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe" };
            var shellProcs = new List<string> { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "bash.exe" };

            if (webAndOfficeProcs.Contains(parentLower) && shellProcs.Contains(procLower))
            {
                severity = "CRITICAL";
                description = $"Suspicious Parent-Child Process: Web/Office app '{parentName}' spawned shell '{processName}'";
                isSuspicious = true;
            }
            // Rule 2: Evasion or post-exploitation commands
            else if (cmdLower.Contains("bypass") && (cmdLower.Contains("powershell") || cmdLower.Contains("pwsh")))
            {
                severity = "WARNING";
                description = $"Powershell Bypass Execution: Command line contains execution policy bypass";
                isSuspicious = true;
            }
            else if (cmdLower.Contains("downloadstring") || cmdLower.Contains("webclient") || cmdLower.Contains("invoke-webrequest") || cmdLower.Contains("iwr "))
            {
                severity = "CRITICAL";
                description = $"Potential Malware Download: Process command line contains download patterns";
                isSuspicious = true;
            }
            else if (cmdLower.Contains("vssadmin") && cmdLower.Contains("delete") && cmdLower.Contains("shadows"))
            {
                severity = "CRITICAL";
                description = $"Ransomware Activity Detected: Attempting to delete Volume Shadow Copies (vssadmin)";
                isSuspicious = true;
            }
            else if (cmdLower.Contains("whoami") || cmdLower.Contains("net user") || cmdLower.Contains("ipconfig /all") || cmdLower.Contains("net localgroup"))
            {
                // Common discovery/recon tools run in short succession or by suspicious parents
                if (shellProcs.Contains(parentLower) || parentLower.Contains("unknown"))
                {
                    severity = "WARNING";
                    description = $"Reconnaissance Command Executed: '{processName}' executing network/user discovery";
                    isSuspicious = true;
                }
            }
            else if (procLower == "certutil.exe" && (cmdLower.Contains("-urlcache") || cmdLower.Contains("-split")))
            {
                severity = "CRITICAL";
                description = $"Lolbin Abuse: 'certutil' used for file download";
                isSuspicious = true;
            }
            else if (procLower == "rundll32.exe" && string.IsNullOrWhiteSpace(commandLine))
            {
                severity = "WARNING";
                description = $"Suspicious Execution: 'rundll32.exe' running without arguments (potential masquerading)";
                isSuspicious = true;
            }
            else if (procLower == "rundll32.exe" && cmdLower.Contains("comsvcs.dll") && (cmdLower.Contains("minidump") || cmdLower.Contains("#24")))
            {
                severity = "CRITICAL";
                description = "Credential Theft Attempt: LSASS memory dump via comsvcs.dll in rundll32";
                isSuspicious = true;
            }
            else if (procLower == "mimikatz.exe" || procLower == "procdump.exe" || procLower == "procdump64.exe" || procLower == "dumpert.exe" || procLower == "nanodump.exe")
            {
                severity = "CRITICAL";
                description = $"Credential Theft Tool Spawned: Known memory dumper '{processName}' launched";
                isSuspicious = true;
            }
            else if (cmdLower.Contains("lsass") && (cmdLower.Contains("minidump") || cmdLower.Contains("comsvcs") || cmdLower.Contains("procdump")))
            {
                severity = "CRITICAL";
                description = "Credential Dumping Activity: Command line indicates attempt to read or dump LSASS memory";
                isSuspicious = true;
            }

            // Create details dictionary
            var details = new Dictionary<string, object>
            {
                { "process_name", processName },
                { "pid", pid },
                { "parent_name", parentName },
                { "parent_pid", ppid },
                { "command_line", commandLine },
                { "executable_path", exePath },
                { "signer", VerifyFileSignature(exePath) },
                { "is_suspicious", isSuspicious }
            };

            // Build alert payload
            var alert = new AlertPayload
            {
                agent_id = _agentId,
                alert_type = "PROCESS",
                severity = severity,
                description = description,
                details = details
            };

            // Invoke callback to report alert
            _onAlertDetected(alert);
        }

        private string GetProcessNameById(int pid)
        {
            if (pid <= 0) return "System";
            try
            {
                using var proc = Process.GetProcessById(pid);
                return proc.ProcessName + ".exe";
            }
            catch
            {
                return "Unknown";
            }
        }

        private string VerifyFileSignature(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                return "Unsigned / Unknown (File not found)";

            try
            {
                // In production, we'd use WinTrust APIs or Authenticode validation in .NET:
                // X509Certificate.CreateFromSignedFile(filePath)
                // For simplicity, we check if file exists and return a mock status,
                // indicating whether it is in System32 (generally signed by Microsoft) vs temp dirs.
                if (filePath.ToLower().Contains("c:\\windows\\system32"))
                {
                    return "Signed (Microsoft Windows Publisher)";
                }
                
                return "Unsigned / Untrusted";
            }
            catch
            {
                return "Verification Failed";
            }
        }
    }
}
