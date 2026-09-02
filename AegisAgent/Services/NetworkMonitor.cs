using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using System.Threading;
using AegisAgent.Models;

namespace AegisAgent.Services
{
    public class NetworkMonitor
    {
        private readonly string _agentId;
        private readonly Action<AlertPayload> _onAlertDetected;
        private Timer? _pollingTimer;
        private readonly HashSet<string> _activeConnectionsCache = new();

        // Common C2/shell ports
        private readonly HashSet<string> _suspiciousPorts = new()
        {
            "4444", "5555", "7777", "8888", "9999", "8080", "31337"
        };

        public NetworkMonitor(string agentId, Action<AlertPayload> onAlertDetected)
        {
            _agentId = agentId;
            _onAlertDetected = onAlertDetected;
        }

        public void Start()
        {
            try
            {
                // Poll every 5 seconds
                _pollingTimer = new Timer(PollConnections, null, TimeSpan.FromSeconds(3), TimeSpan.FromSeconds(5));
                Console.WriteLine("[*] Network Connection Monitor started.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error starting Network Monitor: {ex.Message}");
            }
        }

        public void Stop()
        {
            _pollingTimer?.Change(Timeout.Infinite, Timeout.Infinite);
            _pollingTimer?.Dispose();
            Console.WriteLine("[*] Network Connection Monitor stopped.");
        }

        private void PollConnections(object? state)
        {
            var currentSnapshot = new HashSet<string>();
            var connections = GetEstablishedConnections();

            foreach (var conn in connections)
            {
                string connectionKey = $"{conn.Pid}-{conn.LocalAddress}-{conn.RemoteAddress}";
                currentSnapshot.Add(connectionKey);

                // If connection is new, analyze it
                if (!_activeConnectionsCache.Contains(connectionKey))
                {
                    AnalyzeConnection(conn);
                }
            }

            // Sync cache (removes closed connections)
            _activeConnectionsCache.Clear();
            foreach (var key in currentSnapshot)
            {
                _activeConnectionsCache.Add(key);
            }
        }

        private void AnalyzeConnection(TcpConnectionDetails conn)
        {
            string remoteIp = conn.RemoteIp;
            string remotePort = conn.RemotePort;

            // Ignore local and private range IPs
            if (IsLocalOrPrivateIp(remoteIp))
            {
                return;
            }

            string severity = "INFO";
            string description = $"Outbound Network Connection: Process '{conn.ProcessName}' (PID: {conn.Pid}) connected to {remoteIp}:{remotePort}";
            bool isSuspicious = false;

            if (_suspiciousPorts.Contains(remotePort))
            {
                severity = "CRITICAL";
                description = $"Suspicious Outbound Port: Process '{conn.ProcessName}' (PID: {conn.Pid}) established connection to suspicious port {remotePort} on {remoteIp}";
                isSuspicious = true;
            }

            var details = new Dictionary<string, object>
            {
                { "process_name", conn.ProcessName },
                { "pid", conn.Pid },
                { "local_address", conn.LocalAddress },
                { "remote_address", conn.RemoteAddress },
                { "remote_ip", remoteIp },
                { "remote_port", remotePort },
                { "is_suspicious", isSuspicious }
            };

            var alert = new AlertPayload
            {
                agent_id = _agentId,
                alert_type = "NETWORK",
                severity = severity,
                description = description,
                details = details
            };

            _onAlertDetected(alert);
        }

        private List<TcpConnectionDetails> GetEstablishedConnections()
        {
            var list = new List<TcpConnectionDetails>();
            try
            {
                var startInfo = new ProcessStartInfo
                {
                    FileName = "netstat",
                    Arguments = "-ano -p tcp",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };

                using var process = Process.Start(startInfo);
                if (process == null) return list;

                using var reader = process.StandardOutput;
                string? line;
                while ((line = reader.ReadLine()) != null)
                {
                    if (!line.Contains("ESTABLISHED")) continue;

                    // Clean up multiple whitespaces
                    var parts = Regex.Split(line.Trim(), @"\s+");
                    if (parts.Length < 5) continue;

                    string local = parts[1];
                    string remote = parts[2];
                    string state = parts[3];
                    string pidStr = parts[4];

                    if (!int.TryParse(pidStr, out int pid)) continue;

                    // Extract Remote IP and Port
                    string remoteIp = "0.0.0.0";
                    string remotePort = "0";

                    int lastColon = remote.LastIndexOf(':');
                    if (lastColon > 0)
                    {
                        remoteIp = remote.Substring(0, lastColon).Replace("[", "").Replace("]", "");
                        remotePort = remote.Substring(lastColon + 1);
                    }

                    string procName = GetProcessNameById(pid);

                    list.Add(new TcpConnectionDetails
                    {
                        LocalAddress = local,
                        RemoteAddress = remote,
                        RemoteIp = remoteIp,
                        RemotePort = remotePort,
                        Pid = pid,
                        ProcessName = procName
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error querying active TCP connections: {ex.Message}");
            }
            return list;
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

        private bool IsLocalOrPrivateIp(string ipAddress)
        {
            if (ipAddress == "127.0.0.1" || ipAddress == "0.0.0.0" || ipAddress == "::1" || ipAddress == "::")
                return true;

            if (IPAddress.TryParse(ipAddress, out var ip))
            {
                // Check if IPv6 Link-Local
                if (ip.IsIPv6LinkLocal) return true;

                byte[] bytes = ip.GetAddressBytes();
                if (bytes.Length == 4) // IPv4
                {
                    // 10.0.0.0/8
                    if (bytes[0] == 10) return true;
                    // 172.16.0.0/12
                    if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
                    // 192.168.0.0/16
                    if (bytes[0] == 192 && bytes[1] == 168) return true;
                    // 169.254.0.0/16 (APIPA)
                    if (bytes[0] == 169 && bytes[1] == 254) return true;
                }
            }
            return false;
        }

        private class TcpConnectionDetails
        {
            public string LocalAddress { get; set; } = string.Empty;
            public string RemoteAddress { get; set; } = string.Empty;
            public string RemoteIp { get; set; } = string.Empty;
            public string RemotePort { get; set; } = string.Empty;
            public int Pid { get; set; }
            public string ProcessName { get; set; } = string.Empty;
        }
    }
}
