using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using Microsoft.Win32;
using AegisAgent.Models;

namespace AegisAgent.Services
{
    public class RegistryMonitor
    {
        private readonly string _agentId;
        private readonly Action<AlertPayload> _onAlertDetected;
        private Timer? _pollingTimer;
        private readonly Dictionary<string, string> _registryCache = new();
        
        // Registry hives and paths we want to monitor for persistence
        private readonly (RegistryKey Hive, string SubKey, string DisplayPath)[] _targetPaths = new[]
        {
            (Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run", @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"),
            (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run", @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run")
        };

        public RegistryMonitor(string agentId, Action<AlertPayload> onAlertDetected)
        {
            _agentId = agentId;
            _onAlertDetected = onAlertDetected;
        }

        public void Start()
        {
            try
            {
                // Initialize cache
                InitializeCache();

                // Poll every 5 seconds
                _pollingTimer = new Timer(PollRegistry, null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
                Console.WriteLine("[*] Registry Persistence Monitor started.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error starting Registry Monitor: {ex.Message}");
            }
        }

        public void Stop()
        {
            _pollingTimer?.Change(Timeout.Infinite, Timeout.Infinite);
            _pollingTimer?.Dispose();
            Console.WriteLine("[*] Registry Persistence Monitor stopped.");
        }

        private void InitializeCache()
        {
            _registryCache.Clear();
            foreach (var path in _targetPaths)
            {
                try
                {
                    using var key = path.Hive.OpenSubKey(path.SubKey);
                    if (key == null) continue;

                    foreach (var valueName in key.GetValueNames())
                    {
                        var valueData = key.GetValue(valueName)?.ToString() ?? "";
                        var cacheKey = $"{path.DisplayPath}\\{valueName}";
                        _registryCache[cacheKey] = valueData;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] Registry Monitor initialization warning for {path.DisplayPath}: {ex.Message}");
                }
            }
        }

        private void PollRegistry(object? state)
        {
            var currentSnapshot = new Dictionary<string, string>();

            foreach (var path in _targetPaths)
            {
                try
                {
                    using var key = path.Hive.OpenSubKey(path.SubKey);
                    if (key == null) continue;

                    foreach (var valueName in key.GetValueNames())
                    {
                        var valueData = key.GetValue(valueName)?.ToString() ?? "";
                        var cacheKey = $"{path.DisplayPath}\\{valueName}";
                        currentSnapshot[cacheKey] = valueData;

                        // Check if key is new or modified
                        if (!_registryCache.TryGetValue(cacheKey, out var cachedValue))
                        {
                            // New key added!
                            AnalyzeRegistryModification(path.DisplayPath, valueName, valueData, "ADDED");
                        }
                        else if (cachedValue != valueData)
                        {
                            // Key modified!
                            AnalyzeRegistryModification(path.DisplayPath, valueName, valueData, "MODIFIED", cachedValue);
                        }
                    }
                }
                catch (Exception ex)
                {
                    // Access denied or registry locking can occur occasionally on HKLM paths
                    Console.WriteLine($"[!] Registry polling warning: {ex.Message}");
                }
            }

            // Check if any key was deleted
            foreach (var cachedKey in _registryCache.Keys)
            {
                if (!currentSnapshot.ContainsKey(cachedKey))
                {
                    // Key deleted
                    var parts = cachedKey.Split('\\');
                    var valueName = parts[^1];
                    var path = cachedKey.Substring(0, cachedKey.Length - valueName.Length - 1);
                    AnalyzeRegistryModification(path, valueName, "", "DELETED");
                }
            }

            // Update local cache
            _registryCache.Clear();
            foreach (var kvp in currentSnapshot)
            {
                _registryCache[kvp.Key] = kvp.Value;
            }
        }

        private void AnalyzeRegistryModification(string keyPath, string valueName, string valueData, string action, string previousData = "")
        {
            string severity = "WARNING";
            string description = $"Registry Persistence Alert: '{valueName}' was {action.ToLower()} in {keyPath}";
            bool isSuspicious = false;

            if (action == "DELETED")
            {
                severity = "INFO";
                description = $"Registry persistence deleted: '{valueName}' removed from {keyPath}";
            }
            else
            {
                // Inspect valueData for suspicious file paths (like AppData, Temp, or command scripts)
                string valLower = valueData.ToLower();
                if (valLower.Contains("temp") || valLower.Contains("appdata") || valLower.Contains("localdata") || valLower.Contains("downloads"))
                {
                    severity = "CRITICAL";
                    description = $"Suspicious Registry Persistence: Startup key '{valueName}' points to user-writable directory (Temp/AppData)";
                    isSuspicious = true;
                }
                else if (valLower.Contains("powershell") || valLower.Contains("cmd.exe") || valLower.Contains("wscript") || valLower.Contains("mshta"))
                {
                    severity = "CRITICAL";
                    description = $"Registry Persistence Alert: Scripting engine '{valueName}' added to startup registry";
                    isSuspicious = true;
                }
            }

            var details = new Dictionary<string, object>
            {
                { "key_path", keyPath },
                { "value_name", valueName },
                { "written_value", valueData },
                { "action", action },
                { "previous_value", previousData },
                { "is_suspicious", isSuspicious }
            };

            var alert = new AlertPayload
            {
                agent_id = _agentId,
                alert_type = "REGISTRY",
                severity = severity,
                description = description,
                details = details
            };

            _onAlertDetected(alert);
        }
    }
}
