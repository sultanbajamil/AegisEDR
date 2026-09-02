using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using AegisAgent.Models;

namespace AegisAgent.Services
{
    public class FileMonitor
    {
        private readonly string _agentId;
        private readonly Action<AlertPayload> _onAlertDetected;
        private readonly List<FileSystemWatcher> _watchers = new();

        public FileMonitor(string agentId, Action<AlertPayload> onAlertDetected)
        {
            _agentId = agentId;
            _onAlertDetected = onAlertDetected;
        }

        public void Start()
        {
            try
            {
                // Watch User Startup folder
                string userStartup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
                if (Directory.Exists(userStartup))
                {
                    SetupWatcher(userStartup, "User Startup Folder");
                }

                // Watch Common/Global Startup folder (requires admin, but setup watcher anyway)
                string commonStartup = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
                if (Directory.Exists(commonStartup))
                {
                    SetupWatcher(commonStartup, "Common Startup Folder");
                }

                Console.WriteLine("[*] File System Monitor started.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error starting File Monitor: {ex.Message}");
            }
        }

        public void Stop()
        {
            foreach (var watcher in _watchers)
            {
                watcher.EnableRaisingEvents = false;
                watcher.Dispose();
            }
            _watchers.Clear();
            Console.WriteLine("[*] File System Monitor stopped.");
        }

        private void SetupWatcher(string directoryPath, string description)
        {
            var watcher = new FileSystemWatcher(directoryPath)
            {
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime,
                Filter = "*.*", // Watch all files
                IncludeSubdirectories = true
            };

            watcher.Created += (s, e) => HandleFileEvent(e.FullPath, "CREATED", description);
            watcher.Changed += (s, e) => HandleFileEvent(e.FullPath, "CHANGED", description);
            watcher.Deleted += (s, e) => HandleFileEvent(e.FullPath, "DELETED", description);
            watcher.Renamed += (s, e) => HandleFileEvent(e.FullPath, "RENAMED", description, e.OldFullPath);

            watcher.EnableRaisingEvents = true;
            _watchers.Add(watcher);
            Console.WriteLine($"[*] Monitoring file changes in '{description}': {directoryPath}");
        }

        private void HandleFileEvent(string filePath, string action, string directoryName, string oldPath = "")
        {
            // Ignore temporary files created by editors or OS locks (like .tmp)
            if (filePath.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase) || 
                filePath.EndsWith(".crdownload", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            // Small delay to let the writing process release file locks so we can read the MD5 hash
            if (action == "CREATED" || action == "CHANGED" || action == "RENAMED")
            {
                System.Threading.Thread.Sleep(500);
            }

            string severity = "INFO";
            string description = $"File {action.ToLower()} in {directoryName}: {Path.GetFileName(filePath)}";
            bool isSuspicious = false;

            string extension = Path.GetExtension(filePath).ToLower();
            var executableExtensions = new List<string> { ".exe", ".dll", ".bat", ".cmd", ".vbs", ".ps1", ".lnk", ".scr", ".js", ".vbe" };

            if (action != "DELETED")
            {
                if (executableExtensions.Contains(extension))
                {
                    severity = "CRITICAL";
                    description = $"Suspicious Executable File Drop: Code/Script file '{Path.GetFileName(filePath)}' added/modified in startup directory";
                    isSuspicious = true;
                }
                else
                {
                    severity = "WARNING";
                    description = $"Non-standard File dropped in Startup: '{Path.GetFileName(filePath)}'";
                }
            }

            string fileHash = "N/A (File deleted or inaccessible)";
            if (action != "DELETED" && File.Exists(filePath))
            {
                fileHash = CalculateMD5(filePath);
            }

            var details = new Dictionary<string, object>
            {
                { "file_path", filePath },
                { "action", action },
                { "directory_type", directoryName },
                { "file_hash", fileHash },
                { "extension", extension },
                { "is_suspicious", isSuspicious }
            };

            if (!string.IsNullOrEmpty(oldPath))
            {
                details["old_file_path"] = oldPath;
            }

            var alert = new AlertPayload
            {
                agent_id = _agentId,
                alert_type = "FILE",
                severity = severity,
                description = description,
                details = details
            };

            _onAlertDetected(alert);
        }

        private string CalculateMD5(string filename)
        {
            try
            {
                using var md5 = MD5.Create();
                using var stream = File.OpenRead(filename);
                var hash = md5.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
            catch (Exception ex)
            {
                return $"Error hashing file: {ex.Message}";
            }
        }
    }
}
