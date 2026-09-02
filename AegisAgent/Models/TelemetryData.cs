using System;
using System.Collections.Generic;

namespace AegisAgent.Models
{
    public class AgentRegistration
    {
        public string id { get; set; } = string.Empty;
        public string hostname { get; set; } = string.Empty;
        public string ip_address { get; set; } = string.Empty;
        public string os_version { get; set; } = string.Empty;
    }

    public class AgentHeartbeat
    {
        public string id { get; set; } = string.Empty;
        public string hostname { get; set; } = string.Empty;
        public string ip_address { get; set; } = string.Empty;
        public string os_version { get; set; } = string.Empty;
    }

    public class AlertPayload
    {
        public string agent_id { get; set; } = string.Empty;
        public string alert_type { get; set; } = string.Empty; // PROCESS, REGISTRY, FILE, NETWORK
        public string severity { get; set; } = string.Empty; // INFO, WARNING, CRITICAL
        public string description { get; set; } = string.Empty;
        public Dictionary<string, object> details { get; set; } = new();
    }

    public class CommandResultPayload
    {
        public string command_id { get; set; } = string.Empty;
        public string status { get; set; } = string.Empty; // COMPLETED, FAILED
        public string result { get; set; } = string.Empty;
    }

    // Agent representation of a server command
    public class ServerCommand
    {
        public string id { get; set; } = string.Empty;
        public string command_type { get; set; } = string.Empty; // KILL_PROCESS, ISOLATE_NETWORK, DIAGNOSTIC
        public string arguments { get; set; } = string.Empty;
    }

    public class HeartbeatResponse
    {
        public string status { get; set; } = string.Empty;
        public List<ServerCommand> commands { get; set; } = new();
    }
}
