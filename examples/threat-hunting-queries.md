# Threat Hunting with LCQL

<!-- 
  Developed by Digital Defense Institute (https://digitaldefenseinstitute.com)
  Collection of threat hunting queries for proactive security monitoring.
  These queries are designed to identify suspicious patterns and anomalies.
  Adjust time ranges and thresholds based on your environment.
-->

> **⚠️ REQUIRES VALIDATION**  
> These queries are starting points for investigation. All findings must be validated by security professionals.  
> False positives are expected - tune queries for your specific environment.

## 🎯 Living Off the Land (LOTL) Techniques

### Suspicious PowerShell Usage

```lcql
# Base64 encoded commands
-6h | plat == windows | NEW_PROCESS | 
event/FILE_PATH contains "powershell.exe" AND event/COMMAND_LINE contains "-enc" |
event/FILE_PATH as Process 
event/COMMAND_LINE as EncodedCommand 
event/USER_NAME as User
routing/hostname as Host

# Download and execute patterns
-6h | plat == windows | NEW_PROCESS | 
event/FILE_PATH contains "powershell.exe" AND 
(event/COMMAND_LINE contains "downloadstring" OR 
 event/COMMAND_LINE contains "downloadfile" OR
 event/COMMAND_LINE contains "invoke-webrequest" OR
 event/COMMAND_LINE contains "iwr") |
event/COMMAND_LINE as Command
event/USER_NAME as User
routing/hostname as Host

# Suspicious execution policies
-6h | plat == windows | NEW_PROCESS | 
event/FILE_PATH contains "powershell.exe" AND 
event/COMMAND_LINE contains "-executionpolicy bypass" |
event/COMMAND_LINE as Command
routing/hostname as Host
COUNT(Host) as Count
GROUP BY(Host, Command)
```

### WMIC Abuse

```lcql
# Remote WMIC execution
-24h | plat == windows | NEW_PROCESS | 
event/FILE_PATH contains "wmic.exe" AND 
event/COMMAND_LINE contains "/node:" |
event/COMMAND_LINE as Command
event/USER_NAME as User
routing/hostname as SourceHost

# WMIC process creation
-24h | plat == windows | NEW_PROCESS | 
event/FILE_PATH contains "wmic.exe" AND 
event/COMMAND_LINE contains "process call create" |
event/COMMAND_LINE as Command
routing/hostname as Host
```

### Rundll32 Abuse

```lcql
# Rundll32 without DLL argument (suspicious)
-6h | plat == windows | NEW_PROCESS | 
event/FILE_PATH contains "rundll32.exe" AND 
event/COMMAND_LINE not contains ".dll" |
event/COMMAND_LINE as SuspiciousCommand
event/PARENT/FILE_PATH as Parent
routing/hostname as Host

# Rundll32 with network activity
-6h | plat == windows | NETWORK_CONNECTIONS | 
event/FILE_PATH contains "rundll32.exe" |
event/FILE_PATH as Process
event/NETWORK_ACTIVITY/DESTINATION/IP_ADDRESS as DestIP
event/NETWORK_ACTIVITY/DESTINATION/PORT as Port
routing/hostname as Host
```

## 🔧 Named Pipe Analysis

### Overview
Named pipes are often used by malware for inter-process communication and C2 channels. You can hunt for suspicious named pipes using either LimaCharlie's native events or Sysmon telemetry.

### Check Sysmon Coverage First

```lcql
# Verify Sysmon is collecting pipe events
-24h | plat == windows | WEL | 
event/EVENT/System/Channel == "Microsoft-Windows-Sysmon/Operational" |
event/EVENT/System/EventID as EventID 
COUNT(EventID) as Count 
GROUP BY(EventID) 
ORDER BY Count DESC

# Look for Event IDs 17 and 18 in results
```

### Hunt for Suspicious Named Pipes

```lcql
# Known malicious pipe patterns (high fidelity)
-24h | * | WEL | 
event/EVENT/EventData/PipeName exists AND 
(event/EVENT/EventData/PipeName contains "\\postex_" OR 
 event/EVENT/EventData/PipeName contains "\\msagent_" OR 
 event/EVENT/EventData/PipeName contains "\\MSSE-" OR 
 event/EVENT/EventData/PipeName contains "\\status_") |
event/EVENT/EventData/PipeName as PipeName 
event/EVENT/EventData/Image as Process 
event/EVENT/System/EventID as EventType 
routing/hostname as Host 
ts as Timestamp

# Suspicious processes creating named pipes
-24h | * | WEL | 
event/EVENT/EventData/PipeName exists AND 
event/EVENT/EventData/PipeName != "<Anonymous Pipe>" AND 
(event/EVENT/EventData/Image contains "rundll32" OR 
 event/EVENT/EventData/Image contains "regsvr32" OR 
 event/EVENT/EventData/Image contains "mshta" OR 
 event/EVENT/EventData/Image contains "wscript" OR 
 event/EVENT/EventData/Image contains "cscript" OR 
 event/EVENT/EventData/Image contains "\\Temp\\" OR 
 event/EVENT/EventData/Image contains "\\AppData\\Local\\Temp\\") |
event/EVENT/EventData/PipeName as PipeName 
event/EVENT/EventData/Image as Process 
event/EVENT/System/EventID as EventType 
routing/hostname as Host 
ts as Timestamp
```

### Analyze Rare Named Pipes

```lcql
# Find all unique named pipes sorted by occurrence
-6h | * | WEL | 
event/EVENT/EventData/PipeName exists AND 
event/EVENT/EventData/PipeName != "<Anonymous Pipe>" |
event/EVENT/EventData/PipeName as PipeName 
COUNT(PipeName) as Occurrences 
GROUP BY(PipeName) 
ORDER BY Occurrences ASC

# Find single-occurrence pipes from suspicious processes
# Note: Review results manually for pipes with Count=1 from suspicious processes
-24h | * | WEL | 
event/EVENT/EventData/PipeName exists |
event/EVENT/EventData/PipeName as PipeName 
event/EVENT/EventData/Image as Process
COUNT(PipeName) as Count 
GROUP BY(PipeName, Process) 
ORDER BY Count ASC
```

### Known Malicious Pipe Indicators

| Pipe Pattern | Associated Malware | Notes |
|--------------|-------------------|--------|
| `\\postex_[hex]` | Cobalt Strike | Post-exploitation named pipe |
| `\\msagent_[number]` | Cobalt Strike | Default SMB beacon pipe |
| `\\MSSE-[number]-server` | Various | Mimics Microsoft Security Essentials |
| `\\status_[number]` | Various | Generic C2 pattern |

### Investigation Workflow

1. **Check Sysmon coverage** - Ensure Events 17/18 are being collected
2. **Query for known bad patterns** - Focus on Cobalt Strike defaults
3. **Analyze process context** - Pipes from rundll32/regsvr32 are suspicious
4. **Check process location** - Temp directory processes creating pipes are highly suspicious
5. **Correlate with network activity** - Named pipes often precede C2 communications

### Context is Key

When investigating named pipes, the process creating them matters more than the pipe name itself:
- `rundll32.exe` creating any named pipe is suspicious
- Processes running from `\Temp\` directories creating pipes warrant investigation
- Living-off-the-land binaries (regsvr32, mshta) should rarely create named pipes

## 🔧 Named Pipe Analysis - Native LimaCharlie Events

### Overview
LimaCharlie has native named pipe events (NEW_NAMED_PIPE and OPEN_NAMED_PIPE) that don't require Sysmon. These events show the full device path and require process correlation.

### Hunt Using Native Events

```lcql
# Detect known malicious pipe patterns
-24h | * | NEW_NAMED_PIPE OPEN_NAMED_PIPE | 
event/FILE_PATH contains "\\postex_" OR 
event/FILE_PATH contains "\\msagent_" OR 
event/FILE_PATH contains "\\MSSE-" OR 
event/FILE_PATH contains "\\status_" |
event/FILE_PATH as PipeName 
event/PROCESS_ID as PID 
routing/hostname as Host 
routing/event_type as EventType 
ts as Timestamp

# Find all unique named pipes with occurrence count
-24h | * | NEW_NAMED_PIPE OPEN_NAMED_PIPE |
event/FILE_PATH as PipeName 
COUNT(PipeName) as Count 
GROUP BY(PipeName) 
ORDER BY Count ASC
```

### Correlate with Process Information

Since native events only include PID, you need to correlate with process events:

```lcql
# Step 1: Find suspicious pipe and note the PID and timestamp
# Step 2: Query process events around that time
2025-08-04 22:15:00 to 2025-08-04 22:16:00 | 
hostname == "suspected-host" | 
NEW_PROCESS EXISTING_PROCESS | 
event/PROCESS_ID == suspicious_pid |
event/FILE_PATH as Process 
event/COMMAND_LINE as CommandLine 
event/PARENT/FILE_PATH as Parent
```

### Native vs Sysmon Comparison

| Feature | Native LimaCharlie | Sysmon |
|---------|-------------------|---------|
| Event Types | NEW_NAMED_PIPE, OPEN_NAMED_PIPE | Event ID 17, 18 |
| Pipe Path | Full device path (\\Device\\NamedPipe\\...) | Short form (\\pipename) |
| Process Info | PID only | Full process path included |
| Dependencies | None | Requires Sysmon installed |
| Coverage | All LimaCharlie sensors | Only where Sysmon configured |

## 🔐 Credential Access Attempts

### LSASS Access

```lcql
# Process accessing LSASS (potential credential dumping)
-6h | plat == windows | WEL | 
event/EVENT/System/Channel == "Microsoft-Windows-Sysmon/Operational" AND
event/EVENT/System/EventID == "10" AND
event/EVENT/EventData/TargetImage contains "lsass.exe" |
event/EVENT/EventData/SourceImage as AccessingProcess
event/EVENT/EventData/GrantedAccess as Access
routing/hostname as Host

# Suspicious tools known for credential dumping
-24h | plat == windows | NEW_PROCESS | 
event/FILE_PATH contains "mimikatz" OR
event/FILE_PATH contains "procdump" OR
event/FILE_PATH contains "sqldumper" OR
event/COMMAND_LINE contains "sekurlsa" OR
event/COMMAND_LINE contains "lsadump" |
event/FILE_PATH as Tool
event/COMMAND_LINE as Command
routing/hostname as Host
```

### Kerberos Attacks

```lcql
# Kerberoasting indicators - TGS requests with weak encryption
-24h | plat == windows | WEL | 
event/EVENT/System/EventID == "4769" AND 
event/EVENT/EventData/TicketEncryptionType == "0x17" |
event/EVENT/EventData/ServiceName as Service
event/EVENT/EventData/TargetUserName as User
routing/hostname as DC
COUNT(Service) as RequestCount
GROUP BY(Service, User, DC)

# Golden Ticket detection - TGT requests for sensitive accounts
-24h | plat == windows | WEL | 
event/EVENT/System/EventID == "4768" AND 
(event/EVENT/EventData/TargetUserName contains "admin" OR
 event/EVENT/EventData/TargetUserName contains "krbtgt") |
event/EVENT/EventData/TargetUserName as Account
event/EVENT/EventData/IpAddress as SourceIP
routing/hostname as DC
```

## 🌐 Network Anomalies

### Beaconing Detection

```lcql
# Regular DNS queries (potential C2 beaconing)
-6h | * | DNS_REQUEST |
event/DOMAIN_NAME as Domain
routing/hostname as Host
COUNT(Domain) as QueryCount
GROUP BY(Domain, Host)
HAVING QueryCount > 50
ORDER BY QueryCount DESC

# Suspicious TLDs
-24h | * | DNS_REQUEST |
event/DOMAIN_NAME contains ".tk" OR
event/DOMAIN_NAME contains ".ml" OR
event/DOMAIN_NAME contains ".ga" OR
event/DOMAIN_NAME contains ".cf" |
event/DOMAIN_NAME as SuspiciousDomain
event/IP_ADDRESS as ResolvedIP
routing/hostname as Host
```

### Data Exfiltration Patterns

```lcql
# Large outbound transfers
-6h | * | NETWORK_CONNECTIONS |
event/NETWORK_ACTIVITY/BYTES_SENT > 100000000 |
event/FILE_PATH as Process
event/NETWORK_ACTIVITY/DESTINATION/IP_ADDRESS as DestIP
event/NETWORK_ACTIVITY/BYTES_SENT as BytesSent
routing/hostname as Host

# Connections to rare external IPs
-24h | * | NETWORK_CONNECTIONS |
event/NETWORK_ACTIVITY/DESTINATION/IP_ADDRESS not contains "10." AND
event/NETWORK_ACTIVITY/DESTINATION/IP_ADDRESS not contains "192.168." AND
event/NETWORK_ACTIVITY/DESTINATION/IP_ADDRESS not contains "172." |
event/NETWORK_ACTIVITY/DESTINATION/IP_ADDRESS as ExternalIP
COUNT(ExternalIP) as ConnectionCount
GROUP BY(ExternalIP)
HAVING ConnectionCount < 5
```

## 🔄 Persistence Mechanisms

### Registry Modifications

```lcql
# Run key modifications
-24h | plat == windows | WEL |
event/EVENT/System/Channel == "Microsoft-Windows-Sysmon/Operational" AND
event/EVENT/System/EventID == "13" AND
(event/EVENT/EventData/TargetObject contains "\\CurrentVersion\\Run" OR
 event/EVENT/EventData/TargetObject contains "\\CurrentVersion\\RunOnce") |
event/EVENT/EventData/TargetObject as RegistryKey
event/EVENT/EventData/Details as Value
event/EVENT/EventData/Image as ModifyingProcess
routing/hostname as Host

# Service creation
-24h | plat == windows | WEL |
event/EVENT/System/EventID == "4697" |
event/EVENT/EventData/ServiceName as NewService
event/EVENT/EventData/ServiceFileName as ServicePath
routing/hostname as Host
```

### Scheduled Tasks

```lcql
# New scheduled task creation
-24h | plat == windows | WEL |
event/EVENT/System/EventID == "4698" |
event/EVENT/EventData/TaskName as TaskName
event/EVENT/EventData/SubjectUserName as Creator
routing/hostname as Host

# Hidden scheduled tasks (using SYSTEM account)
-24h | plat == windows | NEW_PROCESS |
event/FILE_PATH contains "schtasks.exe" AND
event/COMMAND_LINE contains "/create" AND
event/USER_NAME == "NT AUTHORITY\\SYSTEM" |
event/COMMAND_LINE as Command
routing/hostname as Host
```

## 🚨 Lateral Movement

### Remote Execution Tools

```lcql
# PsExec and similar tools - process execution
-24h | plat == windows | NEW_PROCESS |
event/FILE_PATH contains "psexec" OR
event/FILE_PATH contains "paexec" OR
event/FILE_PATH contains "remcom" |
event/FILE_PATH as Tool
event/COMMAND_LINE as Command
event/USER_NAME as User
routing/hostname as Host

# PsExec usage - registry EULA acceptance
-24h | plat == windows | REGISTRY_WRITE |
event/REGISTRY_KEY contains "\\SOFTWARE\\Sysinternals\\PsExec\\EulaAccepted" |
event/REGISTRY_KEY as RegistryKey
event/PROCESS_ID as PID
routing/hostname as Host
routing/this as Atom
ts as Timestamp

# Combine both for comprehensive PsExec detection
-24h | plat == windows | NEW_PROCESS REGISTRY_WRITE |
(event/FILE_PATH contains "psexec" OR event/REGISTRY_KEY contains "\\SOFTWARE\\Sysinternals\\PsExec") |
routing/event_type as EventType
routing/hostname as Host
COUNT(EventType) as Count
GROUP BY(Host, EventType)

# RDP connections
-24h | plat == windows | WEL |
event/EVENT/System/EventID == "4624" AND
event/EVENT/EventData/LogonType == "10" |
event/EVENT/EventData/TargetUserName as User
event/EVENT/EventData/IpAddress as SourceIP
routing/hostname as TargetHost
COUNT(SourceIP) as ConnectionCount
GROUP BY(User, SourceIP, TargetHost)
```

### SMB Lateral Movement

```lcql
# Admin share access
-24h | plat == windows | WEL |
event/EVENT/System/EventID == "5140" AND
(event/EVENT/EventData/ShareName == "ADMIN$" OR
 event/EVENT/EventData/ShareName == "C$" OR
 event/EVENT/EventData/ShareName == "IPC$") |
event/EVENT/EventData/ShareName as Share
event/EVENT/EventData/IpAddress as SourceIP
event/EVENT/EventData/SubjectUserName as User
routing/hostname as Host
```

## 🔍 Reconnaissance Activities

### Network Discovery

```lcql
# Network scanning tools
-24h | plat == windows | NEW_PROCESS |
event/FILE_PATH contains "nmap" OR
event/FILE_PATH contains "masscan" OR
event/FILE_PATH contains "arp.exe" OR
event/FILE_PATH contains "nbtstat" |
event/FILE_PATH as Tool
event/COMMAND_LINE as Command
routing/hostname as Host

# AD enumeration
-24h | plat == windows | NEW_PROCESS |
event/FILE_PATH contains "net.exe" AND
(event/COMMAND_LINE contains "group" OR
 event/COMMAND_LINE contains "user" OR
 event/COMMAND_LINE contains "localgroup") |
event/COMMAND_LINE as EnumCommand
routing/hostname as Host
COUNT(EnumCommand) as Count
GROUP BY(Host, EnumCommand)
```

## 📊 Statistical Anomalies

### Rare Process Execution

```lcql
# Processes executed by few hosts (potential targeted malware)
-24h | plat == windows | NEW_PROCESS |
event/HASH as FileHash
event/FILE_PATH as Process
COUNT_UNIQUE(routing/hostname) as UniqueHosts
GROUP BY(FileHash, Process)
HAVING UniqueHosts < 3 AND UniqueHosts > 0
ORDER BY UniqueHosts ASC

# First time seen processes
-168h | plat == windows | CODE_IDENTITY |
event/FILE_IS_SIGNED == 0 |
event/FILE_PATH as UnsignedFile
event/HASH as Hash
MIN(ts) as FirstSeen
COUNT(routing/hostname) as HostCount
GROUP BY(UnsignedFile, Hash)
ORDER BY FirstSeen DESC
```

### User Behavior Anomalies

```lcql
# Users logging in at unusual hours
-24h | plat == windows | WEL |
event/EVENT/System/EventID == "4624" |
event/EVENT/EventData/TargetUserName as User
HOUR(ts) as LoginHour
routing/hostname as Host
HAVING LoginHour < 6 OR LoginHour > 22

# Multiple failed logins followed by success
-6h | plat == windows | WEL |
event/EVENT/System/EventID == "4625" OR event/EVENT/System/EventID == "4624" |
event/EVENT/System/EventID as EventType
event/EVENT/EventData/TargetUserName as User
event/EVENT/EventData/IpAddress as SourceIP
routing/hostname as Host
```

## 🎬 Action Items

After running these queries:

1. **Investigate anomalies** - Not all results are malicious
2. **Correlate findings** - Look for patterns across multiple queries
3. **Check against known good** - Validate against baseline behavior
4. **Document findings** - Keep records for future reference
5. **Create detections** - Turn validated hunts into automated rules
6. **Share with team** - Collaborate on suspicious findings

## 📝 Notes

- Adjust time ranges based on data retention and performance
- Modify thresholds based on your environment's normal behavior
- Test queries in small time windows first
- Use COUNT and GROUP BY to identify patterns
- Combine multiple queries for comprehensive hunting
- Regular hunting helps establish baseline behavior