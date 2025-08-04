# LCQL (LimaCharlie Query Language) Examples

<!-- 
  Developed by Digital Defense Institute (https://digitaldefenseinstitute.com)
  LCQL is LimaCharlie's powerful query language for searching and analyzing events.
  These examples cover common security use cases and can be adapted for your environment.
  Always test queries with small time ranges first to avoid performance issues.
-->

This document provides practical LCQL query examples for common security investigations and threat hunting scenarios.

## 💻 Process Analysis

<!-- Queries for analyzing process behavior and relationships -->

### Examine rundll32.exe executions with command line analysis
```lcql
-12h | plat == windows | NEW_PROCESS | event/PARENT/FILE_PATH contains "rundll32.exe" | event/PARENT/FILE_PATH as parent event/FILE_PATH as child event/COMMAND_LINE as commandline
```

### Find rundll32 executions missing DLL arguments (suspicious)
```lcql
-6h | plat==windows | NEW_PROCESS EXISTING_PROCESS | event/FILE_PATH contains "rundll32.exe" AND event/COMMAND_LINE not contains ".dll" | ts as Timestamp event/FILE_PATH as Path event/COMMAND_LINE as CommandLine
```

### Analyze network activity by specific process
```lcql
-6h | plat==windows | NETWORK_CONNECTIONS | event/FILE_PATH contains "rundll32.exe" | event/FILE_PATH event/NETWORK_ACTIVITY/DESTINATION/IP_ADDRESS as dest_ip event/NETWORK_ACTIVITY/DESTINATION/PORT as dest_port
```

### Stack child processes by parent
```lcql
-12h | plat == windows | NEW_PROCESS | event/PARENT/FILE_PATH contains "cmd.exe" | event/PARENT/FILE_PATH as parent event/FILE_PATH as child COUNT_UNIQUE(event) as count GROUP BY(parent child)
```

### Find processes with specific base64 strings in command line
```lcql
-1h | plat == windows | NEW_PROCESS EXISTING_PROCESS | event/COMMAND_LINE contains "RwBlAHQALQBQAHIAbwBjAGUAcwBzACAATQBzAE0AcABFAG4AZwAsAHMAeQBzAG0AbwBuACoA" | event/FILE_PATH as path event/COMMAND_LINE as cli routing/hostname as host
```

### Same query with counting
```lcql
-1h | plat == windows | NEW_PROCESS EXISTING_PROCESS | event/COMMAND_LINE contains "RwBlAHQALQBQAHIAbwBjAGUAcwBzACAATQBzAE0AcABFAG4AZwAsAHMAeQBzAG0AbwBuACoA" | event/FILE_PATH as path event/COMMAND_LINE as cli routing/hostname as host COUNT(cli) as Count GROUP BY(path cli host)
```

## 🔐 Authentication and Logon Analysis

<!-- Monitor authentication events for anomalies -->

### Analyze failed logons
```lcql
-1h | plat==windows | WEL | event/EVENT/System/EventID is '4625' | event/EVENT/EventData/IpAddress as SrcIP event/EVENT/EventData/LogonType as LogonType event/EVENT/EventData/TargetUserName as Username event/EVENT/EventData/WorkstationName as SrcHostname
```

### Failed logons grouped
```lcql
-1h | plat==windows | WEL | event/EVENT/System/EventID is '4625' | event/EVENT/EventData/IpAddress as SrcIP event/EVENT/EventData/LogonType as LogonType event/EVENT/EventData/TargetUserName as Username event/EVENT/EventData/WorkstationName as SrcHostname GROUP BY(LogonType Username SrcHostname SrcIP)
```

### Successful logons by specific type (Type 10 = RemoteInteractive/RDP)
```lcql
-24h | plat == windows | WEL | event/EVENT/System/EventID == "4624" AND event/EVENT/EventData/LogonType == "10"
```

### Stack successful logons by user and type
```lcql
-24h | plat == windows | WEL | event/EVENT/System/EventID == "4624" | event/EVENT/EventData/LogonType AS LogonType event/EVENT/EventData/TargetUserName as UserName COUNT_UNIQUE(event) as Count GROUP BY(UserName LogonType)
```

## ✅ Code Integrity and Signing

<!-- Identify unsigned or suspicious binaries -->

### Find unsigned binaries
```lcql
-24h | plat == windows | CODE_IDENTITY | event/SIGNATURE/FILE_IS_SIGNED == 0 | event/FILE_PATH as Path event/HASH as Hash event/ORIGINAL_FILE_NAME as OriginalFileName COUNT_UNIQUE(Hash) as Count GROUP BY(Path Hash OriginalFileName)
```

## 🌐 Network Analysis

<!-- Analyze network connections and DNS queries -->

### DNS queries for specific domain
```lcql
-6h | * | DNS_REQUEST | event/DOMAIN_NAME contains "suspicious-domain" | event/ts as Timestamp event/DOMAIN_NAME as Query event/IP_ADDRESS as Response routing/hostname as Host
```

### Count unique hosts querying specific domain
```lcql
-6h | * | DNS_REQUEST | event/DOMAIN_NAME contains "suspicious-domain" | event/DOMAIN_NAME as dns COUNT_UNIQUE(routing/hostname) as hostcount GROUP BY(dns)
```

### Stack CNAME records (DNS_TYPE 5)
```lcql
-24h | * | DNS_REQUEST | event/DNS_TYPE == 5 | event/DOMAIN_NAME AS DomainName COUNT(DomainName) as count GROUP BY(DomainName)
```

### Network connections to specific IP
```lcql
-6h | * | NETWORK_CONNECTIONS| event/NETWORK_ACTIVITY/DESTINATION/IP_ADDRESS is "203.0.113.100" | event/FILE_PATH as path routing/hostname as host COUNT(path) as Count GROUP BY(path host)
```

### Network connections by specific process
```lcql
-6h | plat==windows | NETWORK_CONNECTIONS | event/FILE_PATH contains "rundll32.exe" | event/FILE_PATH event/NETWORK_ACTIVITY/DESTINATION/IP_ADDRESS as dest_ip event/NETWORK_ACTIVITY/DESTINATION/PORT as dest_port
```

## 🔗 Combined Analysis Examples

<!-- Complex queries combining multiple event types -->

### Suspicious rundll32 with missing DLL and hostname context
```lcql
-6h | plat==windows | NEW_PROCESS EXISTING_PROCESS | event/FILE_PATH contains "rundll32.exe" AND event/COMMAND_LINE not contains ".dll" | ts as Timestamp event/FILE_PATH as Path event/COMMAND_LINE as CommandLine routing/hostname as Hostname
```

## 📖 LCQL Query Structure

<!-- Understanding the fundamental structure of LCQL queries -->

### Basic Structure
```
<time_range> | <platform_filter> | <event_types> | <filter_conditions> | <output_fields>
```

### Time Ranges
- `-1h` - Last hour
- `-6h` - Last 6 hours
- `-12h` - Last 12 hours
- `-24h` - Last 24 hours
- `-7d` - Last 7 days

### Platform Filters
- `plat == windows` - Windows only
- `plat == linux` - Linux only
- `plat == macos` - macOS only
- `*` - All platforms

### Common Event Types
- `NEW_PROCESS` - Process creation
- `EXISTING_PROCESS` - Process discovery
- `NETWORK_CONNECTIONS` - Network activity
- `DNS_REQUEST` - DNS queries
- `WEL` - Windows Event Logs
- `CODE_IDENTITY` - Code signing info
- `FILE_CREATE` - File creation
- `FILE_DELETE` - File deletion
- `REGISTRY_CREATE` - Registry key creation

### Aggregation Functions
- `COUNT()` - Count occurrences
- `COUNT_UNIQUE()` - Count unique values
- `GROUP BY()` - Group results by fields
- `SUM()` - Sum numeric values
- `AVG()` - Average numeric values

## 💡 Tips for Effective LCQL Queries

<!-- Best practices for writing efficient and effective queries -->

1. **Start with shorter time ranges** to test queries before expanding
2. **Use platform filters** to reduce noise and improve performance
3. **Combine event types** with space separation for OR logic
4. **Use GROUP BY** for statistical analysis and anomaly detection
5. **Alias fields** with `as` for cleaner output
6. **Test filters incrementally** - build complex queries step by step