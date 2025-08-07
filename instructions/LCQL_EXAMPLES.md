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

## 🚨 YARA and Malware Detection Queries

<!-- Queries for hunting malware using YARA detections -->

### Find all YARA detections
```lcql
-168h | * | YARA_DETECTION | / exists
```

### YARA detections within specific absolute time range
```lcql
2025-01-01 00:00:00 to 2025-01-07 23:59:59 | * | YARA_DETECTION | / exists
```

### YARA detections with specific rule names
```lcql
-24h | * | YARA_DETECTION | event/RULE_NAME contains "CobaltStrike" OR event/RULE_NAME contains "Sliver" | event/RULE_NAME as Rule event/FILE_PATH as File routing/hostname as Host
```

### YARA detections grouped by rule and host
```lcql
-168h | * | YARA_DETECTION | event/RULE_NAME as Rule routing/hostname as Host COUNT(event) as Detections GROUP BY(Rule, Host)
```

### YARA detections with file paths
```lcql
-24h | * | YARA_DETECTION | event/FILE_PATH exists | event/FILE_PATH as MaliciousFile event/RULE_NAME as DetectionRule routing/hostname as InfectedHost ts as DetectionTime
```

### Process-based YARA detections
```lcql
-168h | * | YARA_DETECTION | event/PROCESS/PROCESS_ID exists | event/PROCESS/FILE_PATH as Process event/PROCESS/PROCESS_ID as PID event/RULE_NAME as Rule routing/hostname as Host
```

## 📖 LCQL Query Structure

<!-- Understanding the fundamental structure of LCQL queries -->

### Basic Structure
```
<time_range> | <platform_filter> | <event_types> | <filter_conditions> | <output_fields>
```

### ⚠️ CRITICAL: Event Type Positioning
**Event types (NEW_PROCESS, YARA_DETECTION, NETWORK_CONNECTIONS, etc.) MUST be placed in the 3rd position of the query, NOT in the filter conditions (4th position).**

#### ✅ CORRECT Examples:
```lcql
-1h | * | YARA_DETECTION | / exists
-24h | * | NEW_PROCESS NETWORK_CONNECTIONS | event/FILE_PATH contains "suspicious"
-168h | plat == windows | CODE_IDENTITY YARA_DETECTION | / exists
```

#### ❌ INCORRECT Examples:
```lcql
-1h | * | * | event_type == "YARA_DETECTION"  # WRONG - event type in filter
-24h | * | * | routing/event_type == "NEW_PROCESS"  # WRONG - event type in filter
```

### Time Ranges

#### Relative Time Formats (from current time)
- `-<number>m` - Minutes in the past (e.g., `-30m`, `-5m`)
- `-<number>h` - Hours in the past (e.g., `-1h`, `-24h`, `-168h`)

Common examples:
- `-5m` - Last 5 minutes
- `-30m` - Last 30 minutes
- `-1h` - Last hour
- `-6h` - Last 6 hours
- `-24h` - Last 24 hours (1 day)
- `-48h` - Last 48 hours (2 days)
- `-168h` - Last 168 hours (7 days)
- `-720h` - Last 720 hours (30 days)

#### Absolute Time Ranges
- Format: `YYYY-MM-DD HH:MM:SS to YYYY-MM-DD HH:MM:SS`
- Example: `2025-01-01 00:00:00 to 2025-01-02 00:00:00`

**⚠️ IMPORTANT**: Days (e.g., `-7d`, `-30d`) are NOT valid LCQL time selectors. Use hours (`h`) or minutes (`m`) for relative times, or absolute date-time ranges.

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

## 🔧 Troubleshooting Failed LCQL Queries

### When queries return empty results:

1. **Verify event types exist**:
   ```lcql
   -1h | * | NEW_PROCESS EXISTING_PROCESS | event/* exists
   ```
   Use a very small limit (1-5) to check if events exist.

2. **Check available event types for a sensor**:
   ```lcql
   -1h | hostname contains "target-host" | * | / exists | 
   routing/event_type as EventType COUNT(EventType) as Count 
   GROUP BY(EventType)
   ```

3. **Remove filters progressively**:
   - Start broad: `-1h | * | EVENT_TYPE | event/* exists`
   - Add platform: `-1h | plat == windows | EVENT_TYPE | event/* exists`
   - Add hostname: `-1h | hostname contains "server" | EVENT_TYPE | event/* exists`
   - Add field filters last

4. **Check process creation times**:
   - Processes may have been created days/weeks ago
   - Use `get_processes(sid)` to check CREATION_TIME field
   - If creation is outside 7-day window, query recent activity instead

5. **Array field notation**:
   - NETWORK_ACTIVITY is an array: use `event/NETWORK_ACTIVITY/*/DESTINATION/IP_ADDRESS`
   - Not: `event/NETWORK_ACTIVITY/DESTINATION/IP_ADDRESS`

6. **Common pitfalls**:
   - Process created before query window (check CREATION_TIME in get_processes)
   - Wrong field paths (verify against SAMPLE_EVENTS.md)
   - Array fields need `*/` notation for traversal
   - Missing data for time range (use get_time_when_sensor_has_data)

## ⚠️ CRITICAL: Query Validation and Event Structure

**NEVER assume that an initial query with no results means the events don't exist.** Your query syntax or field paths may be incorrect.

### Query Validation Workflow

1. **First, validate event existence** with a simple query:
   ```lcql
   -1h | * | EVENT_TYPE | event/* exists
   ```
   Use a very small limit (5-10) to check if events exist and examine their structure.

2. **Check organization-specific event schemas**:
   ```python
   # Single event type
   get_event_schema(name="NEW_PROCESS")
   
   # Multiple event types at once
   get_event_schemas_batch(event_names=["NEW_PROCESS", "YARA_DETECTION", "DNS_REQUEST"])
   ```
   Note: Some event types may show empty schemas but still contain data.

3. **Reference sample events** in this repository:
   - Check `@instructions/SAMPLE_EVENTS.md` for detailed event structures
   - Look for the specific event type to understand field paths
   - Pay attention to nested structures and array fields

4. **Examine the event structure** before crafting complex queries:
   - Look at the raw event data to understand field paths
   - Check nested structures (e.g., `event/EVENTS/*/SOURCE/FILE_PATH`)
   - Note which fields are arrays vs single values

5. **Use available resources** before writing complex queries:
   - Check LCQL examples in this project for similar queries
   - Use the `generate_lcql_query()` tool for AI assistance
   - Reference `SAMPLE_EVENTS.md` for event structures
   - Use `get_event_schema()` to check org-specific schemas

6. **Build incrementally**:
   - Start with `event/* exists` to see raw data
   - Add one filter at a time
   - Test each addition before proceeding

### Example: Finding SENSITIVE_PROCESS_ACCESS Events

```lcql
# Step 1: Check if events exist
-168h | * | SENSITIVE_PROCESS_ACCESS | event/* exists

# Step 2: Examine structure to find source process path  
-168h | * | SENSITIVE_PROCESS_ACCESS | event/* exists | event/EVENTS as Events

# Step 3: Build the final query based on discovered structure
-168h | * | SENSITIVE_PROCESS_ACCESS | event/* exists | 
event/*/event/SOURCE/FILE_PATH as source_process 
COUNT(event) as access_count 
GROUP BY(source_process)
```

### Common Pitfalls to Avoid

- ❌ Assuming field paths without checking structure
- ❌ Giving up when first query returns no results
- ❌ Writing complex queries without understanding event schema
- ❌ Assuming empty schemas mean no events exist (some events have empty schemas but still contain data)
- ❌ **Using undocumented LCQL operators** - NEVER use HAVING, LIMIT, WHERE, or other SQL-like operators unless explicitly shown in LCQL examples
- ✅ Always validate event existence first with `event/* exists`
- ✅ Check org-specific schemas with `get_event_schema()` tools
- ✅ Reference `SAMPLE_EVENTS.md` for event structure examples
- ✅ Use `generate_lcql_query()` for AI-assisted query generation
- ✅ Build queries incrementally, testing each step
- ✅ **Only use documented LCQL syntax** - When in doubt, use generate_lcql_query() to verify proper syntax