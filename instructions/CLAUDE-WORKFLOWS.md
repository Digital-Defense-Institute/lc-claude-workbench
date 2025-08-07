# LimaCharlie MCP Workflows & Examples

<!-- 
  Developed by Digital Defense Institute (https://digitaldefenseinstitute.com)
  Practical workflows for common security operations tasks.
  Each example includes comments explaining the approach.
  Always test these workflows in a safe environment first.
-->

## 🚨 Getting Recent Detections

<!-- This is one of the most common operations - retrieving recent alerts -->
```python
# CRITICAL: Always get fresh timestamp
current_time = $(date -u +%s)  # Execute this command first!
start_time = current_time - 600  # Last 10 minutes
get_historic_detections(start=start_time, end=current_time, limit=10)
```

## ⚡ Rapid Detection Triage

<!-- Standard workflow for quickly triaging a detection -->
```python
# 1. Initial context (run in parallel)
current_time = $(date -u +%s)
is_online(sid="sensor-id")
get_os_version(sid="sensor-id")
get_historic_detections(start=current_time-600, end=current_time, limit=10)

# 2. Process investigation
get_process_modules(sid="sensor-id", pid=suspicious_pid)
find_strings(sid="sensor-id", 
            strings=["ReflectiveLoader", "beacon", "mimikatz"],
            pid=suspicious_pid)

# 3. Timeline reconstruction
run_lcql_query(query="2025-07-17 02:45:00 to 2025-07-17 02:48:00 | sid == 'sensor-id' | NEW_PROCESS EXISTING_PROCESS | event/PROCESS_ID == target_pid")
```

## 🔍 Common IOC Searches

<!-- Search for known Indicators of Compromise -->
```python
# Cobalt Strike indicators
# This is only used when we cannot predict valid YARA rule names that may or may not exist in the org, so we do it the lazy way with common bad strings
# This should be improved in the future to better leverage YARA scanning, but we must know rule names available
cs_strings = [
    "ReflectiveLoader",
    "beacon",
    "\\pipe\\msagent",
    "\\pipe\\postex",
    "Mozilla/5.0",
    "IEX",
    "DownloadString"
]
find_strings(sid="sensor-id", strings=cs_strings, pid=pid)
```

## 🎯 Investigating YARA Detections in Memory

<!-- YARA detections in memory are critical alerts requiring immediate investigation -->

### Step 1: Query Recent YARA Detections
```python
# Get current UTC timestamp
current_time = $(date -u +%s)

# Query YARA detections from last 7 days
yara_query = """
-168h | * | YARA_DETECTION | 
event/PROCESS/PROCESS_ID exists |
event/RULE_NAME as Rule
event/PROCESS/FILE_PATH as Process
event/PROCESS/PROCESS_ID as PID
routing/hostname as Host
routing/sid as SensorID
ts as DetectionTime
"""
results = run_lcql_query(query=yara_query, limit=50)

# For specific rule matches
specific_rule_query = """
-168h | * | YARA_DETECTION |
event/RULE_NAME contains "CobaltStrike" OR event/RULE_NAME contains "Mimikatz" |
event/RULE_NAME as Rule
event/PROCESS/FILE_PATH as Process
event/PROCESS/PROCESS_ID as PID
routing/hostname as Host
routing/sid as SensorID
"""
```

### Step 2: Investigate Detected Process
```python
# From YARA detection results
sid = "sensor-id-from-detection"
pid = detected_pid

# Check if sensor is online first
is_online(sid=sid)

# Get process details and modules
process_info = get_processes(sid=sid)
modules = get_process_modules(sid=sid, pid=pid)

# Search for additional IOCs in memory
suspicious_strings = [
    "ReflectiveLoader",
    "beacon",
    "mimikatz",
    "\\pipe\\msagent",
    "sekurlsa::logonpasswords"
]
string_search = find_strings(sid=sid, strings=suspicious_strings, pid=pid)
```

### Step 3: Analyze Process Relationships
```python
# Get parent-child relationships using LCQL
process_tree_query = f"""
-6h | sid == '{sid}' |
NEW_PROCESS EXISTING_PROCESS |
event/PROCESS_ID == {pid} OR event/PARENT/PROCESS_ID == {pid} |
event/FILE_PATH as Process
event/COMMAND_LINE as CommandLine
event/PARENT/FILE_PATH as ParentProcess
event/PROCESS_ID as PID
event/PARENT/PROCESS_ID as ParentPID
routing/this as Atom
routing/parent as ParentAtom
"""
process_tree = run_lcql_query(query=process_tree_query, limit=100)
```

### Step 4: Check Network Activity
```python
# Network connections from the detected process
network_query = f"""
-24h | sid == '{sid}' |
NETWORK_CONNECTIONS |
event/PROCESS_ID == {pid} |
event/NETWORK_ACTIVITY/DESTINATION/IP_ADDRESS as DestIP
event/NETWORK_ACTIVITY/DESTINATION/PORT as Port
event/FILE_PATH as Process
ts as ConnectionTime
"""
network_activity = run_lcql_query(query=network_query, limit=50)
```

### Step 5: Check for Persistence
```python
# Registry modifications by the process
persistence_query = f"""
-24h | sid == '{sid}' |
WEL |
event/EVENT/System/EventID == "13" AND
event/EVENT/EventData/ProcessId == "{pid}" |
event/EVENT/EventData/TargetObject as RegistryKey
event/EVENT/EventData/Details as Value
"""
registry_changes = run_lcql_query(query=persistence_query, limit=50)

# File drops
file_creation_query = f"""
-24h | sid == '{sid}' |
FILE_CREATE |
event/PARENT/PROCESS_ID == {pid} |
event/FILE_PATH as DroppedFile
event/HASH as FileHash
"""
file_drops = run_lcql_query(query=file_creation_query, limit=50)
```

### Step 6: Response Actions
```python
# Based on investigation findings
if confirmed_malicious:
    # Tag the system
    add_tag(sid=sid, tag="yara_detection_confirmed", ttl=604800)  # 7 days
    
    # Consider isolation (requires explicit approval)
    print("⚠️ WARNING: This system has confirmed malicious activity.")
    print("Network isolation would disconnect all network access.")
    print("To isolate, explicitly confirm: 'Yes, isolate the system'")
    
    # Generate detection summary
    summary = generate_detection_summary(
        query=f"YARA rule {rule_name} detected in process {process_name} PID {pid}"
    )
```

### Key Points for YARA Memory Investigations:
- **Act quickly** - Memory artifacts are volatile
- **Check process legitimacy** - Verify if process should exist
- **Look for injection** - Check if legitimate process was compromised
- **Examine network activity** - C2 communications often follow
- **Document everything** - YARA detections are high-confidence alerts
- **Consider containment** - But always with explicit approval

## 🎯 LCQL Threat Hunting

<!-- Proactive threat hunting queries -->
```python
# Unsigned binaries
query = "-24h | plat == windows | CODE_IDENTITY | event/SIGNATURE/FILE_IS_SIGNED == 0 | event/FILE_PATH as Path event/HASH as Hash COUNT_UNIQUE(Hash) as Count GROUP BY(Path Hash)"
run_lcql_query(query=query)

# Suspicious rundll32
query = "-6h | plat==windows | NEW_PROCESS | event/FILE_PATH contains 'rundll32.exe' AND event/COMMAND_LINE not contains '.dll'"
run_lcql_query(query=query)

# Failed RDP attempts
query = "-1h | plat==windows | WEL | event/EVENT/System/EventID is '4625' AND event/EVENT/EventData/LogonType == '10'"
run_lcql_query(query=query)
```

## 🤖 AI-Powered Detection Creation

<!-- Use AI to generate detection rules from natural language -->
```python
# Generate detection rule
detection = generate_dr_rule_detection(
    query="Detect PowerShell downloading and executing scripts from the internet"
)

# Generate response
response = generate_dr_rule_respond(
    query="Isolate the system and collect process memory dumps"
)

# Generate LCQL query
query = generate_lcql_query(
    query="Find all processes that made DNS requests to newly registered domains"
)
results = run_lcql_query(query=query)
```

## 🏷️ Tag Management

<!-- Use tags to track investigation status -->
```python
# Tag compromised system
add_tag(sid="sensor-id", tag="compromised", ttl=86400)  # 24 hours

# Remove after remediation
remove_tag(sid="sensor-id", tag="compromised")
```

## 📈 Managing Large Responses

<!-- Best practices for handling large API responses -->
- Always use `limit` parameter
- Functions that often exceed limits:
  - `get_services()` - 35K+ tokens
  - `get_detection_rules()` - Full ruleset too large
  - `get_process_strings()` - Can be very large

## 📊 Show Complete Raw Events

<!-- Important: Always show full event context for critical findings -->
When investigating, always show complete raw events for:
- First occurrence of suspicious activity
- Parent process investigations (atoms)
- Network connections
- Cross-process activities
- Detection events

Example:
```python
print("Complete event showing suspicious network activity:")
print(json.dumps(event, indent=2))
print(f"\nKey findings:")
print(f"- Process: {event['event']['FILE_PATH']} (PID: {event['event']['PROCESS_ID']})")
print(f"- Network: {event['event']['NETWORK_ACTIVITY'][0]['DESTINATION']['IP_ADDRESS']}")
print(f"- Atom: {event['routing']['this']}")
print(f"- Parent Atom: {event['routing'].get('parent', 'Not available')}")
```