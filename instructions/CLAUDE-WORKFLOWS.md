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