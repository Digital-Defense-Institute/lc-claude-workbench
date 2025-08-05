# Incident Response Playbook with LimaCharlie MCP

<!-- 
  Developed by Digital Defense Institute (https://digitaldefenseinstitute.com)
  This playbook demonstrates how to use Claude AI with LimaCharlie MCP
  for rapid incident response and investigation.
-->

> **⚠️ EDUCATIONAL EXAMPLE ONLY**  
> This playbook is for learning purposes. In real incidents, ALWAYS validate AI suggestions with human expertise.  
> Never make critical response decisions based solely on AI outputs.

## Scenario: Suspicious Process Detection

### Step 1: Initial Alert Triage

```python
# Get the current UTC timestamp
current_time = $(date -u +%s)

# Retrieve recent detections from the last 10 minutes
detections = get_historic_detections(
    start=current_time-600, 
    end=current_time, 
    limit=20
)

# For each detection, examine the severity and category
# Focus on high/critical severity alerts first
```

### Step 2: Sensor Status Verification

```python
# Extract sensor ID from the detection
sid = "your-sensor-id-from-detection"

# Check if the sensor is online and responsive
sensor_status = is_online(sid=sid)

# Get basic OS information for context
os_info = get_os_version(sid=sid)

# Check if sensor is already isolated
isolation_status = is_isolated(sid=sid)
```

### Step 3: Process Investigation

```python
# Investigate the suspicious process
suspicious_pid = 1234  # From detection event

# Get process details and loaded modules
process_modules = get_process_modules(sid=sid, pid=suspicious_pid)

# Search for known malicious strings in memory
malware_indicators = [
    "mimikatz",
    "beacon",
    "ReflectiveLoader",
    "sekurlsa",
    "lsadump",
    "\\pipe\\msagent"
]

string_results = find_strings(
    sid=sid, 
    strings=malware_indicators, 
    pid=suspicious_pid
)
```

### Step 4: Timeline Reconstruction

```python
# Use LCQL to reconstruct process creation timeline
# Look 1 hour before the detection
timeline_query = f"""
-1h | sid == '{sid}' | 
NEW_PROCESS EXISTING_PROCESS | 
event/PARENT/PROCESS_ID == {suspicious_pid} OR event/PROCESS_ID == {suspicious_pid} |
ts as Timestamp 
event/FILE_PATH as Process 
event/COMMAND_LINE as CommandLine 
event/PARENT/FILE_PATH as Parent
routing/this as Atom
routing/parent as ParentAtom
"""

timeline = run_lcql_query(query=timeline_query, limit=100)
```

### Step 5: Network Activity Analysis

```python
# Check for network connections from the suspicious process
network_query = f"""
-6h | sid == '{sid}' | 
NETWORK_CONNECTIONS | 
event/PROCESS_ID == {suspicious_pid} |
event/NETWORK_ACTIVITY/DESTINATION/IP_ADDRESS as DestIP
event/NETWORK_ACTIVITY/DESTINATION/PORT as DestPort
event/FILE_PATH as Process
COUNT(DestIP) as ConnectionCount
GROUP BY(DestIP, DestPort, Process)
"""

network_activity = run_lcql_query(query=network_query, limit=50)

# Check for DNS queries
dns_query = f"""
-6h | sid == '{sid}' | 
DNS_REQUEST | 
event/PROCESS_ID == {suspicious_pid} |
event/DOMAIN_NAME as Domain
event/IP_ADDRESS as ResolvedIP
COUNT(Domain) as QueryCount
GROUP BY(Domain, ResolvedIP)
"""

dns_activity = run_lcql_query(query=dns_query, limit=50)
```

### Step 6: Persistence Mechanism Check

```python
# Check common persistence locations
# Registry Run keys
registry_paths = [
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
]

for reg_path in registry_paths:
    reg_keys = get_registry_keys(sid=sid, path=reg_path)
    # Analyze results for suspicious entries

# Check scheduled tasks (via LCQL)
schtask_query = f"""
-24h | sid == '{sid}' | 
WEL | 
event/EVENT/System/EventID == "4698" OR event/EVENT/System/EventID == "4700" |
event/EVENT/EventData/TaskName as TaskName
event/EVENT/EventData/Command as Command
"""

scheduled_tasks = run_lcql_query(query=schtask_query, limit=20)

# Check services
services = get_services(sid=sid)  # Note: May be large, use carefully

# Check autoruns
autoruns = get_autoruns(sid=sid)
```

### Step 7: Lateral Movement Detection

```python
# Look for lateral movement indicators
lateral_query = f"""
-6h | sid == '{sid}' | 
NEW_PROCESS | 
event/FILE_PATH contains "psexec" OR 
event/FILE_PATH contains "wmic" OR 
event/FILE_PATH contains "winrm" OR 
event/FILE_PATH contains "net.exe" |
event/FILE_PATH as Tool
event/COMMAND_LINE as Command
event/USER_NAME as User
"""

lateral_movement = run_lcql_query(query=lateral_query, limit=50)

# Check for suspicious authentication
auth_query = f"""
-6h | sid == '{sid}' | 
WEL | 
event/EVENT/System/EventID == "4624" AND event/EVENT/EventData/LogonType == "3" |
event/EVENT/EventData/TargetUserName as User
event/EVENT/EventData/IpAddress as SourceIP
event/EVENT/EventData/WorkstationName as SourceHost
"""

remote_auth = run_lcql_query(query=auth_query, limit=50)
```

### Step 8: YARA Scanning (if rules are available)

```python
# Scan the suspicious process with YARA rules
# Note: Rule names must exist in your LimaCharlie organization

# Common rule names (adjust based on your org)
yara_rules = ["CobaltStrike", "Mimikatz", "Metasploit"]

for rule in yara_rules:
    try:
        yara_result = yara_scan_process(
            sid=sid, 
            rule=rule, 
            pid=suspicious_pid
        )
        # Analyze results
    except:
        # Rule may not exist, continue
        pass

# Scan specific directories for malicious files
yara_scan_directory(
    sid=sid,
    rule="Ransomware",  # If available
    root_directory="C:\\Users",
    file_expression="*.exe"
)
```

### Step 9: Containment Decision

```python
# Based on investigation findings, decide on containment

# Tag the system for tracking
add_tag(sid=sid, tag="under_investigation", ttl=86400)  # 24 hours

# If confirmed malicious:
if confirmed_malicious:
    # Isolate the system from network
    isolate_network(sid=sid)
    
    # Tag as compromised
    add_tag(sid=sid, tag="compromised", ttl=604800)  # 7 days
    
    # Generate incident summary for analysts
    summary = generate_detection_summary(
        query=f"Summarize the malicious activity on sensor {sid} including process {suspicious_pid}"
    )
```

### Step 10: Automated Response Actions

```python
# Generate automated response rules
detection_rule = generate_dr_rule_detection(
    query=f"Detect similar behavior to what was seen with process {suspicious_pid}"
)

response_rule = generate_dr_rule_respond(
    query="Isolate the system and send high priority alert to SOC"
)

# Create sensor selector for similar systems
selector = generate_sensor_selector(
    query="Select all Windows servers in production environment"
)
```

## Post-Incident Actions

### Clean-up After Remediation

```python
# After incident is resolved
# Remove isolation
rejoin_network(sid=sid)

# Remove tags
remove_tag(sid=sid, tag="compromised")
remove_tag(sid=sid, tag="under_investigation")

# Verify system is back online
is_online(sid=sid)
```

### Lessons Learned Query

```python
# Generate a comprehensive report
report_query = f"""
-168h | sid == '{sid}' | 
* | 
event_type == 'DETECTION' |
event as FullEvent
COUNT(event_type) as DetectionCount
GROUP BY(event_type)
"""

weekly_report = run_lcql_query(query=report_query, limit=1000)
```

## Key Reminders

1. **Always use UTC timestamps** - Use `date -u +%s` for current time
2. **Check sensor status first** - Ensure sensor is online before investigation
3. **Use atoms for tracking** - More reliable than PIDs for parent-child relationships
4. **Limit large queries** - Always use limit parameter to avoid timeouts
5. **Document actions** - Keep track of all investigative steps
6. **Tag appropriately** - Use tags to track investigation status
7. **Test isolation carefully** - Ensure you can reconnect before isolating production systems

## Customization Notes

- Adjust time ranges based on your detection latency
- Modify IOC lists based on your threat landscape  
- Customize YARA rule names to match your organization
- Adapt persistence checks for your environment
- Scale response actions based on criticality