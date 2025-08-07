# Persistence Detection Workflow

This workflow provides systematic approaches to detecting persistence mechanisms using LimaCharlie MCP tools, with a focus on efficient investigation techniques discovered through real-world testing.

> **⚠️ IMPORTANT NOTES:**
> - Registry queries are more efficient than get_services() for targeted investigation
> - Always check multiple persistence locations as attackers often use redundant methods
> - Base64 encoded values in registry responses require decoding
> - Focus on anomalies and recently modified entries

## 1. Service-Based Persistence [HIGHEST CONFIDENCE]

### Efficient Service Enumeration via Registry

**DISCOVERED BEST PRACTICE**: Instead of using `get_services()` which returns 35K+ tokens and often exceeds limits, use targeted registry queries.

#### Step 1: List All Services (Registry Method)
```python
# Get list of all services without overwhelming response
get_registry_keys(sid="sensor-id", path="HKLM\\SYSTEM\\CurrentControlSet\\Services")
```

**Why This Works Better:**
- Returns only service names, not full configurations
- Typically 500-600 service names vs full details
- Allows targeted investigation of suspicious services
- No timeout or token limit issues

#### Step 2: Investigate Suspicious Services
```python
# Look for services with random/suspicious names from the list
# Common patterns: short names, random characters, misspellings
suspicious_services = ["svchost1", "windws", "systm32", "msupdate"]

for service in suspicious_services:
    get_registry_keys(
        sid="sensor-id", 
        path=f"HKLM\\SYSTEM\\CurrentControlSet\\Services\\{service}"
    )
```

#### Step 3: Analyze Service Configuration
Key fields to examine:
- **ImagePath**: Look for base64 encoding, unusual paths, or command line arguments
- **Type**: Service type indicates its nature:
  - Type 1 = Kernel Driver (common for security tools)
  - Type 2 = File System Driver
  - Type 16 = Win32 Service (runs in own process)
  - Type 32 = Win32 Service (shares process)
- **Start**: Startup type:
  - Type 0 = Boot Start (critical drivers)
  - Type 1 = System Start (started by kernel)
  - Type 2 = Automatic (starts at system startup)
  - Type 3 = Manual/On-Demand (started when needed)
  - Type 4 = Disabled
- **DisplayName**: Often reveals the true purpose
- **Description**: May be missing for both malicious AND legitimate services

### Example: Detecting Malicious Service
```python
# Check a suspicious service found in enumeration
result = get_registry_keys(
    sid="sensor-id",
    path="HKLM\\SYSTEM\\CurrentControlSet\\Services\\suspicious_svc"
)

# Red flags to look for:
# 1. ImagePath pointing to %TEMP%, %APPDATA%, or non-standard locations
# 2. Base64 encoded commands in ImagePath
# 3. Missing or generic DisplayName/Description
# 4. Start type = 2 (Automatic) for unknown services
```

## 2. Registry Run Keys [HIGH CONFIDENCE]

### Standard Persistence Locations

```python
# Check all common Run key locations
persistence_locations = [
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKCU\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"
]

for location in persistence_locations:
    result = get_registry_keys(sid="sensor-id", path=location)
    # Analyze each entry for suspicious executables
```

### ⚠️ CRITICAL LIMITATION: User-Specific Registry Access

**IMPORTANT DISCOVERY**: The LimaCharlie agent runs as SYSTEM, which means:
- `HKCU` queries only show the SYSTEM user's hive
- Individual user Run keys in NTUSER.dat files are NOT accessible via HKCU
- `HKU` (HKEY_USERS) prefix is not supported by the registry API
- User hives may not be loaded if users aren't logged in

### Workaround: Enumerate Users First

```python
# Step 1: Get list of users on the system
users = get_users(sid="sensor-id")

# Step 2: Extract user SIDs from the response
user_sids = []
for user in users["event"]["USERS"]:
    user_sids.append({
        "username": user["USER_NAME"],
        "sid": user["SECURITY_ID"]
    })

# Step 3: Check ProfileList for loaded profiles
profile_list = get_registry_keys(
    sid="sensor-id",
    path="HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"
)

# Note: User-specific Run keys in NTUSER.dat files cannot be directly accessed
# This is a significant limitation for detecting user-level persistence
```

### Alternative Detection Methods for User Persistence:

1. **Use get_autoruns()** - This tool may capture some user-level persistence
2. **Check Default User profile** - Persistence here affects all new users
3. **Monitor process creation** - Look for processes launched at user logon
4. **Check scheduled tasks** - User-level tasks may be visible
5. **File system analysis** - Look for suspicious files in user Startup folders:
   - `C:\Users\[username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`
   - `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp` (all users)

### What to Look For:
- Executables in %TEMP%, %APPDATA%, or %PUBLIC%
- PowerShell with encoded commands
- Rundll32.exe with unusual DLL paths
- Short or random executable names
- Recently added entries (compare with baseline)

## 3. Image File Execution Options (Debugger Hijacking) [HIGH CONFIDENCE]

### Check for Debugger Persistence

```python
# List all IFEO entries
result = get_registry_keys(
    sid="sensor-id",
    path="HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
)

# For each legitimate executable, check for debugger
for exe in result["event"]["REGISTRY_KEY"]:
    details = get_registry_keys(
        sid="sensor-id",
        path=f"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\{exe}"
    )
    # Look for "Debugger" value - should not exist for most executables
```

**Red Flags:**
- Any "Debugger" value for common executables (notepad.exe, calc.exe, etc.)
- GlobalFlag values of 0x200 (indicates heap debugging)
- Unusual executables in IFEO list

## 4. Scheduled Tasks [MEDIUM CONFIDENCE]

### Registry-Based Task Enumeration

```python
# Check scheduled tasks via registry
task_paths = [
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks",
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree"
]

for path in task_paths:
    result = get_registry_keys(sid="sensor-id", path=path)
    # Each GUID represents a scheduled task
```

**Note**: Full task details require additional investigation through the file system or WMI.

## 5. AppInit DLLs (Global Hooking) [HIGH CONFIDENCE]

### Check for DLL Injection

```python
result = get_registry_keys(
    sid="sensor-id",
    path="HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"
)

# Critical values to check:
# - AppInit_DLLs: Should be empty
# - LoadAppInit_DLLs: Should be 0
# - RequireSignedAppInit_DLLs: Should be 1 if AppInit_DLLs is used
```

## 6. Winlogon Persistence [HIGH CONFIDENCE]

### Check Winlogon Registry Keys

```python
winlogon_path = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
result = get_registry_keys(sid="sensor-id", path=winlogon_path)

# Key values to examine:
# - Shell: Should be "explorer.exe"
# - Userinit: Should be "C:\\Windows\\system32\\userinit.exe,"
# - Notify: DLLs loaded at logon
# - System: Should be empty or not exist
```

## 7. LSA Providers [HIGH CONFIDENCE]

### Check Security Support Providers

```python
lsa_paths = [
    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SecurityProviders"
]

for path in lsa_paths:
    result = get_registry_keys(sid="sensor-id", path=path)
    # Look for unusual DLLs in:
    # - Authentication Packages
    # - Notification Packages
    # - Security Packages
```

## 8. Using get_autoruns() Effectively

While `get_autoruns()` provides a comprehensive view, it can be supplemented with targeted registry queries:

```python
# First get overview with autoruns
autoruns = get_autoruns(sid="sensor-id")

# Then deep-dive suspicious entries via registry
for entry in autoruns["event"]["AUTORUNS"]:
    if entry["FILE_IS_SIGNED"] == 0 and "Temp" in entry["FILE_PATH"]:
        # Investigate further via registry
        # Extract registry path from REGISTRY_KEY field
```

## Investigation Workflow

### Investigation Prioritization
Instead of immediately flagging suspicious patterns:

1. **Establish Baseline First**
   - What security tools are deployed?
   - What's normal for this environment?
   - Are there recent deployments?

2. **Check Prevalence**
   - Single system affected? Higher priority
   - All systems affected? Likely legitimate deployment
   - Subset of systems? Investigate commonalities

3. **Correlate Multiple Indicators**
   - Single suspicious pattern? Needs more evidence
   - Multiple indicators? Higher confidence
   - Behavioral anomalies? Prioritize investigation

4. **Verify Before Escalating**
   - Cross-reference with known tools
   - Check deployment schedules
   - Consult documentation
   - Confirm with IT/Security teams

### Systematic Approach

1. **Start with Registry Service Enumeration**
   ```python
   services = get_registry_keys(sid="sensor-id", path="HKLM\\SYSTEM\\CurrentControlSet\\Services")
   ```

2. **Check Standard Run Keys**
   ```python
   for run_key in standard_run_locations:
       get_registry_keys(sid="sensor-id", path=run_key)
   ```

3. **Verify Critical System Settings**
   - Winlogon (Shell, Userinit)
   - AppInit DLLs
   - Image File Execution Options

4. **Investigate Anomalies WITH CONTEXT**
   - Services with random names (verify against baseline)
   - Unsigned executables in autoruns (check if known tools)
   - Recent modifications to persistence locations (correlate with deployments)

### Decoding Registry Values

Registry values are base64 encoded. Common types:
- **Type 1 (REG_SZ)**: Unicode string
- **Type 2 (REG_EXPAND_SZ)**: Expandable string with environment variables
- **Type 3 (REG_BINARY)**: Binary data
- **Type 4 (REG_DWORD)**: 32-bit integer

Example decoding:
```python
import base64

# "AQAAAA==" in base64
decoded = base64.b64decode("AQAAAA==")
# Results in b'\x01\x00\x00\x00' = DWORD value 1

# For strings, decode and handle Unicode
string_value = base64.b64decode(encoded_value).decode('utf-16-le')
```

## Key Advantages of Registry-Based Investigation

1. **Targeted Queries**: Only retrieve what you need
2. **No Token Limits**: Avoid 35K+ token responses from get_services()
3. **Granular Control**: Investigate specific services/keys
4. **Better Performance**: Faster response times
5. **Comprehensive Coverage**: Access to all registry-based persistence

## False Positive Mitigation [CRITICAL]

### Build an Environment Baseline
Before investigating persistence, establish what's normal:

1. **Document Known Security Tools**
   - Endpoint detection and response (EDR) agents
   - Anti-virus and anti-malware services
   - Monitoring and management tools
   - Backup and recovery agents
   
2. **Create Service Allowlists**
   - Legitimate kernel drivers in your environment
   - Standard enterprise deployment services
   - Managed service provider tools
   - Security tool components

3. **Track Deployment Patterns**
   - Services deployed to all systems
   - Standard naming conventions used by your tools
   - Typical service configurations

### Verification Steps Before Escalation
1. **Check prevalence** - Present on all managed systems? Likely legitimate
2. **Verify against documentation** - Cross-reference with IT/Security deployments
3. **Consider timing** - Does creation date align with known deployments?
4. **Look for supporting evidence** - Legitimate tools have multiple components
5. **Consult with teams** - Verify with IT/Security before flagging

## Common Patterns (Require Context)

### Service Analysis Considerations
**IMPORTANT**: These patterns appear in both legitimate and malicious software:

- **Temporary naming patterns** (`tmp_*`) - Used by legitimate installers and security tools
- **Kernel drivers** (Type 1) - Common for security software, not just malware
- **Manual start services** (Type 3) - May be intentionally configured
- **Cross-system presence** - Could indicate standard enterprise deployment
- **Short/random names** - Some legitimate tools use abbreviated names
- **Missing descriptions** - Not all legitimate services have descriptions

### Context is Critical
Services or persistence mechanisms found on ALL systems may indicate:
- Enterprise security tools
- Legitimate monitoring software  
- Standard deployment packages
- Managed service provider tools
- IT management solutions

### Service Persistence Indicators (WITH CONTEXT)
Evaluate these in combination, never in isolation:
- Services with single letter names (but check if standard in your environment)
- Services running from %TEMP% or %APPDATA% (unless part of known tools)
- Base64 encoded command lines (some legitimate tools use encoding)
- Services with no description (verify against known tools)
- Start type 2 (Automatic) for unknown services

### Registry Run Key Indicators (WITH CONTEXT)
- PowerShell with -enc or -EncodedCommand (check if part of management scripts)
- Rundll32 without a valid DLL (some legitimate uses exist)
- Executables in user-writable directories (verify purpose)
- Recently created entries (correlate with deployment schedules)
- Misspelled system executables (high confidence indicator)

### Advanced Persistence Indicators (HIGH CONFIDENCE)
These are less common in legitimate software:
- Modified LSA providers
- Non-empty AppInit_DLLs (rare legitimate use)
- Debugger entries in IFEO for system executables
- Modified Winlogon Shell or Userinit
- WMI Event Consumers (requires WMI investigation)

## Response Actions

When persistence is detected:

1. **Document the mechanism** - Exact registry path and values
2. **Preserve evidence** - Screenshot or export registry keys
3. **Identify scope** - Check if persistence exists on other systems
4. **Remove carefully** - Some persistence may be required for malware operation
5. **Monitor for re-establishment** - Attackers often have multiple persistence methods

## Important Notes

- **ERROR codes in responses**:
  - 0 = Success
  - 2 = Path not found
  - 5 = Access denied

- **Always check multiple locations** - Attackers use redundant persistence
- **Compare with baseline** - Know what's normal in your environment
- **Focus on unsigned/unusual** - But remember legitimate tools can be abused
- **Time-based analysis** - Recently modified entries are more suspicious

This workflow emphasizes efficiency and targeted investigation, avoiding the token limit issues of comprehensive tools while maintaining thorough coverage of persistence mechanisms.