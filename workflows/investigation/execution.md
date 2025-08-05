# Execution Detection: Renamed and Suspicious Binaries

This workflow focuses on detecting renamed binaries and suspicious execution patterns using CODE_IDENTITY events and other telemetry sources.

> **⚠️ IMPORTANT NOTES:**
> - CODE_IDENTITY events are the most reliable for identifying renamed binaries
> - Original filenames persist even when attackers rename tools
> - Focus on suspicious locations and execution patterns
> - Combine with behavioral analysis for comprehensive detection

## 1. CODE_IDENTITY Analysis [HIGHEST CONFIDENCE]

### Detect Renamed Sysinternals Tools

```lcql
-72h | * | CODE_IDENTITY | event/SIGNATURE/CERT_SUBJECT contains "Microsoft Corporation" AND (event/ORIGINAL_FILE_NAME contains ".exe" OR event/ORIGINAL_FILE_NAME contains ".c") AND event/FILE_PATH not contains event/ORIGINAL_FILE_NAME | event/FILE_PATH as CurrentName event/ORIGINAL_FILE_NAME as RealName event/HASH as SHA256 routing/hostname as Host
```

### Common Attack Tools by Original Name

```lcql
-72h | * | CODE_IDENTITY | event/ORIGINAL_FILE_NAME == "sdelete.exe" OR event/ORIGINAL_FILE_NAME == "procdump.exe" OR event/ORIGINAL_FILE_NAME == "mimikatz.exe" OR event/ORIGINAL_FILE_NAME == "lazagne.exe" OR event/ORIGINAL_FILE_NAME == "rubeus.exe" | event/FILE_PATH as ExecutedAs event/ORIGINAL_FILE_NAME as ActualTool event/HASH as FileHash routing/hostname as Host ts as Timestamp
```

### Suspicious Staging Locations

```lcql
-72h | * | CODE_IDENTITY | (event/FILE_PATH contains "\\Temp\\" OR event/FILE_PATH contains "\\ProgramData\\" OR event/FILE_PATH contains "\\Users\\Public\\" OR event/FILE_PATH contains "\\Windows\\Temp\\") AND event/FILE_PATH contains ".exe" | event/FILE_PATH as StagedFile event/ORIGINAL_FILE_NAME as OriginalName event/SIGNATURE/FILE_IS_SIGNED as IsSigned event/HASH as SHA256 routing/hostname as Host
```

## 2. Batch Execution Patterns [HIGH CONFIDENCE]

### For-Loop Deployment Detection

```lcql
-24h | * | NEW_PROCESS | event/COMMAND_LINE contains "for " AND event/COMMAND_LINE contains " do " AND (event/COMMAND_LINE contains ".exe" OR event/COMMAND_LINE contains "-accepteula") | event/COMMAND_LINE as BatchCommand event/FILE_PATH as Executor routing/hostname as LaunchHost ts as Timestamp
```

### Sequential Tool Execution

```lcql
-6h | * | NEW_PROCESS | event/FILE_PATH contains "\\Temp\\" AND event/COMMAND_LINE contains "\\\\" | event/FILE_PATH as Tool event/COMMAND_LINE as TargetCommand routing/hostname as SourceHost COUNT(event) as ExecutionCount GROUP BY(Tool, SourceHost) ORDER BY ExecutionCount DESC
```

## 3. Unsigned Binary Detection [MEDIUM CONFIDENCE]

### Unsigned Executables from Internet

```lcql
-24h | * | CODE_IDENTITY | event/SIGNATURE/FILE_IS_SIGNED == 0 AND (event/FILE_PATH contains ":Zone.Identifier" OR event/FILE_PATH contains "Downloads") | event/FILE_PATH as UnsignedFile event/HASH as FileHash event/FILE_SIZE as Size routing/hostname as Host
```

### Unsigned in System Directories

```lcql
-24h | * | CODE_IDENTITY | event/SIGNATURE/FILE_IS_SIGNED == 0 AND (event/FILE_PATH contains "\\Windows\\" OR event/FILE_PATH contains "\\System32\\") AND event/FILE_PATH contains ".exe" | event/FILE_PATH as SuspiciousFile event/HASH as FileHash routing/hostname as Host
```

### Rare Unsigned Executions

```lcql
-72h | plat == windows | CODE_IDENTITY | event/SIGNATURE/FILE_IS_SIGNED != 1 | event/FILE_PATH as Path event/HASH as Hash COUNT(event) as Count GROUP BY(Path Hash) ORDER BY Count ASC
```

**Common False Positive Locations (Usually Safe to Ignore):**
- `C:\Windows\assembly\NativeImages_*\` - .NET pre-compiled assemblies
- `C:\Program Files\WindowsApps\` - Windows Store/UWP applications
- System processes with empty hashes (Registry, MemCompression, etc.)

**Focus Monitoring on Unusual Locations:**
- User directories: `C:\Users\*\AppData\Local\Temp\`
- Downloads folders: `C:\Users\*\Downloads\`
- Suspicious paths: `C:\ProgramData\`, `C:\Windows\Temp\`
- Root directories: `C:\`, `D:\`
- Custom application paths outside Program Files

### Hunt for Rare Unsigned Binaries

```lcql
-168h | plat == windows | CODE_IDENTITY | event/SIGNATURE/FILE_IS_SIGNED != 1 AND event/FILE_PATH contains ".exe" AND event/FILE_PATH not contains "\\Windows\\assembly\\NativeImages" AND event/FILE_PATH not contains "\\WindowsApps\\" | event/FILE_PATH as RareUnsigned event/HASH as FileHash COUNT(event) as Occurrences COUNT_UNIQUE(routing/hostname) as UniqueHosts GROUP BY(RareUnsigned, FileHash) ORDER BY Occurrences ASC
```

### Single-Host Unsigned Executables

```lcql
-168h | plat == windows | CODE_IDENTITY | event/SIGNATURE/FILE_IS_SIGNED != 1 AND event/FILE_PATH contains ".exe" | event/HASH as FileHash event/FILE_PATH as FilePath COUNT_UNIQUE(routing/hostname) as HostCount GROUP BY(FileHash, FilePath) ORDER BY HostCount ASC
```

## 4. Hash-Based Detection [HIGHEST CONFIDENCE]

### Known Tool Hashes

```lcql
-168h | * | CODE_IDENTITY | event/HASH == "078163d5c16f64caa5a14784323fd51451b8c831c73396b967b4e35e6879937b" OR event/HASH == "a39d548bb5b0eec77b8259b2a7a0c9e7ca108d16d1fc6df6ebea30f3b0918b30" OR event/HASH == "your_known_bad_hash_here" | event/FILE_PATH as FilePath event/HASH as DetectedHash event/ORIGINAL_FILE_NAME as TrueName routing/hostname as Host
```

### Hash Frequency Analysis

```lcql
-168h | * | CODE_IDENTITY | event/FILE_PATH contains ".exe" | event/HASH as FileHash event/ORIGINAL_FILE_NAME as FileName COUNT_UNIQUE(routing/hostname) as HostCount COUNT(event) as TotalExecutions GROUP BY(FileHash, FileName) ORDER BY TotalExecutions ASC
```

## 5. Multi-Tool Campaigns [HIGH CONFIDENCE]

### Correlated Tool Usage

```lcql
-24h | * | CODE_IDENTITY | (event/ORIGINAL_FILE_NAME == "psexec.c" OR event/ORIGINAL_FILE_NAME == "sdelete.exe" OR event/ORIGINAL_FILE_NAME == "procdump.exe" OR event/ORIGINAL_FILE_NAME contains "mimikatz") | routing/hostname as Host event/ORIGINAL_FILE_NAME as Tool COUNT_UNIQUE(Tool) as UniqueTools GROUP BY(Host) ORDER BY UniqueTools DESC
```

### Timeline Correlation

```lcql
-24h | * | CODE_IDENTITY NEW_PROCESS | routing/hostname == "eng-01.initechsw.com" AND (event/FILE_PATH contains "\\Temp\\" OR event/ORIGINAL_FILE_NAME exists) | ts as Timestamp routing/event_type as EventType event/FILE_PATH as File event/ORIGINAL_FILE_NAME as TrueName event/COMMAND_LINE as Command ORDER BY Timestamp ASC
```

## 6. Living Off the Land (LOTL) Detection [MEDIUM CONFIDENCE]

### Rundll32 Abuse Detection

```lcql
-6h | plat==windows | NEW_PROCESS EXISTING_PROCESS | event/FILE_PATH contains "rundll32.exe" AND event/COMMAND_LINE not contains ".dll" | ts as Timestamp event/FILE_PATH as Path event/COMMAND_LINE as CommandLine routing/hostname as Hostname
```

**Why This Works:**
- Rundll32.exe should always have a DLL parameter
- Missing DLL argument indicates proxy execution or abuse
- Common technique for executing malicious code

### Rundll32 with Network Activity

```lcql
-6h | plat==windows | NETWORK_CONNECTIONS | event/FILE_PATH contains "rundll32.exe" | event/FILE_PATH as Process event/NETWORK_ACTIVITY/DESTINATION/IP_ADDRESS as DestIP event/NETWORK_ACTIVITY/DESTINATION/PORT as DestPort routing/hostname as Host
```

**Red Flags:**
- Rundll32.exe making direct network connections
- Especially suspicious to non-standard ports
- May indicate C2 communication through DLL

### Base64 Encoded Commands

```lcql
-1h | plat == windows | NEW_PROCESS EXISTING_PROCESS | event/COMMAND_LINE contains "RwBlAHQALQBQAHIAbwBjAGUAcwBzACAATQBzAE0AcABFAG4AZwAsAHMAeQBzAG0AbwBuACoA" | event/FILE_PATH as Path event/COMMAND_LINE as EncodedCommand routing/hostname as Host
```

**Detection Strategy:**
- Look for known malicious base64 patterns
- Focus on PowerShell encoded commands
- Monitor for download/execute patterns

### Command Execution Chains

```lcql
-12h | plat == windows | NEW_PROCESS | event/PARENT/FILE_PATH contains "cmd.exe" | event/PARENT/FILE_PATH as Parent event/FILE_PATH as Child COUNT_UNIQUE(event) as Count GROUP BY(Parent Child)
```

**Analysis Focus:**
- Identify unusual parent-child relationships
- Look for cmd.exe spawning suspicious processes
- High counts indicate scripted activity

### Renamed Windows Binaries

```lcql
-24h | * | CODE_IDENTITY | event/SIGNATURE/CERT_SUBJECT contains "Microsoft Windows" AND event/FILE_PATH not contains event/ORIGINAL_FILE_NAME AND event/FILE_PATH not contains "\\Windows\\" | event/FILE_PATH as RenamedSystemTool event/ORIGINAL_FILE_NAME as ActualTool routing/hostname as Host
```

### LOTL Tool Abuse

```lcql
-24h | * | NEW_PROCESS | (event/FILE_PATH contains "certutil.exe" OR event/FILE_PATH contains "bitsadmin.exe" OR event/FILE_PATH contains "mshta.exe") AND (event/COMMAND_LINE contains "-decode" OR event/COMMAND_LINE contains "-download" OR event/COMMAND_LINE contains "http") | event/FILE_PATH as LOTLTool event/COMMAND_LINE as SuspiciousUsage routing/hostname as Host
```

## Investigation Workflow

### 1. Initial Detection
- Start with CODE_IDENTITY queries to find renamed tools
- Check for unsigned binaries in suspicious locations
- Look for batch execution patterns

### 2. Tool Identification
- Use ORIGINAL_FILE_NAME to identify true tool identity
- Compare file hashes against known tools
- Check certificate information for legitimacy

### 3. Campaign Analysis
- Correlate multiple tools used together
- Build timeline of execution events
- Identify staging directories and persistence

### 4. Response Priorities
- **Critical**: Renamed credential dumpers (mimikatz, lazagne)
- **High**: Lateral movement tools (psexec, wmic)
- **Medium**: Data destruction tools (sdelete, cipher)
- **Low**: Legitimate tools in proper locations

## Key Detection Rules

### High-Fidelity Indicators
1. **ORIGINAL_FILE_NAME mismatch** - File renamed from original
2. **Suspicious staging paths** - Temp, ProgramData, Public
3. **Batch deployment patterns** - For loops with multiple targets
4. **Multi-tool usage** - Multiple attack tools on same host
5. **Unsigned in system directories** - Suspicious binary placement

### Environmental Considerations
- Some legitimate software uses Temp directories
- System management tools may appear suspicious
- Consider organizational software deployment methods
- Baseline normal administrative tool usage

## Automation Opportunities

1. **Alert on renamed Sysinternals tools**
2. **Flag unsigned executables in Windows directories**
3. **Detect batch deployment patterns**
4. **Monitor for known attack tool hashes**
5. **Track multi-tool campaign indicators**

## Example: Ransomware Campaign Detection

Our investigation revealed:
- **p.exe** = PsExec (ORIGINAL_FILE_NAME: psexec.c)
- **s.exe** = SDelete (ORIGINAL_FILE_NAME: sdelete.exe)
- Batch deployment via for-loop
- Staged in Temp directory
- Used to deploy cryptolocker2.exe

This workflow would have detected:
1. Renamed tools via CODE_IDENTITY
2. Batch execution pattern
3. Suspicious staging location
4. Multi-tool campaign correlation

## 7. Long-Tail Analysis for Suspicious Locations [HIGHEST CONFIDENCE - VALIDATED]

### Rare Executables in Malware Staging Directories

```lcql
-168h | * | NEW_PROCESS | (event/FILE_PATH contains "\\ProgramData\\" OR event/FILE_PATH contains "\\Users\\Public\\" OR event/FILE_PATH contains "\\Windows\\Temp\\" OR event/FILE_PATH contains "\\AppData\\Local\\Temp\\" OR event/FILE_PATH contains "\\AppData\\Roaming\\") AND event/FILE_PATH contains ".exe" | event/FILE_PATH as SuspiciousPath COUNT(event) as Executions COUNT_UNIQUE(routing/hostname) as Hosts GROUP BY(SuspiciousPath) ORDER BY Executions ASC
```

**Why This Works:**
- Malware often executes only once or twice from staging directories
- Legitimate software typically has consistent, repeated execution patterns
- Single-host, low-execution-count binaries are highly suspicious
- Long-tail (rare) events often reveal malicious activity

### Critical Staging Locations to Monitor

1. **Persistence Locations:**
   - `\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\`
   - `\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\`
   - `\\Users\\[username]\\AppData\\Roaming\\`

2. **Common Malware Staging:**
   - `\\Users\\Public\\` - World-writable directory
   - `\\Windows\\Temp\\` - System-level temporary storage
   - `\\AppData\\Local\\Temp\\` - User temporary directories
   - `\\ProgramData\\` - Application data directories

3. **High-Risk Patterns:**
   - Subdirectories with random names or GUIDs
   - Very short executable names (1-3 characters)
   - Executables in numbered subdirectories
   - Files in temp with persistence-related names

### Investigation Methodology

1. **Start with Extended Timeframe**
   - Use 168h (7 days) to capture rare executions
   - Longer timeframes reveal true long-tail anomalies

2. **Focus on Statistical Anomalies**
   - Executions = 1 (single execution)
   - Hosts = 1 (single host affected)
   - Order by execution count ascending

3. **Pattern Recognition**
   - Executable names shorter than 5 characters
   - Files in subdirectories of temp locations
   - Presence in multiple suspicious locations
   - Execution timing (off-hours, weekends)

4. **Exclude Known Good**
   - Windows update components (dismhost.exe)
   - Legitimate installer patterns
   - Known software deployment tools
   - Build a baseline of normal activity

### Response Prioritization

**Critical Priority:**
- Any executable in Startup folders with low execution count
- Executables in \\Users\\Public\\ with single execution
- Very short filenames in temp directories

**High Priority:**
- Single-execution files in \\Windows\\Temp\\
- Executables in numbered/GUID subdirectories
- Files executing from multiple suspicious locations

**Medium Priority:**
- Low-execution count in \\ProgramData\\
- Unusual patterns in \\AppData\\Roaming\\
- First-time-seen executables in any staging location

### Automation Opportunities

1. **Baseline Normal Activity**
   - Create allowlist of legitimate temp executables
   - Track normal execution counts over time
   - Build profiles of legitimate staging activity

2. **Real-Time Detection Rules**
   - Alert on first-time execution from Startup folders
   - Flag single-character executables in temp
   - Monitor for execution count anomalies

3. **Statistical Thresholds**
   - Execution count ≤ 3 in 7 days from staging locations
   - Present on ≤ 2 hosts in the environment
   - File age < 24 hours with immediate execution

This long-tail analysis approach has proven highly effective at identifying:
- Advanced persistent threats
- Ransomware staging
- Living-off-the-land attacks
- Custom malware deployment
- Persistence mechanisms

Remember: CODE_IDENTITY analysis is your most powerful tool for unmasking renamed binaries, and long-tail analysis is your most effective method for discovering rare malicious executions in staging directories.