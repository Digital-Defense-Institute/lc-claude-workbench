# LimaCharlie MCP Usage Guide

> **⚠️ IMPORTANT: This is a PROOF OF CONCEPT. All outputs MUST be validated by qualified security professionals. See [DISCLAIMER.md](DISCLAIMER.md) for critical safety information.**

This document contains critical instructions for working with the LimaCharlie MCP integration.

## Additional Resources

### Core References
@instructions/LCQL_EXAMPLES.md - LCQL query patterns
@instructions/SAMPLE_EVENTS.md - Event structure examples  
@instructions/CLAUDE-REFERENCE.md - Complete function reference
@instructions/CLAUDE-WORKFLOWS.md - Example workflows and best practices

### Practical Examples
@examples/incident-response-playbook.md - Step-by-step IR procedures
@examples/threat-hunting-queries.md - Proactive threat hunting patterns

### Investigation Workflows (Confidence-Rated)
@workflows/investigation/CLAUDE.md - Guidelines for creating confidence-rated workflows
@workflows/investigation/execution.md - Detecting renamed binaries & suspicious execution (CODE_IDENTITY focus)
@workflows/investigation/lateral-movement.md - Systematic lateral movement detection with 5 PsExec methods

### Sigma Detection Rules Reference
@references/sigma-limacharlie/ - Community-maintained Sigma rules converted to LimaCharlie format
- Contains 3,200+ detection rules from the Sigma project (on `rules` branch)
- Organized by platform (Windows, Linux, macOS) and detection maturity
- Use as inspiration for crafting queries and understanding suspicious behaviors
- Update regularly with: `git submodule update --remote --merge` in project root

## 📝 Continuous Documentation Improvement

**IMPORTANT**: As you work with LimaCharlie MCP, continuously validate and improve these instructions:

1. **Track Issues**: When queries fail or behave unexpectedly, note the root cause
2. **Verify Examples**: Test that LCQL examples actually work with real data
3. **Document Discoveries**: When you learn new patterns or limitations, suggest updates
4. **Propose Changes**: Always suggest documentation improvements when you identify:
   - Incorrect LCQL syntax or examples
   - Missing guidance on timestamp handling
   - Undocumented field structures or array notations
   - New troubleshooting techniques
   - Better investigation workflows

**When suggesting updates**: 
- Clearly explain what's wrong with current instructions
- Provide the corrected version with examples
- Ask user to confirm before making changes
- Only update instructions you're 100% confident are correct

Example: "I discovered that NETWORK_ACTIVITY requires array notation (*/). Should I update the documentation to reflect this?"

## ⚠️ Critical Notes

### 🛑 HIGH-IMPACT COMMAND SAFETY

**NEVER automatically execute high-impact commands without explicit user confirmation:**

#### Commands Requiring Explicit Confirmation:
- **`isolate_network(sid)`** - Quarantines endpoint from network
  - ⚠️ IMPACT: Disconnects system from all network access
  - ⚠️ IMPACT: May disrupt business operations
  - ⚠️ IMPACT: Requires `rejoin_network()` to restore connectivity
  - **ALWAYS ASK:** "This will isolate the endpoint from the network. Are you sure you want to proceed?"

- **`add_tag()` / `remove_tag()`** - Modifies sensor tags
  - ⚠️ IMPACT: May trigger automated response rules
  - ⚠️ IMPACT: Changes how system is treated by policies
  - **ALWAYS ASK:** "This will modify sensor tags which may trigger automated actions. Proceed?"

- **YARA scanning operations** - Memory/file scanning
  - ⚠️ IMPACT: Can cause performance degradation
  - ⚠️ IMPACT: May trigger false positives
  - **ALWAYS WARN:** About potential performance impact before scanning

#### Required Safety Protocol:
1. **EXPLAIN the impact** - Clearly describe what will happen
2. **WARN about risks** - Outline potential disruptions
3. **ASK for confirmation** - Get explicit "yes" from user
4. **PROVIDE rollback steps** - Explain how to undo if needed
5. **NEVER assume intent** - Even if user seems to imply action

#### Example Safe Interaction:
```
User: "The system looks compromised"
Assistant: "I can see suspicious activity. To contain this threat, I could isolate the endpoint from the network. 

⚠️ WARNING: Network isolation will:
- Disconnect ALL network access immediately
- Potentially disrupt user work and services
- Require manual intervention to restore connectivity

To proceed with isolation, please explicitly confirm: 'Yes, isolate the system'
To continue investigation without isolation: 'Continue without isolation'"
```

### Time and Timestamps

- **ALWAYS use UTC timestamps** when querying LimaCharlie APIs
- **CRITICAL: Always get current time with `date -u +%s` FIRST** - Never use hardcoded timestamps
- LimaCharlie expects all time parameters in Unix epoch format
- **🚨 CRITICAL TIMESTAMP CONVERSION:**
  - LimaCharlie event timestamps are in **milliseconds** (e.g., `1754346325456`)
  - For Unix timestamp conversion, **divide by 1000** to get seconds: `1754346325`
  - **ALWAYS double-check date conversions** - Use online converter or `date -d @<seconds>` command
  - Common fields with millisecond timestamps: `event_time`, `ts`, `timestamp`
  - **NEVER guess or estimate dates** - Always calculate precisely
  - Example: `1754346325` seconds = `2025-08-04 22:25:25 UTC` (NOT July or January!)
- **Process Creation Times**: 
  - Processes may have been created days/weeks ago, outside the 7-day LCQL query window
  - **Always check CREATION_TIME** in get_processes() results before attempting historical queries
  - If process creation is outside query range, focus on recent activity (network, DNS, file operations)
- Historic queries have practical limitations:
  - Start with small time ranges (minutes) and expand as needed
  - API may timeout or truncate results for large time ranges
  - Free tier: Last 30 days of data queryable without additional cost
  - Use `limit` parameter to control response size

### Common Issues and Solutions

1. **Empty Detection Results**: Verify UTC timestamps, check time ranges
2. **Response Size Limits**: Always use `limit` parameter
3. **LCQL Date Format**: Use `YYYY-MM-DD HH:MM:SS` for absolute times
4. **YARA Rules**: Must exist in org, use rule name not content

### Understanding Atoms

Atoms are GUIDs that uniquely identify events/processes. Unlike PIDs which can be reused, atoms provide permanent references:
- **`routing/this`**: Current event's atom
- **`routing/parent`**: Parent event's atom  
- **`routing/target`**: Target event's atom (cross-process events)

Always prefer atoms over PIDs for relationship tracking.

## 🚀 Quick Start Examples

```python
# IMPORTANT: Always get fresh UTC timestamp first!
current_time = $(date -u +%s)  # Execute this shell command

# Check sensor status
is_online(sid="sensor-id")

# Get recent detections (max limit=20 to avoid token limits)
get_historic_detections(start=current_time-600, end=current_time, limit=20)

# Investigate process
get_process_modules(sid="sensor-id", pid=suspicious_pid)
```

## 🔧 Key MCP Functions

### Essential Functions
<!-- These are the most commonly used functions for daily operations -->
- `is_online(sid)` - Check sensor status
- `get_historic_detections(start, end, limit)` - Query recent detections (max limit=20)
- `run_lcql_query(query, limit)` - Execute LCQL queries
- `get_processes(sid)` - List running processes
- `find_strings(sid, strings, pid)` - Search strings in memory

### AI Generation (Organization-Aware)
<!-- These functions use AI to generate org-specific rules based on your actual data -->
- `generate_dr_rule_detection(query)` - Generate detection logic
- `generate_lcql_query(query)` - Generate LCQL queries
- `generate_detection_summary(query)` - Generate analyst summaries

See @instructions/CLAUDE-REFERENCE.md for complete function list.

## 🔍 Investigation Best Practices

<!-- Follow these patterns for effective investigations -->

1. **Always check sensor online status** before running commands
2. **Use appropriate time ranges** to avoid API timeouts
3. **Handle large responses** with limit parameters
4. **Show complete raw events** for important findings
5. **Use parallel queries** for initial context gathering
6. **Verify parent-child relationships** using atoms when available
7. **ALWAYS check for persistence** when C2/beacon activity is detected:
   - Query registry Run keys (HKLM/HKCU)
   - Check scheduled tasks
   - Look for service installations
   - Examine WMI event subscriptions
   - Search for modified startup folders

Use AI generation tools to create org-specific rules based on your actual event data.

## ⚡ Performance Tips

<!-- Optimize your queries to avoid timeouts and large responses -->

- Functions that commonly exceed limits: 
  - `get_services()` - Often returns 35K+ tokens
  - `get_detection_rules()` - Full ruleset too large
  - `get_process_strings()` - Can be very large
  - `get_historic_detections()` - **Use limit≤20 to avoid 25K token limit**
- Always use `limit` parameter
- Start with small limits and increase if needed
- Use LCQL filters to reduce result size
- Query specific items rather than all items

For detailed examples and workflows, see the files in @instructions/

## External Documentation

- **LimaCharlie MCP Server**: [docs.limacharlie.io/docs/mcp-server](https://docs.limacharlie.io/docs/mcp-server)
- **Claude Code Overview**: [docs.anthropic.com/en/docs/claude-code/overview](https://docs.anthropic.com/en/docs/claude-code/overview)
- **Claude Code MCP Guide**: [docs.anthropic.com/en/docs/claude-code/mcp](https://docs.anthropic.com/en/docs/claude-code/mcp)