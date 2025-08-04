# LimaCharlie MCP Function Reference

<!-- 
  Developed by Digital Defense Institute (https://digitaldefenseinstitute.com)
  Complete reference for all available MCP functions.
  Functions are grouped by category for easy navigation.
  Each function includes parameters and common usage patterns.
-->

## Available MCP Functions

### Testing & Diagnostics
<!-- Use these functions to verify connectivity and troubleshoot issues -->
- `mcp__limacharlie__test_tool()` - Verify MCP server is working

### Sensor Management
<!-- Functions for managing and monitoring endpoints/sensors -->
- `list_with_platform(platform)` - Get sensors by platform (windows/linux/macos)
- `is_online(sid)` - Check if sensor is online
- `is_isolated(sid)` - Check network isolation status
- `isolate_network(sid)` - Quarantine sensor
- `rejoin_network(sid)` - Remove isolation
- `add_tag(sid, tag, ttl)` - Add tag with TTL
- `remove_tag(sid, tag)` - Remove tag

### Detection & Response
<!-- Query and manage detection rules and alerts -->
- `get_detection_rules()` - Get all D&R rules (WARNING: Large)
- `get_fp_rules()` - Get false positive rules
- `get_historic_detections(start, end, limit, cat)` - Get detections within time range
- `get_mitre_report()` - MITRE ATT&CK coverage
- `run_lcql_query(query, limit)` - Execute LCQL queries

### AI Generation
<!-- AI-powered functions that generate rules/queries based on your org's data -->
- `generate_dr_rule_detection(query)` - Generate detection logic
- `generate_dr_rule_respond(query)` - Generate response actions
- `generate_lcql_query(query)` - Generate LCQL queries
- `generate_sensor_selector(query)` - Generate sensor selectors
- `generate_python_playbook(query)` - Generate Python automation
- `generate_detection_summary(query)` - Generate analyst summaries

### System Information
<!-- Gather detailed information from endpoints -->
- `get_processes(sid)` - List running processes
- `get_process_modules(sid, pid)` - Get loaded DLLs/modules
- `get_process_strings(sid, pid)` - Extract strings from memory
- `get_network_connections(sid)` - Active network connections
- `get_services(sid)` - Windows services (Large)
- `get_autoruns(sid)` - Startup entries
- `get_drivers(sid)` - Kernel drivers
- `get_packages(sid)` - Installed software
- `get_users(sid)` - System users
- `get_os_version(sid)` - OS details
- `get_registry_keys(sid, path)` - Query registry

### Security Analysis
<!-- Advanced analysis capabilities including YARA and string searches -->
- `yara_scan_process(sid, rule, pid)` - Scan process with YARA
- `yara_scan_file(sid, rule, file_path)` - Scan file
- `yara_scan_directory(sid, rule, root_directory, file_expression)` - Scan directory
- `yara_scan_memory(sid, rule, process_expr)` - Scan memory
- `find_strings(sid, strings, pid)` - Search strings in memory

### Events & Timeline
<!-- Query historical events and reconstruct timelines -->
- `get_historic_events(sid, start_time, end_time)` - Get events within time range
- `get_time_when_sensor_has_data(sid, start, end)` - Find data timestamps

### Schema & Platform Info
<!-- Understand event structures and platform capabilities -->
- `get_event_schema(name)` - Get event type schema
- `get_event_schemas_batch(event_names)` - Get multiple schemas
- `get_event_types_with_schemas()` - List all event types
- `get_event_types_with_schemas_for_platform(platform)` - Platform event types
- `get_platform_names()` - Available platforms

## 💡 Understanding Atoms

<!-- 
  Atoms are critical for accurate event correlation.
  Unlike PIDs which get reused, atoms provide permanent unique identifiers.
-->

Atoms are GUIDs that uniquely identify events/processes:
- `routing/this` - Current event's atom
- `routing/parent` - Parent event's atom  
- `routing/target` - Target event's atom (for cross-process events)

Use atoms instead of PIDs for reliable relationship tracking.