# Investigation Workflows Guidelines

## Core Principles

All investigation workflows in this directory MUST be based on:

1. **Tested and Validated Approaches** - Every query and technique has been tested against real data
2. **Practical Experience** - Derived from actual incident investigations, not theoretical concepts
3. **Confidence Levels** - Each method is labeled with confidence levels based on real-world effectiveness
4. **Environment Awareness** - Acknowledges that detection effectiveness varies by environment

## Workflow Requirements

### Every workflow MUST include:

1. **Confidence Ratings**
   - `[HIGHEST CONFIDENCE]` - Proven reliable across all environments
   - `[HIGH CONFIDENCE]` - Works in most environments with proper logging
   - `[MEDIUM CONFIDENCE]` - Environment-dependent, requires specific conditions
   - `[LOW CONFIDENCE]` - Limited reliability, use as supplementary method

2. **Real-World Validation**
   - Include actual query results when possible
   - Document known limitations discovered during testing
   - Provide examples of both successful and failed detections

3. **Practical Guidance**
   - Start with highest confidence methods
   - Iterate based on actual results, not assumptions
   - Include time range considerations for performance

4. **Environmental Considerations**
   - Note telemetry requirements (e.g., "Requires Sysmon")
   - Highlight platform-specific queries
   - Document performance impacts of queries

## Example Structure

```markdown
## Detection Method [CONFIDENCE LEVEL]

**Why this works:** [Explanation based on testing]

### Query
```lcql
[Actual tested query]
```

### Known Limitations
- [Discovered during testing]
- [Environmental dependencies]

### Real-World Example
[Actual investigation results]
```

## Key Lessons from Testing

1. **Simple queries first** - Complex queries often fail due to missing data
2. **Verify data exists** - Many theoretical detections fail because events aren't collected
3. **Renamed binaries are common** - Name-based detection alone is insufficient
4. **CODE_IDENTITY is powerful** - Original filenames persist through renaming
5. **Correlation requires multiple methods** - Single detection methods miss sophisticated attacks

## Validation Process

Before adding or updating a workflow:

1. **Test queries against real data** - Confirm events exist and queries return results
2. **Document confidence levels** - Based on success rate across different environments
3. **Include failure scenarios** - Show what doesn't work and why
4. **Provide remediation** - What to do when primary methods fail

## Anti-Patterns to Avoid

❌ **Theoretical queries** - "This should detect X behavior"
❌ **Untested assumptions** - "Attackers always do Y"
❌ **Single detection methods** - "Just look for process name"
❌ **Ignoring environment** - "This works everywhere"

✅ **Validated queries** - "Testing showed this detects X in 90% of cases"
✅ **Multiple approaches** - "If registry detection fails, try CODE_IDENTITY"
✅ **Environmental awareness** - "Requires Windows Event ID 5140 logging"
✅ **Practical limitations** - "Large responses, use limit parameter"

## Continuous Improvement

- Update workflows when new detection methods are validated
- Remove or demote methods that prove unreliable
- Add environmental discoveries from investigations
- Share limitations discovered during incident response

Remember: **Every query in these workflows has been battle-tested.** If it hasn't been validated, it doesn't belong here.