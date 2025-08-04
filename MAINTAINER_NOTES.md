# Maintainer Notes

## Claude Code File References

Claude Code automatically loads and processes files referenced with the `@` prefix in CLAUDE.md. This provides context to Claude AI when working in this project.

### How File References Work

When you use `@path/to/file.md` in CLAUDE.md, Claude Code:
1. Automatically includes that file's content in Claude's context
2. Makes the file available for Claude to reference during conversations
3. Allows Claude to understand project-specific patterns and examples

### Current Structure

```
CLAUDE.md (main context file)
├── @instructions/
│   ├── LCQL_EXAMPLES.md      - Query patterns
│   ├── SAMPLE_EVENTS.md      - Event structures
│   ├── CLAUDE-REFERENCE.md   - Function reference
│   └── CLAUDE-WORKFLOWS.md   - Workflows
└── @examples/
    ├── incident-response-playbook.md
    └── threat-hunting-queries.md
```

### Adding New Reference Files

1. Create your file in the appropriate directory
2. Add a reference in CLAUDE.md using the format: `@directory/filename.md`
3. Include a brief description of what the file contains

### Important Notes

- **No Wildcard Support**: Claude Code doesn't support patterns like `@instructions/*.md`
- **Each file must be explicitly referenced** in CLAUDE.md
- **Keep CLAUDE.md concise** - it's the primary context file
- **Use subdirectories** to organize related content

### Best Practices

1. **Limit total context size** - Too many referenced files can slow down Claude
2. **Use clear, descriptive filenames** that indicate content
3. **Keep individual files focused** on specific topics
4. **Update CLAUDE.md** whenever adding/removing reference files
5. **Test references** by starting Claude Code and verifying context loads

---

Developed by [Digital Defense Institute](https://digitaldefenseinstitute.com)