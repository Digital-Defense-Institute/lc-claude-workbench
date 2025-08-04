# Contributing to LimaCharlie Claude MCP Workbench

**A [Digital Defense Institute](https://digitaldefenseinstitute.com) Project**

Thank you for your interest in contributing to the LimaCharlie Claude MCP Workbench! This document provides guidelines and instructions for contributing to this Digital Defense Institute open source project.

## 🤝 How to Contribute

### Reporting Issues

1. **Check existing issues** - Ensure the issue hasn't already been reported
2. **Use issue templates** - Follow the provided templates when available
3. **Provide context** - Include:
   - Claude version
   - LimaCharlie organization type (if relevant)
   - Steps to reproduce
   - Expected vs actual behavior
   - Error messages or logs

### Suggesting Enhancements

1. **Open a discussion** - Start with a GitHub Discussion for new features
2. **Provide use cases** - Explain why this enhancement would be useful
3. **Consider alternatives** - What workarounds currently exist?

### Contributing Code

1. **Fork the repository**
2. **Create a feature branch** - `git checkout -b feature/your-feature-name`
3. **Make your changes**
4. **Test thoroughly** - Ensure your changes work as expected
5. **Commit with clear messages** - Follow conventional commits
6. **Submit a pull request**

## 📝 Contribution Guidelines

### Documentation Contributions

Documentation improvements are highly valued! When contributing docs:

- **Follow existing structure** - Maintain consistency with current documentation
- **Add practical examples** - Real-world use cases are extremely helpful
- **Include comments** - Explain complex queries or workflows
- **Test all examples** - Ensure queries and code snippets actually work
- **Update the index** - Add new docs to README.md if appropriate

### LCQL Query Contributions

When contributing new LCQL queries:

```lcql
# Brief description of what this query detects
# Use case or threat being hunted
-24h | plat == windows | NEW_PROCESS |
event/FILE_PATH contains "suspicious.exe" |
# Add inline comments for complex logic
event/FILE_PATH as Process
event/COMMAND_LINE as Command
# Always include example output format
```

### Workflow Contributions

For new workflows or playbooks:

1. **Provide context** - Explain when and why to use the workflow
2. **Step-by-step instructions** - Clear, numbered steps
3. **Include error handling** - What to do when things go wrong
4. **Add decision points** - When to escalate or pivot
5. **Time estimates** - How long each step typically takes

### Example Structure

```markdown
## Workflow Name

### Purpose
Brief description of what this workflow accomplishes

### Prerequisites
- Required permissions
- Required MCP functions
- Expected environment

### Steps
1. **Step Name** - Description
   ```python
   # Code example
   ```
   
2. **Decision Point** - What to look for
   - If X, then do Y
   - If Z, then escalate

### Expected Outcomes
What success looks like

### Troubleshooting
Common issues and solutions
```

## 🔧 Development Setup

### Local Testing

1. Clone your fork:
   ```bash
   git clone https://github.com/digitaldefenseinstitute/lc-claude-workbench.git
   cd lc-claude-workbench
   ```

2. Configure Claude MCP:
   ```bash
   claude mcp add \
     --transport http \
     limacharlie \
     https://mcp.limacharlie.io/mcp \
     --header "Authorization: Bearer YOUR_API_KEY:YOUR_ORG_ID"
   ```

3. Test your changes with Claude

### Testing Checklist

Before submitting a PR, ensure:

- [ ] All examples run without errors
- [ ] Documentation is clear and accurate
- [ ] No sensitive information is included
- [ ] Comments explain complex logic
- [ ] File follows existing naming conventions
- [ ] Changes are documented in the PR description

## 📋 Pull Request Process

1. **Update documentation** - Include any necessary doc changes
2. **Describe your changes** - Use the PR template
3. **Link related issues** - Reference any related issues
4. **Allow edits** - Enable "Allow edits from maintainers"
5. **Be responsive** - Address review feedback promptly

### PR Title Format

Use conventional commit format:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation only
- `style:` Formatting changes
- `refactor:` Code restructuring
- `test:` Test additions
- `chore:` Maintenance tasks

Examples:
- `feat: add ransomware detection queries`
- `docs: improve MCP configuration instructions`
- `fix: correct timestamp handling in workflows`

## 🏷️ Labeling

We use labels to organize contributions:

- `good first issue` - Suitable for newcomers
- `documentation` - Documentation improvements
- `enhancement` - New features or capabilities
- `bug` - Something isn't working
- `question` - Further information requested
- `duplicate` - This issue or PR already exists
- `help wanted` - Extra attention needed

## 🎯 Priority Areas

Current areas where contributions are especially welcome:

1. **LCQL Query Library** - Additional threat hunting queries
2. **Integration Examples** - Using MCP with other tools
3. **Performance Optimization** - Query efficiency improvements
4. **Video Tutorials** - Screen recordings of workflows
5. **Translations** - Documentation in other languages
6. **Unit Tests** - Testing for queries and workflows
7. **Automation Scripts** - Helper scripts for common tasks

## 📚 Resources

### Learning Resources

- [LimaCharlie Documentation](https://docs.limacharlie.io)
- [LCQL Reference](https://docs.limacharlie.io/docs/lcql)
- [Claude MCP Docs](https://docs.anthropic.com/mcp)
- [MITRE ATT&CK](https://attack.mitre.org)

### Community

- [LimaCharlie Community Forum](https://community.limacharlie.com)
- [GitHub Discussions](https://github.com/digitaldefenseinstitute/lc-claude-workbench/discussions)

## ⚖️ Code of Conduct

### Our Standards

- **Be respectful** - Treat everyone with respect
- **Be collaborative** - Work together effectively
- **Be inclusive** - Welcome diverse perspectives
- **Be constructive** - Provide helpful feedback
- **Be professional** - Maintain professional conduct

### Unacceptable Behavior

- Harassment or discrimination
- Trolling or insulting comments
- Publishing private information
- Inappropriate content
- Other unprofessional conduct

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License held by Digital Defense Institute.

## 🙏 Recognition

Contributors will be recognized in:
- The project README
- Release notes
- Special thanks section

Thank you for helping make the LimaCharlie Claude MCP Workbench better for everyone!

---

Questions? Open a [GitHub Discussion](https://github.com/digitaldefenseinstitute/lc-claude-workbench/discussions), participate in the [LimaCharlie Community Forum](https://community.limacharlie.com), or visit [Digital Defense Institute](https://digitaldefenseinstitute.com).