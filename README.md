# LimaCharlie Claude MCP Workbench

**Developed by [Digital Defense Institute](https://digitaldefenseinstitute.com)**

> ⚠️ **CRITICAL DISCLAIMER** ⚠️
> 
> **THIS PROJECT IS A PROOF OF CONCEPT AND WORK IN PROGRESS**
> 
> - **DO NOT** rely solely on this tool for production security investigations
> - **ALWAYS** validate AI-generated findings with human expertise
> - **REQUIRES** proper training and understanding of both LimaCharlie and security operations
> - **ALL OUTPUTS** must be verified by qualified security professionals
> - **USER ASSUMES ALL RISKS** associated with the use of these tools
> - **NO WARRANTY** is provided for accuracy, completeness, or fitness for any purpose
> 
> This tool is intended to **augment** human analysts, not replace them. Critical security decisions should **NEVER** be made based solely on AI-generated content without thorough validation.
> 
> See [DISCLAIMER.md](DISCLAIMER.md) for full legal disclaimer.

A comprehensive guide and reference for using Claude AI with the LimaCharlie Model Context Protocol (MCP) integration for security operations, threat hunting, and incident response.

## 🌟 Overview

This repository provides documentation, examples, and best practices for leveraging Claude AI's capabilities with LimaCharlie's SecOps Cloud Platform through the MCP integration. Whether you're a security analyst, incident responder, or detection engineer, this workbench will help you maximize the power of AI-assisted security operations.

### What is LimaCharlie?

[LimaCharlie](https://limacharlie.io) is a SecOps Cloud Platform that provides endpoint detection and response (EDR), log management, and threat detection capabilities. It offers a powerful, API-first approach to security operations.

### What is Claude MCP?

The Model Context Protocol (MCP) is an open protocol that enables Claude AI to interact with external systems and tools. The LimaCharlie MCP integration allows Claude to directly query sensors, analyze detections, and assist with security investigations.

- **LimaCharlie MCP Documentation**: [docs.limacharlie.io/docs/mcp-server](https://docs.limacharlie.io/docs/mcp-server)
- **Claude Code MCP Guide**: [docs.anthropic.com/en/docs/claude-code/mcp](https://docs.anthropic.com/en/docs/claude-code/mcp)

## 🚀 Quick Start

### Prerequisites

- **Node.js** (v18+) - [nodejs.org](https://nodejs.org)
- **Claude Code CLI** - `npm install -g @anthropic-ai/claude-code` ([Learn more](https://www.anthropic.com/claude-code))
- **LimaCharlie Account** - [limacharlie.io](https://limacharlie.io)

### 30-Second Setup

**1. Clone this repository with submodules**
```bash
git clone --recurse-submodules https://github.com/Digital-Defense-Institute/lc-claude-workbench.git
```
Or if you already cloned without submodules:
```bash
git submodule update --init --recursive
```

**2. Enter the project directory**
```bash
cd lc-claude-workbench
```

**3. Install Claude Code**
```bash
npm install -g @anthropic-ai/claude-code
```

**4. Get your LimaCharlie Organization API Key and Org ID**
- Navigate to: `https://app.limacharlie.io/org/<your-org-id>/rest-api`
- Create a "User-Generated API Key" (this is at ORG level, not user level)

**5. Configure MCP** (run from project directory)
```bash
claude mcp add \
  limacharlie \
  https://mcp.limacharlie.io/mcp \
  --transport http \
  --header "Authorization: Bearer YOUR_API_KEY:YOUR_ORG_ID"
```

**6. Start Claude in this project**
```bash
claude
```

**7. Test it**
Ask Claude: "List my LimaCharlie sensors"

📖 **For detailed setup instructions, troubleshooting, and security best practices, see [setup.md](setup.md)**

## 📖 Documentation Structure

### Core Documentation

- **[CLAUDE.md](CLAUDE.md)** - Essential usage guide with critical notes and quick reference
- **[instructions/](instructions/)** - Detailed documentation directory:
  - **[CLAUDE-REFERENCE.md](instructions/CLAUDE-REFERENCE.md)** - Complete MCP function reference
  - **[CLAUDE-WORKFLOWS.md](instructions/CLAUDE-WORKFLOWS.md)** - Common workflows and examples
  - **[LCQL_EXAMPLES.md](instructions/LCQL_EXAMPLES.md)** - LimaCharlie Query Language patterns
  - **[SAMPLE_EVENTS.md](instructions/SAMPLE_EVENTS.md)** - Event structure examples for detection engineering


## 💡 Key Concepts

- **Atoms** - Unique event/process identifiers (more reliable than PIDs)
- **LCQL** - LimaCharlie Query Language for searching events
- **UTC Timestamps** - Always required for API queries
- **Time Ranges** - Start with small ranges and expand as needed

📖 **See [CLAUDE.md](CLAUDE.md) for critical usage notes and common pitfalls**

## 📚 Example Use Cases

- **Incident Response** - Triage detections, investigate processes, collect IOCs
- **Threat Hunting** - Search for unsigned binaries, suspicious PowerShell, network anomalies  
- **Detection Engineering** - Generate AI-powered detection rules and response actions
- **Compliance** - Monitor system changes, audit user activities, track data access

📖 **See [examples/](examples/) for detailed playbooks and workflows**

## 🛠️ MCP Functions Overview

**Core Functions**: Sensor management, process inspection, detection queries, LCQL execution
**AI Functions**: Generate detection rules, LCQL queries, and analyst summaries from natural language

📖 **See [instructions/CLAUDE-REFERENCE.md](instructions/CLAUDE-REFERENCE.md) for complete function reference**
📖 **See [instructions/LCQL_EXAMPLES.md](instructions/LCQL_EXAMPLES.md) for query patterns**


## ⚖️ Responsible Use Guidelines

### This Tool Should Be Used To:
- **Augment** human security analysts (not replace them)
- **Generate hypotheses** for further investigation
- **Speed up** initial triage and data gathering
- **Learn** about security operations and AI integration
- **Experiment** in safe, non-production environments

### This Tool Should NOT Be Used To:
- **Make automated decisions** without human review
- **Replace security professionals** or their judgment
- **Handle sensitive incidents** without proper oversight
- **Generate final reports** without validation
- **Operate in production** without extensive testing

### Required Safeguards:
1. **Human-in-the-loop**: Always have qualified personnel review outputs
2. **Validation workflows**: Establish procedures to verify AI findings
3. **Audit trails**: Log all AI suggestions and human decisions
4. **Training**: Ensure users understand both the tool and its limitations
5. **Fallback procedures**: Maintain manual investigation capabilities

## 🤝 Contributing

This project is maintained by [Digital Defense Institute](https://digitaldefenseinstitute.com). We welcome contributions! Please:

1. Fork the repository
2. Create a feature branch
3. Add your improvements (documentation, examples, workflows)
4. Submit a pull request

### Areas for Contribution

- Additional LCQL query examples
- Detection rule templates
- Incident response playbooks
- Integration workflows
- Performance optimization tips

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Resources

### LimaCharlie Documentation
- [LimaCharlie Documentation](https://docs.limacharlie.io)
- [LimaCharlie MCP Server](https://docs.limacharlie.io/docs/mcp-server)
- [LimaCharlie API Reference](https://api.limacharlie.io)
- [LCQL Reference](https://docs.limacharlie.io/docs/lcql)
- [LimaCharlie Community Forum](https://community.limacharlie.com)

### Claude Code Documentation
- [Claude Code Product Page](https://www.anthropic.com/claude-code)
- [Claude Code GitHub Repository](https://github.com/anthropics/claude-code)
- [Claude Code Overview](https://docs.anthropic.com/en/docs/claude-code/overview)
- [Claude Code Memory Management](https://docs.anthropic.com/en/docs/claude-code/memory)
- [Claude Code MCP Integration](https://docs.anthropic.com/en/docs/claude-code/mcp)

## 💬 Support

- **LimaCharlie Support**: [support.limacharlie.io](https://support.limacharlie.io)
- **Community Forum**: [community.limacharlie.com](https://community.limacharlie.com)
- **Issues**: Use the GitHub Issues tab for bug reports and feature requests

## 🙏 Acknowledgments

- **[Digital Defense Institute](https://digitaldefenseinstitute.com)** - Project development and maintenance
- The LimaCharlie team for their excellent SecOps Cloud Platform and MCP integration
- Anthropic for Claude AI and the Model Context Protocol
- The security community for continuous feedback and improvements

---

---

**Developed and Maintained by**: [Digital Defense Institute](https://digitaldefenseinstitute.com)

**Note**: This is a community resource developed by Digital Defense Institute. For official LimaCharlie documentation, please visit [docs.limacharlie.io](https://docs.limacharlie.io).