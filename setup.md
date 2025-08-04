# Quick Setup Guide for Claude Code

<!-- 
  Developed by Digital Defense Institute (https://digitaldefenseinstitute.com)
  Step-by-step setup instructions for Claude Code CLI users.
  This guide covers installation, configuration, and verification.
-->

> **⚠️ WARNING: PROOF OF CONCEPT**  
> This tool is experimental and requires human validation of all outputs.  
> See [DISCLAIMER.md](DISCLAIMER.md) before using in any security operations.

## Prerequisites Checklist

Before starting, ensure you have:

- [ ] **Node.js installed** (v18+ recommended - get from [nodejs.org](https://nodejs.org))
- [ ] **Claude Code CLI** or plan to install it
- [ ] **LimaCharlie account** (sign up at [limacharlie.io](https://limacharlie.io))
- [ ] **This repository** cloned to your computer

## Step 1: Install Claude Code

Learn more about Claude Code:
- **Product Overview**: [anthropic.com/claude-code](https://www.anthropic.com/claude-code)
- **Documentation**: [docs.anthropic.com/en/docs/claude-code/overview](https://docs.anthropic.com/en/docs/claude-code/overview)
- **GitHub**: [github.com/anthropics/claude-code](https://github.com/anthropics/claude-code)

```bash
# Install Claude Code globally via npm
npm install -g @anthropic-ai/claude-code

# Verify installation
claude --version

# If you get "command not found", ensure npm's global bin is in your PATH
# Usually: ~/.npm-global/bin or /usr/local/bin
```

**Alternative: Use npx without installing**
```bash
# Run Claude Code without installing globally
npx @anthropic-ai/claude-code
```

## Step 2: Get LimaCharlie Credentials

For more details on LimaCharlie MCP configuration, see: [docs.limacharlie.io/docs/mcp-server](https://docs.limacharlie.io/docs/mcp-server)

### Create Organization API Key

> ⚠️ **CRITICAL: You need an Organization-level API Key**
> 
> The option is called "User-Generated API Keys" but these exist at the ORGANIZATION level, not user level!

1. **Log into LimaCharlie** at [app.limacharlie.io](https://app.limacharlie.io)
2. Navigate to your organization's REST API page:
   - Direct URL: `https://app.limacharlie.io/org/<your-org-id>/rest-api`
   - Or: Click org name → "Access Management" → "REST API"
3. Find the **"User-Generated API Keys"** section
4. Click **"Create New API Key"**
5. Name it: `Claude-Code-MCP`
6. Set expiry (recommendation: 90 days, rotate regularly)
7. Select minimum required permissions:
   ```
   ✅ sensor.get      - Read sensor information
   ✅ detection.get   - Read detections  
   ✅ dr.get          - Read detection rules
   ✅ insight.get     - Query capabilities
   ✅ sensor.task     - Execute sensor tasks (recommended for response)
   ```
8. Click **"Create"**
9. **IMMEDIATELY COPY THE API KEY** - You won't see it again!

**Important Notes:**
- Despite the name "User-Generated", these keys operate at the organization level
- This is different from personal user API keys
- The key will have access to all sensors in your organization

### Get Organization ID

1. In LimaCharlie, click your organization name (top-left)
2. Go to **"Organization"** → **"Settings"**
3. Copy the **Organization ID** (UUID format like: `a1b2c3d4-e5f6-7890-abcd-ef1234567890`)

## Step 3: Configure Claude Code MCP

### Option A: Direct Configuration (Quick Start)

```bash
# Add the LimaCharlie MCP server
claude mcp add \
  --transport http \
  limacharlie \
  https://mcp.limacharlie.io/mcp \
  --header "Authorization: Bearer YOUR_API_KEY:YOUR_ORG_ID"

# Example with actual format (DO NOT COMMIT):
# claude mcp add \
#   --transport http \
#   limacharlie \
#   https://mcp.limacharlie.io/mcp \
#   --header "Authorization: Bearer 2a3b4c5d-6e7f-8a9b-0c1d-2e3f4a5b6c7d:a1b2c3d4-e5f6-7890-abcd-ef1234567890"
```

### Option B: Environment Variables (Recommended)

```bash
# 1. Set environment variables in your shell profile (~/.bashrc, ~/.zshrc, etc.)
export LC_API_KEY="your-api-key-here"
export LC_ORG_ID="your-org-id-here"

# 2. Source your profile
source ~/.bashrc  # or ~/.zshrc

# 3. Add MCP server using environment variables
claude mcp add \
  --transport http \
  limacharlie \
  https://mcp.limacharlie.io/mcp \
  --header "Authorization: Bearer ${LC_API_KEY}:${LC_ORG_ID}"
```

### Option C: Multiple Organizations

```bash
# Production organization
claude mcp add \
  --transport http \
  lc-prod \
  https://mcp.limacharlie.io/mcp \
  --header "Authorization: Bearer ${LC_API_KEY_PROD}:${LC_ORG_ID_PROD}"

# Development organization  
claude mcp add \
  --transport http \
  lc-dev \
  https://mcp.limacharlie.io/mcp \
  --header "Authorization: Bearer ${LC_API_KEY_DEV}:${LC_ORG_ID_DEV}"

# List all configured MCP servers
claude mcp list
```

## Step 4: Test the Connection

### Basic Connection Test

```bash
# Navigate to this project directory
cd lc-claude-workbench

# Start Claude Code
claude

# In the Claude session, type:
"Test the LimaCharlie MCP connection"

# Expected response: Confirmation that MCP server is working
```

### Verify API Access

Test with real queries:

```bash
# In Claude Code, try these commands:

"List all sensors in my LimaCharlie organization"
# Should return list of sensors

"Check if any sensors are offline"
# Should check sensor status

"Show me detections from the last hour"
# Should query recent detections (if any)
```

## Step 5: Using This Workbench

### Project Context

When you run Claude Code in this directory, it automatically loads `CLAUDE.md`:

```bash
cd lc-claude-workbench
claude

# Claude now has context about:
# - LimaCharlie MCP functions
# - Common pitfalls to avoid
# - Performance optimization tips
# - Example queries and workflows
```

### Example Workflows

Try these example queries from the documentation:

```python
# Get recent detections
"Show me all detections from the last 10 minutes"

# Check specific sensor
"Is sensor abc-123-def online?"

# Generate LCQL query
"Generate an LCQL query to find unsigned PowerShell processes"

# Threat hunting
"Search for processes with base64 encoded commands"
```

## Troubleshooting

### Claude Code Specific Issues

#### Installation Problems

```bash
# NPM permission errors on Mac/Linux
npm install -g @anthropic-ai/claude-code  # May need sudo
# OR use a different npm prefix:
npm config set prefix ~/.npm-global
export PATH=~/.npm-global/bin:$PATH
npm install -g @anthropic-ai/claude-code

# Windows PowerShell execution policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Node version issues (requires Node 18+)
node --version  # Check version
# If too old, update from nodejs.org
```

#### Claude Command Not Working

```bash
# Command not found after installation
which claude  # Mac/Linux
where claude  # Windows

# If not found, check npm bin path
npm bin -g  # Shows where global packages are installed

# Add to PATH if needed (Mac/Linux)
echo 'export PATH="$(npm bin -g):$PATH"' >> ~/.bashrc
source ~/.bashrc

# Windows: Add npm global bin to System PATH
# Usually: %APPDATA%\npm
```

### MCP Connection Issues

```bash
# Check if MCP server is configured
claude mcp list

# Should show:
# limacharlie - https://mcp.limacharlie.io/mcp

# If missing, add it:
claude mcp add \
  --transport http \
  limacharlie \
  https://mcp.limacharlie.io/mcp \
  --header "Authorization: Bearer YOUR_API_KEY:YOUR_ORG_ID"

# Remove and re-add if corrupted
claude mcp remove limacharlie
# Then add again with correct credentials
```

#### MCP Server Not Responding

```bash
# Test direct API access
curl -H "Authorization: Bearer YOUR_API_KEY:YOUR_ORG_ID" \
     https://api.limacharlie.io/v1/sensors

# Common causes:
# 1. Network firewall blocking HTTPS
# 2. Corporate proxy not configured
# 3. API endpoint temporarily down
```

### Authentication Errors

Common issues and fixes:

| Error | Solution |
|-------|----------|
| "Invalid API key" | Check format: `API_KEY:ORG_ID` with colon separator |
| "Permission denied" | Verify API key has required permissions in LimaCharlie |
| "Organization not found" | Confirm Organization ID is correct UUID format |
| "No sensors found" | Check that organization has deployed sensors |
| "401 Unauthorized" | API key may be expired or revoked - create new one |
| "403 Forbidden" | API key lacks required permissions - check in LC console |
| "Wrong key type" | **CRITICAL**: Must be "User-Generated API Key" from org-level REST API page |

#### Testing Authentication

```bash
# Test with minimal query in Claude Code
claude
# Then type: "Test LimaCharlie connection"

# If auth fails, verify credentials format:
# CORRECT: "Bearer abc123:def-456-ghi"
# WRONG: "Bearer abc123 def-456-ghi" (space instead of colon)
# WRONG: "abc123:def-456-ghi" (missing Bearer prefix)
```

### Environment Variable Issues

```bash
# Check if variables are set (Mac/Linux)
echo $LC_API_KEY
echo $LC_ORG_ID

# Windows Command Prompt
echo %LC_API_KEY%
echo %LC_ORG_ID%

# Windows PowerShell
$env:LC_API_KEY
$env:LC_ORG_ID

# Setting variables permanently:

# Mac/Linux - add to ~/.bashrc or ~/.zshrc
export LC_API_KEY="your-api-key-here"
export LC_ORG_ID="your-org-id-here"
# Then reload: source ~/.bashrc

# Windows - Set as System Environment Variable
# Control Panel > System > Advanced > Environment Variables
# Or use PowerShell as Administrator:
[Environment]::SetEnvironmentVariable("LC_API_KEY", "your-key", "User")
[Environment]::SetEnvironmentVariable("LC_ORG_ID", "your-org", "User")
```

### Claude Code Runtime Issues

#### Context Loading Problems

```bash
# CLAUDE.md not loading automatically
# Ensure you're in the project directory:
pwd  # Should show .../lc-claude-workbench
ls CLAUDE.md  # File should exist

# Start Claude from project root:
cd /path/to/lc-claude-workbench
claude  # Now CLAUDE.md loads automatically
```

#### MCP Function Errors

```bash
# "Function not found" errors
# Verify MCP server name matches:
claude mcp list  # Should show "limacharlie"

# In Claude, reference functions correctly:
# CORRECT: "Use limacharlie to check sensor status"
# WRONG: "Use lc to check sensor status" (wrong name)
```

#### Performance Issues

```bash
# Slow responses or timeouts
# 1. Reduce query time ranges (use minutes not hours)
# 2. Add limit parameters to queries
# 3. Check network latency to LimaCharlie API

# Test network speed:
time curl -H "Authorization: Bearer $LC_API_KEY:$LC_ORG_ID" \
     https://api.limacharlie.io/v1/sensors | head -n 1
```

## Security Best Practices

### Never Commit Credentials

```bash
# Add to .gitignore
.env
.env.local
*.key
config.local.json

# Use git-secrets to prevent accidental commits
git secrets --install
git secrets --register-aws  # Detects common credential patterns
```

### Use Secrets Management

For production use:

```bash
# 1Password CLI
export LC_API_KEY=$(op read "op://Security/LimaCharlie/api_key")

# AWS Secrets Manager
export LC_API_KEY=$(aws secretsmanager get-secret-value \
  --secret-id lc-api-key \
  --query SecretString \
  --output text)

# HashiCorp Vault
export LC_API_KEY=$(vault kv get -field=api_key secret/limacharlie)
```

### Rotate Keys Regularly

1. Create new API key in LimaCharlie
2. Update MCP configuration
3. Test new key works
4. Delete old key in LimaCharlie

## Next Steps

Now that you're connected:

1. 📖 Review [CLAUDE.md](CLAUDE.md) for critical usage notes
2. 🔍 Explore [threat hunting queries](examples/threat-hunting-queries.md)
3. 🚨 Practice with the [incident response playbook](examples/incident-response-playbook.md)
4. 📚 Study [LCQL examples](instructions/LCQL_EXAMPLES.md)
5. 🤝 Join the [LimaCharlie Community Forum](https://community.limacharlie.com)

## Getting Help

### LimaCharlie Resources
- **Documentation**: [docs.limacharlie.io](https://docs.limacharlie.io)
- **MCP Server Guide**: [docs.limacharlie.io/docs/mcp-server](https://docs.limacharlie.io/docs/mcp-server)
- **Community Forum**: [community.limacharlie.com](https://community.limacharlie.com)
- **Support**: support@limacharlie.io

### Claude Code Resources
- **Documentation**: [docs.anthropic.com/en/docs/claude-code/overview](https://docs.anthropic.com/en/docs/claude-code/overview)
- **Memory Management**: [docs.anthropic.com/en/docs/claude-code/memory](https://docs.anthropic.com/en/docs/claude-code/memory)
- **MCP Integration**: [docs.anthropic.com/en/docs/claude-code/mcp](https://docs.anthropic.com/en/docs/claude-code/mcp)
- **GitHub Issues**: [github.com/anthropics/claude-code/issues](https://github.com/anthropics/claude-code/issues)

### Project Issues
- **This Project**: [GitHub Issues](https://github.com/digitaldefenseinstitute/lc-claude-workbench/issues)

---

🎉 **You're ready to use Claude Code with LimaCharlie!**

---

**This project is developed and maintained by [Digital Defense Institute](https://digitaldefenseinstitute.com)**