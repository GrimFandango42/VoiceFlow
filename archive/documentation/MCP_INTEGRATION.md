# VoiceFlow MCP Integration

## Overview

VoiceFlow now includes Model Context Protocol (MCP) integration with GitHub Actions, providing automated build, test, and release capabilities through AI-assisted workflows.

## Setup

### 1. GitHub Token Configuration

The system uses your existing GitHub authentication:
- **Active Token**: `github_pat_11BI3VEKI096BS8w9dKMY3_***`
- **Account**: `GrimFandango42`
- **Repository**: `https://github.com/GrimFandango42/voiceflow.git`

### 2. MCP Server Configuration

Located at `.mcp/config.json`:
```json
{
  "servers": {
    "github": {
      "command": "npx",
      "args": ["@anthropic/mcp-server-github"],
      "env": {
        "GITHUB_TOKEN": "${GITHUB_TOKEN}"
      }
    }
  }
}
```

### 3. GitHub Actions Integration

The workflow `.github/workflows/build-release.yml` includes:
- **MCP Integration Job**: Tests and configures MCP GitHub server
- **Automated Builds**: Windows and Unix executables
- **Security Scanning**: Bandit and Safety dependency checks
- **Release Management**: Automated release creation with artifacts

## Available MCP Skills

### Repository Management
- Create and manage releases
- Update repository settings
- Manage branches and tags

### Issue & PR Automation
- Create issues from build failures
- Auto-assign reviewers
- Update PR status based on builds

### Workflow Control
- Trigger builds via MCP commands
- Monitor workflow status
- Restart failed jobs

### Release Management
- Create releases with proper artifacts
- Generate release notes
- Tag versions automatically

## Usage Examples

### Trigger a Release Build
```bash
gh workflow run build-release.yml -f create_release=true -f build_type=release
```

### Check MCP Integration Status
The workflow automatically tests MCP integration and creates reports in the artifacts.

### Manual MCP Configuration
```bash
# Install MCP tools
npm install -g @modelcontextprotocol/cli
npm install -g @anthropic/mcp-server-github

# Configure with your token
export GITHUB_TOKEN="your_token_here"
npx @anthropic/mcp-server-github --test
```

## Workflow Triggers

### Automatic
- **Tag Push**: `git tag v3.1.0 && git push origin v3.1.0`
- **Main Branch Push**: Builds and tests on main branch changes
- **Pull Requests**: Validates builds on PR creation

### Manual
- **Workflow Dispatch**: Trigger builds manually via GitHub UI or CLI
- **Release Creation**: Force release creation with custom parameters

## Security

### Token Permissions
- Repository: `write`
- Issues: `write`
- Pull Requests: `write`
- Actions: `write`
- Releases: `write`

### Best Practices
- Tokens are stored as GitHub secrets
- MCP server runs in isolated environment
- All interactions are logged and auditable

## Monitoring

### Build Status
Monitor builds at: https://github.com/GrimFandango42/voiceflow/actions

### MCP Reports
Each workflow run generates MCP integration reports available in artifacts.

### Notifications
- Workflow failures trigger notifications
- Release creation sends updates
- Security scan results are reported

## Troubleshooting

### Token Issues
```bash
# Check current token status
gh auth status

# Refresh token if needed
gh auth refresh
```

### MCP Server Issues
```bash
# Test MCP GitHub server
timeout 10s npx @anthropic/mcp-server-github --test

# Check MCP configuration
cat .mcp/config.json
```

### Workflow Failures
1. Check workflow logs in GitHub Actions
2. Review MCP integration report in artifacts
3. Verify token permissions and expiration

## Integration Benefits

### For Development
- Automated testing on every change
- Consistent build environments
- Security validation before merge

### For Releases
- Automated artifact generation
- Cross-platform builds
- Security reports included

### For Maintenance
- Dependency updates tracking
- Vulnerability monitoring
- Performance regression detection

## Future Enhancements

### Planned Features
- Auto-update dependencies via MCP
- Intelligent issue triage
- Performance benchmarking automation
- Multi-environment testing

### Integration Opportunities
- Slack/Discord notifications
- Jira integration for project management
- Documentation auto-generation
- Code quality metrics tracking