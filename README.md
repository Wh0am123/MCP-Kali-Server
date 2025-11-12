# MCP Kali Server (Forked)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) 
[![CodeQL](https://github.com/canstralian/forked-u-MCP-Kali-Server/actions/workflows/codeql.yml/badge.svg)](https://github.com/canstralian/forked-u-MCP-Kali-Server/security/code-scanning)
[![Architecture](https://img.shields.io/badge/Architecture-MCP%20Server-blue)](https://github.com/canstralian/forked-u-MCP-Kali-Server)
[![Python](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-enabled-blue)](https://www.docker.com/)

**Fork Notice:**  
This repository is a fork of [Wh0am123/MCP-Kali-Server](https://github.com/Wh0am123/MCP-Kali-Server).  
While it inherits the original structure and features, this fork will evolve in a **new direction**, focusing on expanded AI integrations, multi-agent orchestration, and extended security automation.

**Purpose of the Fork:**  
- Modernize and extend AI-assisted penetration testing capabilities.  
- Introduce more flexible MCP server integrations (HuggingFace, GitHub, Notion).  
- Improve automation for CTF challenges, recon, and exploitation workflows.  
- Maintain schema-compliant MCP client/server interaction while enhancing functionality.

---

## 🔍 Use Case

The original MCP functionality allowed AI-driven offensive security testing by:  

- Interacting with AI endpoints like OpenAI, Claude, DeepSeek, or other models.  
- Exposing an API to execute commands on a Kali Linux machine.  
- Automating recon, exploitation, and solving CTF web challenges.  
- Sending custom requests (e.g., curl, nmap, ffuf) and receiving structured outputs.  

**This fork will expand the direction of the project to include:**  

- Enhanced automation for security workflows beyond standard terminal commands.  
- Extended integrations with additional AI models and services.  
- Improved orchestration for multi-agent scenarios and collaborative testing.  
- Streamlined pipelines for penetration testing, CTF solving, and ethical hacking exercises.

---

## 🚀 Features

The original repository included:

- 🧠 **AI Endpoint Integration:** Connect Kali to any MCP client like Claude Desktop or 5ire.  
- 🖥️ **Command Execution API:** Controlled API to execute terminal commands on Kali Linux.  
- 🕸️ **Web Challenge Support:** AI-assisted interaction with web apps, APIs, and capture of flags.  
- 🔐 **Designed for Offensive Security Professionals:** Ideal for red teamers, bug bounty hunters, or CTF players automating common tasks.  

**Future features in this fork will focus on:**  

- Multi-agent orchestration and intelligent task delegation.  
- Integration with cloud-based AI endpoints and model pipelines.  
- Enhanced logging, analytics, and structured output for automation workflows.  
- Additional security tooling, including forensic and analysis utilities.

---

## 🔒 Security & Production Readiness

### Production-Grade Security Features (v0.1.0+)

This release includes comprehensive security hardening for production deployments:

✅ **Implemented Security Controls:**
- **Input Validation**: Comprehensive validation for all parameters (IP, hostname, URL, file paths, ports)
- **Command Injection Protection**: All commands built as lists with strict argument allowlisting
- **Rate Limiting**: Per-IP rate limiting (configurable, default: 10 req/60s)
- **Request Tracking**: Unique request IDs and structured logging
- **Resource Limits**: Command timeouts and output size limits
- **Error Handling**: Generic error messages to prevent information disclosure
- **Secure Temp Files**: Restrictive permissions and guaranteed cleanup
- **Path Traversal Protection**: Validation against directory traversal attacks

⚠️ **Production Deployment Requirements:**

**You MUST implement these additional controls for production:**
- ✓ Deploy behind reverse proxy with authentication (nginx + basic auth/OAuth)
- ✓ Enable TLS/HTTPS with valid certificates
- ✓ Configure firewall rules restricting access to authorized IPs
- ✓ Use VPN or SSH tunneling for remote access
- ✓ Enable centralized logging with secure log storage
- ✓ Regular security audits and penetration testing

**📚 Documentation:**
- [Production Deployment Guide](PRODUCTION_DEPLOYMENT.md) - Complete deployment instructions
- [Security Policy](SECURITY.md) - Detailed security considerations and best practices

### Testing & Quality

- 🧪 **Comprehensive Test Suite**: 80%+ code coverage with security-focused tests
- 🔍 **Automated Security Scanning**: CodeQL, Bandit, and dependency auditing in CI/CD
- ✅ **Type Safety**: Input validation and type checking throughout

---

## 🛠️ Installation

### Prerequisites

- **Operating System:** Kali Linux (recommended) or any Linux distribution
- **Python:** 3.11 or higher
- **Docker:** (optional) for containerized deployment

### Method 1: Quick Start with Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/canstralian/forked-u-MCP-Kali-Server.git
cd forked-u-MCP-Kali-Server

# Build and run with docker-compose
docker-compose up -d

# Or build and run manually
docker build -t mcp-kali-server .
docker run -p 5000:5000 mcp-kali-server
```

### Method 2: Installation from Source

**On the Linux machine (API Server):**

```bash
# Clone the repository
git clone https://github.com/canstralian/forked-u-MCP-Kali-Server.git
cd forked-u-MCP-Kali-Server

# Create and activate virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy and configure environment variables
cp .env.example .env
# Edit .env with your settings

# Run the server
python3 kali_server.py
```

**On your MCP Client (Windows or Linux):**

```bash
python3 /absolute/path/to/mcp_server.py --server http://LINUX_IP:5000
```

### Method 3: Development Installation

```bash
# Clone and setup
git clone https://github.com/canstralian/forked-u-MCP-Kali-Server.git
cd forked-u-MCP-Kali-Server

# Install with development dependencies
pip install -e ".[dev]"

# Run tests
pytest -v

# Run linters
flake8 .
pylint kali_server.py mcp_server.py
```

---

## 🔧 Configuration

### Environment Variables

Create a `.env` file from `.env.example`:

```bash
# API Server Configuration
API_PORT=5000
DEBUG_MODE=0
COMMAND_TIMEOUT=180

# MCP Server Configuration
KALI_SERVER_URL=http://localhost:5000
REQUEST_TIMEOUT=300
```

### Claude Desktop Configuration

Edit `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "kali_mcp": {
      "command": "python3",
      "args": [
        "/absolute/path/to/mcp_server.py",
        "--server",
        "http://LINUX_IP:5000/"
      ]
    }
  }
}
```

### 5ire Desktop Application

Add an MCP with the command:
```bash
python3 /absolute/path/to/mcp_server.py http://LINUX_IP:5000
```

The app will generate the needed configuration automatically.

---

## 📖 Usage

### Available Tools

The MCP server provides access to the following security tools:

- **Network Scanning:** nmap
- **Directory Enumeration:** gobuster, dirb
- **Web Scanning:** nikto, wpscan, sqlmap
- **Password Cracking:** hydra, john
- **SMB Enumeration:** enum4linux
- **Exploitation Framework:** metasploit

### Example Commands

Through your MCP client (like Claude Desktop), you can use natural language:

```
"Run an nmap scan on 192.168.1.1"
"Use gobuster to enumerate directories on http://example.com"
"Check http://example.com for SQL injection vulnerabilities"
"Crack the hashes in /path/to/hashfile using john"
```

### API Endpoints

Direct API usage:

```bash
# Health check
curl http://localhost:5000/health

# Execute nmap scan
curl -X POST http://localhost:5000/api/tools/nmap \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1", "scan_type": "quick"}'

# Run custom command
curl -X POST http://localhost:5000/api/command \
  -H "Content-Type: application/json" \
  -d '{"command": "whoami"}'
```

---

## 🧪 Testing

```bash
# Run all tests
pytest -v

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test file
pytest test_basic.py -v
```

---

## 🔒 Security Considerations

**⚠️ IMPORTANT:** This tool executes system commands and should be deployed with extreme caution.

### Best Practices

1. **Never expose to public internet** without authentication
2. **Use in isolated networks** or behind VPN/firewall
3. **Run with minimal privileges** (not as root)
4. **Review logs regularly** for suspicious activity
5. **Keep dependencies updated** (`pip-audit`, `safety check`)

See [SECURITY.md](SECURITY.md) for comprehensive security guidelines.

---

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Quick Start for Contributors

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests and linters
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

---

## 📋 Project Status

### Current Version: v0.1.0 (Alpha)

- ✅ Core MCP server functionality
- ✅ Security tool integrations
- ✅ Docker support
- ✅ Basic tests and CI/CD
- ✅ Comprehensive documentation

### Roadmap

See [CHANGELOG.md](CHANGELOG.md) for version history and upcoming features.

**Planned Features:**
- Multi-agent orchestration
- Cloud AI endpoint integration
- Enhanced logging and analytics
- Memory and disk forensics tools
- Advanced automation workflows

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🔮 Extended Possibilities

The AI-driven terminal opens up more potential beyond the original features:

- **Memory Forensics (Volatility):** Automate memory analysis tasks like process enumeration, DLL injection checks, and registry extraction from memory dumps.
- **Disk Forensics (SleuthKit):** Automate analysis from disk images, timeline generation, file carving, and hash comparisons.
- **Custom AI Workflows:** The fork will explore automated multi-step AI-driven security workflows, integrating multiple tools in a single pipeline.

---

## 🔒 Branch Protection

This repository uses branch protection rules to maintain code quality and security. The `main` branch is protected with:

- ✅ Prevention of force pushes and deletions
- ✅ Required status checks before merging (Lint and Test, CodeQL Analyze)
- ✅ Pull request reviews required before merging

📄 For detailed information on configuring and maintaining branch protection, see [BRANCH_PROTECTION.md](BRANCH_PROTECTION.md).

---

## ⚠️ Disclaimer

This project is intended **solely for educational and ethical testing purposes**. Any misuse — including unauthorized access, exploitation, or malicious activity — is **strictly prohibited**. 

**You are responsible for:**
- Obtaining proper authorization before testing
- Complying with all applicable laws
- Using the tool ethically and responsibly

The authors assume **no responsibility** for misuse.

---

## 🙏 Acknowledgments

- Original project by [Wh0am123](https://github.com/Wh0am123/MCP-Kali-Server)
- Inspired by [project_astro](https://github.com/whit3rabbit0/project_astro)
- Built with the [Model Context Protocol (MCP)](https://github.com/anthropics/mcp)

---

## 📞 Support

- **Issues:** [GitHub Issues](https://github.com/canstralian/forked-u-MCP-Kali-Server/issues)
- **Discussions:** [GitHub Discussions](https://github.com/canstralian/forked-u-MCP-Kali-Server/discussions)
- **Security:** See [SECURITY.md](SECURITY.md) for vulnerability reporting