# Security Policy

## Overview

The MCP Kali Server is designed for **educational and ethical security testing purposes only**. This document outlines security considerations, best practices, and vulnerability reporting procedures.

## Intended Use

✅ **Authorized Uses:**
- Educational and learning purposes
- Authorized penetration testing with proper permissions
- Security research in controlled environments
- CTF (Capture The Flag) competitions
- Red team exercises with explicit authorization

❌ **Prohibited Uses:**
- Unauthorized access to systems or networks
- Malicious activities or exploitation
- Deployment on production systems without proper security controls
- Any illegal activities

## Production Security Enhancements (v0.1.0+)

The following security features have been implemented for production readiness:

### ✅ Implemented Security Controls

#### 1. **Input Validation & Sanitization**
- ✓ Comprehensive input validation for all parameters
- ✓ Regex-based validation for IPs, hostnames, URLs, file paths, and ports
- ✓ Path traversal attack prevention (`..` detection, restricted directories)
- ✓ Command injection protection through argument allowlisting
- ✓ Special character filtering and validation
- ✓ Maximum length restrictions on all inputs

#### 2. **Command Injection Protection**
- ✓ All commands built as lists (not strings) to prevent shell injection
- ✓ Use of `shlex.split()` for safe argument parsing
- ✓ Per-tool allowlists for additional arguments
- ✓ Validation of all user-provided flags and options
- ✓ `shell=False` enforcement in subprocess execution

#### 3. **Rate Limiting**
- ✓ Per-IP rate limiting (configurable: 10 requests/60 seconds default)
- ✓ Automatic cleanup of expired rate limit entries
- ✓ 429 status code responses when limits exceeded
- ✓ Environment variable configuration for thresholds

#### 4. **Request Tracking & Logging**
- ✓ Unique request IDs for all API calls
- ✓ Request/response timing metrics
- ✓ Source IP logging
- ✓ Structured logging with contextual information
- ✓ Request lifecycle tracking

#### 5. **Resource Limiting**
- ✓ Command execution timeout limits (default: 180 seconds)
- ✓ Maximum output size limits (default: 10MB)
- ✓ Output truncation with warnings when limits exceeded
- ✓ Graceful timeout handling with partial results

#### 6. **Enhanced Error Handling**
- ✓ Generic error messages to prevent information disclosure
- ✓ Detailed logging of errors server-side
- ✓ Try-catch blocks around all endpoint logic
- ✓ Consistent JSON error response format
- ✓ HTTP status code best practices

#### 7. **Secure Temporary File Handling**
- ✓ Use of `tempfile.NamedTemporaryFile` for Metasploit resources
- ✓ Restrictive file permissions (0600) on temp files
- ✓ Guaranteed cleanup in finally blocks
- ✓ Secure temp file prefixes and suffixes

#### 8. **HTTP Security Best Practices**
- ✓ Request body validation (JSON required)
- ✓ Content-Type validation
- ✓ Parameter stripping (whitespace removal)
- ✓ Success/failure flags in all responses

### 📋 Additional Production Requirements

For production deployment, you **MUST** also implement:

- [ ] **Reverse proxy with authentication** (nginx + basic auth/OAuth)
- [ ] **TLS/HTTPS encryption** with valid certificates
- [ ] **Firewall rules** restricting access to authorized IPs only
- [ ] **VPN or SSH tunneling** for remote access
- [ ] **Centralized logging** with secure log storage
- [ ] **Regular security audits** and penetration testing
- [ ] **Incident response plan** and monitoring
- [ ] **Backup and disaster recovery** procedures

**See PRODUCTION_DEPLOYMENT.md for complete deployment guide.**

## Security Considerations

### 1. Authentication & Authorization

⚠️ **Important:** The current version (v0.1.0) does **NOT** include built-in authentication.

**Recommendations:**
- Deploy behind a reverse proxy with authentication (nginx, Apache)
- Use network-level security (firewall rules, VPN)
- Never expose directly to the public internet
- Implement API keys or OAuth if exposing externally
- Consider integration with existing authentication systems

### 2. Input Validation

✅ **Fully Implemented** - All API endpoints validate input to prevent:
- Command injection attacks
- Path traversal vulnerabilities
- Malformed requests causing crashes
- Buffer overflow from oversized inputs

**Current implementation includes:**
- ✓ Comprehensive parameter validation with regex patterns
- ✓ Required field checks with type validation
- ✓ Strict allowlists for command parameters and flags
- ✓ File path validation against directory traversal
- ✓ URL and hostname format validation
- ✓ Port range validation (1-65535)
- ✓ Maximum length restrictions on all inputs
- ✓ Whitespace stripping and normalization

**Additional recommendations:**
- Consider adding WAF (Web Application Firewall) at reverse proxy level
- Implement additional business logic validation as needed
- Regular security testing of validation rules

### 3. Network Security

**Best Practices:**
- Run on isolated network segments
- Use firewall rules to restrict access
- Enable HTTPS/TLS for production deployments
- Consider VPN or SSH tunneling for remote access
- Monitor network traffic for anomalies

### 4. Privilege Management

**Container Deployment:**
- Dockerfile runs as non-root user (mcpuser)
- Minimal system permissions

**Direct Installation:**
- Avoid running as root unless absolutely necessary
- Use dedicated service account with minimal privileges
- Apply principle of least privilege

### 5. Secrets Management

**Never commit sensitive data to version control:**
- API keys
- Passwords
- Tokens
- Private keys
- Database credentials

**Use environment variables or secrets management:**
- Create `.env` file from `.env.example`
- Use Docker secrets for container deployments
- Consider tools like HashiCorp Vault for production
- Rotate credentials regularly

### 6. Command Execution Risks

The server executes system commands, which poses inherent risks:

**Mitigations:**
- Commands execute with timeout limits
- Output is captured and logged
- Subprocess isolation
- Resource limits can be configured

**Additional recommendations:**
- Implement command allowlisting
- Audit all command executions
- Monitor for suspicious patterns
- Set up alerts for dangerous operations

### 7. Logging & Monitoring

**Current logging includes:**
- Request logging
- Error tracking
- Command execution results

**Best practices:**
- Enable detailed logging in production
- Store logs securely
- Implement log rotation
- Set up monitoring and alerting
- Regular security audits of logs

### 8. Dependency Security

**Regular maintenance required:**
```bash
# Check for vulnerable dependencies
pip-audit

# Update dependencies
pip install --upgrade -r requirements.txt

# Security scanning
bandit -r .
```

**CI/CD includes:**
- CodeQL security scanning
- Automated dependency checks

## Deployment Recommendations

### Development Environment
```bash
# Use with local network only
python3 kali_server.py --port 5000
```

### Production Environment
1. **Use Docker with security hardening**
2. **Enable HTTPS/TLS**
3. **Implement authentication**
4. **Set up monitoring and logging**
5. **Regular security updates**
6. **Network isolation**

### Docker Security
```bash
# Run with read-only filesystem where possible
docker run --read-only -v /tmp:/tmp:rw mcp-kali-server

# Limit resources
docker run --memory="512m" --cpus="1.0" mcp-kali-server

# Drop capabilities
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE mcp-kali-server
```

## Vulnerability Reporting

### Reporting Security Issues

If you discover a security vulnerability, please report it responsibly:

1. **Do NOT open a public GitHub issue**
2. Email the maintainer at: [Provide email]
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if available)

### Response Timeline

- **Initial Response:** Within 48 hours
- **Assessment:** Within 1 week
- **Fix Development:** Based on severity
- **Public Disclosure:** After patch is available

### Security Updates

Security patches will be released as soon as possible and announced via:
- GitHub Security Advisories
- CHANGELOG.md
- Release notes

## Security Scanning

### Automated Scans

The project uses:
- **CodeQL:** Static analysis for security vulnerabilities
- **Dependabot:** Automated dependency updates
- **GitHub Actions:** CI/CD security checks

### Manual Security Audits

Recommended tools:
```bash
# Python security linter
bandit -r . -f json -o bandit-report.json

# Check dependencies for known vulnerabilities
pip-audit

# Alternative dependency checker
safety check
```

## Compliance & Legal

### Disclaimer

**THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.**

Users are solely responsible for:
- Obtaining proper authorization before testing
- Compliance with applicable laws and regulations
- Ethical use of the software
- Any consequences of misuse

### Legal Requirements

Before using this software:
1. Obtain written authorization for any testing
2. Understand applicable laws in your jurisdiction
3. Follow responsible disclosure practices
4. Respect privacy and data protection laws

## Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Penetration Testing Execution Standard](http://www.pentest-standard.org/)

## Version

This security policy applies to MCP Kali Server v0.1.0 and later.

Last Updated: 2024
