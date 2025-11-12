# Production Deployment Guide

## Overview

This guide provides comprehensive instructions for deploying the MCP Kali Server to a production environment with proper security hardening, monitoring, and best practices.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Security Requirements](#security-requirements)
3. [Infrastructure Setup](#infrastructure-setup)
4. [Configuration](#configuration)
5. [Deployment Options](#deployment-options)
6. [Reverse Proxy Configuration](#reverse-proxy-configuration)
7. [Monitoring and Logging](#monitoring-and-logging)
8. [Backup and Recovery](#backup-and-recovery)
9. [Maintenance](#maintenance)
10. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements

- **Operating System**: Kali Linux 2023.1+ or Debian-based Linux
- **Python**: 3.11 or 3.12
- **Memory**: Minimum 2GB RAM, recommended 4GB+
- **Storage**: Minimum 10GB free space
- **Network**: Dedicated network segment (isolated from public internet)

### Required Software

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python and dependencies
sudo apt install python3.11 python3.11-venv python3-pip

# Install security tools (if not already present on Kali)
sudo apt install nmap gobuster dirb nikto sqlmap hydra john wpscan enum4linux
```

---

## Security Requirements

### 🔒 Critical Security Checklist

Before deploying to production, ensure:

- [ ] **No Direct Internet Exposure**: Server should NOT be directly accessible from the internet
- [ ] **Reverse Proxy with Authentication**: Deploy behind nginx/Apache with authentication
- [ ] **TLS/HTTPS Enabled**: All traffic encrypted with valid certificates
- [ ] **Firewall Rules**: Strict firewall rules allowing only authorized IPs
- [ ] **VPN/SSH Tunnel**: Access only through VPN or SSH tunnel
- [ ] **Non-Root User**: Run application as non-privileged user
- [ ] **Environment Variables**: All secrets in environment variables (never hardcoded)
- [ ] **Rate Limiting**: Configured appropriately for your use case
- [ ] **Logging Enabled**: Centralized logging with retention policies
- [ ] **Security Scanning**: Regular vulnerability scanning enabled
- [ ] **Backup Strategy**: Automated backups configured
- [ ] **Incident Response Plan**: Team knows how to respond to security incidents

### Network Security Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Internet                              │
└───────────────────┬─────────────────────────────────────┘
                    │
                    ▼
         ┌──────────────────────┐
         │   VPN Gateway        │
         │   (WireGuard/        │
         │    OpenVPN)          │
         └──────────┬───────────┘
                    │
                    ▼
         ┌──────────────────────┐
         │  Reverse Proxy       │
         │  (Nginx + Auth)      │
         │  - TLS Termination   │
         │  - Rate Limiting     │
         │  - WAF               │
         └──────────┬───────────┘
                    │
                    ▼
         ┌──────────────────────┐
         │  MCP Kali Server     │
         │  (Internal Network)  │
         │  Port: 5000          │
         └──────────────────────┘
                    │
                    ▼
         ┌──────────────────────┐
         │  Security Tools      │
         │  (Kali Linux)        │
         └──────────────────────┘
```

---

## Infrastructure Setup

### 1. Create Dedicated User

```bash
# Create non-root user for running the application
sudo useradd -m -s /bin/bash mcpuser
sudo usermod -aG sudo mcpuser  # Optional: only if needed

# Switch to the user
sudo su - mcpuser
```

### 2. Prepare Application Directory

```bash
# Create application directory
mkdir -p /opt/mcp-kali-server
cd /opt/mcp-kali-server

# Clone repository (or copy files)
git clone https://github.com/canstralian/forked-u-MCP-Kali-Server.git .

# Create Python virtual environment
python3.11 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Configure Environment Variables

```bash
# Copy environment template
cp .env.example .env

# Edit configuration
nano .env
```

**Production `.env` Configuration:**

```bash
# API Server Configuration
API_PORT=5000
DEBUG_MODE=0  # MUST be 0 in production

# Command Execution Settings
COMMAND_TIMEOUT=300  # 5 minutes
MAX_OUTPUT_SIZE=10485760  # 10MB

# Rate Limiting (adjust based on expected usage)
RATE_LIMIT_REQUESTS=20  # requests per window
RATE_LIMIT_WINDOW=60    # 60 seconds

# MCP Server Configuration
KALI_SERVER_URL=http://localhost:5000
REQUEST_TIMEOUT=600  # 10 minutes for long-running tools
```

**Set secure file permissions:**

```bash
chmod 600 .env
chown mcpuser:mcpuser .env
```

---

## Deployment Options

### Option 1: Systemd Service (Recommended)

Create a systemd service file:

```bash
sudo nano /etc/systemd/system/mcp-kali-server.service
```

**Service File Content:**

```ini
[Unit]
Description=MCP Kali Security Tools Server
After=network.target

[Service]
Type=simple
User=mcpuser
Group=mcpuser
WorkingDirectory=/opt/mcp-kali-server
Environment="PATH=/opt/mcp-kali-server/venv/bin"
EnvironmentFile=/opt/mcp-kali-server/.env

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/mcp-kali-server
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true

# Start command using gunicorn
ExecStart=/opt/mcp-kali-server/venv/bin/gunicorn \
    --bind 127.0.0.1:5000 \
    --workers 2 \
    --timeout 600 \
    --access-logfile /var/log/mcp-kali-server/access.log \
    --error-logfile /var/log/mcp-kali-server/error.log \
    --log-level info \
    kali_server:app

Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Create log directory:**

```bash
sudo mkdir -p /var/log/mcp-kali-server
sudo chown mcpuser:mcpuser /var/log/mcp-kali-server
sudo chmod 755 /var/log/mcp-kali-server
```

**Enable and start service:**

```bash
sudo systemctl daemon-reload
sudo systemctl enable mcp-kali-server
sudo systemctl start mcp-kali-server
sudo systemctl status mcp-kali-server
```

### Option 2: Docker Deployment

Using the provided Dockerfile:

```bash
# Build image
docker build -t mcp-kali-server:latest .

# Run with docker-compose (recommended)
docker-compose up -d

# Or run directly
docker run -d \
    --name mcp-kali-server \
    -p 127.0.0.1:5000:5000 \
    --env-file .env \
    --restart unless-stopped \
    --security-opt no-new-privileges:true \
    --cap-drop ALL \
    --cap-add NET_RAW \
    --cap-add NET_ADMIN \
    mcp-kali-server:latest
```

**Production docker-compose.yml:**

```yaml
version: '3.8'

services:
  mcp-kali-server:
    build: .
    ports:
      - "127.0.0.1:5000:5000"
    env_file:
      - .env
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_RAW
      - NET_ADMIN
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 512M
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    volumes:
      - /var/log/mcp-kali-server:/app/logs
```

---

## Reverse Proxy Configuration

### Nginx Configuration

**Install Nginx:**

```bash
sudo apt install nginx certbot python3-certbot-nginx
```

**Create site configuration:**

```bash
sudo nano /etc/nginx/sites-available/mcp-kali-server
```

**Configuration:**

```nginx
# Rate limiting zone
limit_req_zone $binary_remote_addr zone=mcp_limit:10m rate=10r/s;

# Upstream backend
upstream mcp_backend {
    server 127.0.0.1:5000 fail_timeout=30s;
}

server {
    listen 443 ssl http2;
    server_name kali-mcp.yourdomain.com;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/kali-mcp.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/kali-mcp.yourdomain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer" always;

    # Access control
    allow 10.0.0.0/8;      # Private network
    allow 192.168.0.0/16;  # Private network
    deny all;

    # Basic authentication
    auth_basic "MCP Kali Server - Authorized Access Only";
    auth_basic_user_file /etc/nginx/.htpasswd;

    # Logging
    access_log /var/log/nginx/mcp-kali-access.log;
    error_log /var/log/nginx/mcp-kali-error.log;

    # Rate limiting
    limit_req zone=mcp_limit burst=20 nodelay;

    location / {
        proxy_pass http://mcp_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts for long-running scans
        proxy_connect_timeout 600s;
        proxy_send_timeout 600s;
        proxy_read_timeout 600s;

        # Buffer settings
        proxy_buffering off;
        proxy_request_buffering off;
    }

    # Health check endpoint (no auth required)
    location /health {
        auth_basic off;
        proxy_pass http://mcp_backend;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name kali-mcp.yourdomain.com;
    return 301 https://$server_name$request_uri;
}
```

**Create htpasswd file:**

```bash
sudo apt install apache2-utils
sudo htpasswd -c /etc/nginx/.htpasswd admin
# Enter password when prompted
```

**Enable site:**

```bash
sudo ln -s /etc/nginx/sites-available/mcp-kali-server /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

**Get SSL certificate:**

```bash
sudo certbot --nginx -d kali-mcp.yourdomain.com
```

---

## Monitoring and Logging

### Application Logs

```bash
# View real-time logs
sudo journalctl -u mcp-kali-server -f

# View recent logs
sudo journalctl -u mcp-kali-server --since "1 hour ago"

# Search logs
sudo journalctl -u mcp-kali-server | grep ERROR
```

### Log Rotation

Create `/etc/logrotate.d/mcp-kali-server`:

```
/var/log/mcp-kali-server/*.log {
    daily
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 mcpuser mcpuser
    sharedscripts
    postrotate
        systemctl reload mcp-kali-server
    endscript
}
```

### Health Monitoring Script

```bash
#!/bin/bash
# /opt/mcp-kali-server/health-check.sh

HEALTH_URL="http://localhost:5000/health"
ALERT_EMAIL="admin@yourdomain.com"

response=$(curl -s -o /dev/null -w "%{http_code}" $HEALTH_URL)

if [ $response -ne 200 ]; then
    echo "MCP Kali Server health check failed! Status: $response" | \
        mail -s "ALERT: MCP Kali Server Down" $ALERT_EMAIL
    exit 1
fi

exit 0
```

**Add to crontab:**

```bash
# Check health every 5 minutes
*/5 * * * * /opt/mcp-kali-server/health-check.sh
```

---

## Firewall Configuration

### UFW (Uncomplicated Firewall)

```bash
# Install UFW
sudo apt install ufw

# Default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH (adjust port if needed)
sudo ufw allow 22/tcp

# Allow HTTPS (for reverse proxy)
sudo ufw allow 443/tcp

# Allow from specific trusted networks only
sudo ufw allow from 192.168.1.0/24 to any port 443

# Enable firewall
sudo ufw enable
sudo ufw status verbose
```

---

## Backup and Recovery

### Backup Script

```bash
#!/bin/bash
# /opt/mcp-kali-server/backup.sh

BACKUP_DIR="/backups/mcp-kali-server"
DATE=$(date +%Y%m%d_%H%M%S)
APP_DIR="/opt/mcp-kali-server"

mkdir -p $BACKUP_DIR

# Backup configuration
tar -czf "$BACKUP_DIR/config_$DATE.tar.gz" \
    "$APP_DIR/.env" \
    "$APP_DIR/requirements.txt" \
    "$APP_DIR/pyproject.toml"

# Backup logs (last 7 days)
tar -czf "$BACKUP_DIR/logs_$DATE.tar.gz" \
    /var/log/mcp-kali-server/

# Remove backups older than 30 days
find $BACKUP_DIR -name "*.tar.gz" -mtime +30 -delete

echo "Backup completed: $DATE"
```

**Schedule daily backups:**

```bash
# Add to crontab
0 2 * * * /opt/mcp-kali-server/backup.sh
```

---

## Maintenance

### Regular Updates

```bash
# Update application
cd /opt/mcp-kali-server
git pull
source venv/bin/activate
pip install -r requirements.txt --upgrade

# Restart service
sudo systemctl restart mcp-kali-server
```

### Security Audits

```bash
# Run dependency vulnerability scan
pip-audit

# Run bandit security scan
bandit -r kali_server.py mcp_server.py

# Check for outdated packages
pip list --outdated
```

### Performance Monitoring

```bash
# Check service status
sudo systemctl status mcp-kali-server

# Monitor resource usage
htop
# Filter by 'mcpuser'

# Check active connections
sudo netstat -tuln | grep :5000
```

---

## Troubleshooting

### Service Won't Start

```bash
# Check service status
sudo systemctl status mcp-kali-server

# View logs
sudo journalctl -u mcp-kali-server -n 50

# Check if port is already in use
sudo lsof -i :5000

# Verify permissions
ls -la /opt/mcp-kali-server
ls -la /var/log/mcp-kali-server
```

### High Memory Usage

```bash
# Check memory usage
free -h

# Reduce worker count in gunicorn
# Edit: /etc/systemd/system/mcp-kali-server.service
# Change: --workers 2  to  --workers 1

# Reduce max output size
# Edit: .env
# Change: MAX_OUTPUT_SIZE=10485760  to  MAX_OUTPUT_SIZE=5242880
```

### Rate Limiting Issues

```bash
# Adjust rate limits in .env
RATE_LIMIT_REQUESTS=50  # Increase if needed
RATE_LIMIT_WINDOW=60

# Restart service
sudo systemctl restart mcp-kali-server
```

### Connection Timeouts

```bash
# Increase command timeout in .env
COMMAND_TIMEOUT=600  # 10 minutes

# Increase nginx proxy timeouts (see nginx config above)

# Restart both services
sudo systemctl restart mcp-kali-server
sudo systemctl reload nginx
```

---

## Security Incident Response

### If Compromise is Suspected

1. **Immediately isolate the server:**
   ```bash
   sudo ufw enable
   sudo ufw deny incoming
   ```

2. **Stop the service:**
   ```bash
   sudo systemctl stop mcp-kali-server
   ```

3. **Preserve logs:**
   ```bash
   sudo cp -r /var/log/mcp-kali-server /tmp/incident-logs
   sudo journalctl -u mcp-kali-server > /tmp/incident-journal.log
   ```

4. **Review access logs:**
   ```bash
   sudo tail -n 500 /var/log/nginx/mcp-kali-access.log
   ```

5. **Contact security team and follow incident response procedures**

---

## Compliance Considerations

### Logging Requirements

- All command executions are logged with request IDs
- Client IP addresses are logged
- Timestamp for all operations
- Log retention: minimum 90 days recommended

### Access Control

- All access requires authentication
- Role-based access control recommended
- Regular access reviews
- Principle of least privilege

### Audit Trail

- Enable audit logging for configuration changes
- Track all administrative actions
- Periodic security reviews

---

## Support and Resources

- **GitHub Issues**: https://github.com/canstralian/forked-u-MCP-Kali-Server/issues
- **Security Policy**: See SECURITY.md
- **Contributing**: See CONTRIBUTING.md

---

## Version History

- **v0.1.0** - Initial production-ready release with comprehensive security hardening

---

**⚠️ WARNING**: This server executes potentially dangerous security tools. Only deploy in authorized environments with proper controls. Misuse may violate laws and regulations.
