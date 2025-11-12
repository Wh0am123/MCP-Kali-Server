#!/usr/bin/env python3

# This script connect the MCP AI agent to Kali Linux terminal and API Server.

# some of the code here was inspired from https://github.com/whit3rabbit0/project_astro , be sure to check them out

import argparse
import logging
import os
import re
import shlex
import subprocess
import sys
import tempfile
import traceback
import threading
import uuid
from pathlib import Path
from typing import Dict, Any, List, Optional
from flask import Flask, request, jsonify, g
from functools import wraps
from collections import defaultdict
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Configuration
API_PORT = int(os.environ.get("API_PORT", 5000))
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
COMMAND_TIMEOUT = int(os.environ.get("COMMAND_TIMEOUT", 180))  # 3 minutes default timeout
MAX_OUTPUT_SIZE = int(os.environ.get("MAX_OUTPUT_SIZE", 10 * 1024 * 1024))  # 10MB max output
RATE_LIMIT_REQUESTS = int(os.environ.get("RATE_LIMIT_REQUESTS", 10))  # requests per window
RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW", 60))  # window in seconds

# Only allow execution of these command names via the /api/command endpoint
# Add to this dictionary as needed for safe operations
COMMAND_ALLOWLIST = {
    "list": ["ls", "-l"],
    "stat": ["stat", "/etc/passwd"],
    "uptime": ["uptime"],
    "whoami": ["whoami"],
    "date": ["date"],
    # Add other safe commands here
}

# Validation patterns for common parameters
VALIDATION_PATTERNS = {
    "ip": re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"),
    "hostname": re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"),
    "port": re.compile(r"^[0-9]{1,5}$"),
    "port_range": re.compile(r"^[0-9]{1,5}(-[0-9]{1,5})?(,[0-9]{1,5}(-[0-9]{1,5})?)*$"),
    "url": re.compile(r"^https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+$"),
    "file_path": re.compile(r"^[a-zA-Z0-9\-._/]+$"),
}

app = Flask(__name__)

# Rate limiting storage (in-memory, use Redis for production)
rate_limit_storage = defaultdict(list)


# Input validation helpers
def validate_target(target: str) -> bool:
    """Validate that a target is either a valid IP or hostname."""
    if not target or len(target) > 255:
        return False
    return (VALIDATION_PATTERNS["ip"].match(target) is not None or
            VALIDATION_PATTERNS["hostname"].match(target) is not None)


def validate_url(url: str) -> bool:
    """Validate that a URL is properly formatted and uses http/https."""
    if not url or len(url) > 2048:
        return False
    return VALIDATION_PATTERNS["url"].match(url) is not None


def validate_file_path(path: str, must_exist: bool = False) -> bool:
    """Validate file path to prevent path traversal attacks."""
    if not path or len(path) > 4096:
        return False

    # Check for path traversal attempts
    if ".." in path or path.startswith("/proc") or path.startswith("/sys"):
        return False

    # Allow absolute paths starting with common safe directories
    safe_prefixes = ["/usr/share/wordlists/", "/tmp/", "/home/", "/opt/"]
    if not any(path.startswith(prefix) for prefix in safe_prefixes):
        if not VALIDATION_PATTERNS["file_path"].match(path):
            return False

    if must_exist:
        return Path(path).exists()

    return True


def validate_port_spec(port_spec: str) -> bool:
    """Validate port specification (single port, range, or comma-separated)."""
    if not port_spec:
        return True  # Empty is valid (means default)

    if not VALIDATION_PATTERNS["port_range"].match(port_spec):
        return False

    # Validate individual port numbers
    parts = port_spec.replace("-", ",").split(",")
    for part in parts:
        if part and (int(part) < 1 or int(part) > 65535):
            return False

    return True


def sanitize_additional_args(args: str, allowed_flags: List[str]) -> Optional[List[str]]:
    """
    Sanitize additional arguments by parsing and validating against allowed flags.
    Returns a list of sanitized arguments or None if validation fails.
    """
    if not args:
        return []

    try:
        # Use shlex to properly parse arguments (handles quoted strings)
        parsed_args = shlex.split(args)
    except ValueError as e:
        logger.error(f"Failed to parse additional arguments: {e}")
        return None

    sanitized = []
    i = 0
    while i < len(parsed_args):
        arg = parsed_args[i]

        # Check if argument starts with - or --
        if not arg.startswith("-"):
            logger.warning(f"Additional argument doesn't start with -: {arg}")
            return None

        # Extract flag name (without leading dashes and any = value)
        flag_name = arg.lstrip("-").split("=")[0]

        # Check if flag is in allowed list
        if flag_name not in allowed_flags and arg not in allowed_flags:
            logger.warning(f"Disallowed flag in additional arguments: {arg}")
            return None

        sanitized.append(arg)

        # If flag takes a value and it's not using = syntax, include next arg
        if "=" not in arg and i + 1 < len(parsed_args) and not parsed_args[i + 1].startswith("-"):
            sanitized.append(parsed_args[i + 1])
            i += 1

        i += 1

    return sanitized


def rate_limit(f):
    """Decorator to implement rate limiting per IP address."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.remote_addr or "unknown"
        now = datetime.now()

        # Clean old entries
        rate_limit_storage[client_ip] = [
            timestamp for timestamp in rate_limit_storage[client_ip]
            if now - timestamp < timedelta(seconds=RATE_LIMIT_WINDOW)
        ]

        # Check rate limit
        if len(rate_limit_storage[client_ip]) >= RATE_LIMIT_REQUESTS:
            logger.warning(f"Rate limit exceeded for {client_ip}")
            return jsonify({
                "error": f"Rate limit exceeded. Max {RATE_LIMIT_REQUESTS} requests per {RATE_LIMIT_WINDOW} seconds.",
                "success": False
            }), 429

        # Record this request
        rate_limit_storage[client_ip].append(now)

        return f(*args, **kwargs)

    return decorated_function


@app.before_request
def before_request():
    """Add request ID and logging for each request."""
    g.request_id = str(uuid.uuid4())
    g.start_time = datetime.now()
    logger.info(f"[{g.request_id}] {request.method} {request.path} from {request.remote_addr}")


@app.after_request
def after_request(response):
    """Log request completion."""
    if hasattr(g, 'request_id') and hasattr(g, 'start_time'):
        duration = (datetime.now() - g.start_time).total_seconds()
        logger.info(f"[{g.request_id}] Completed in {duration:.2f}s with status {response.status_code}")
    return response


class CommandExecutor:
    """Class to handle command execution with better timeout management"""

    def __init__(self, command: list, timeout: int = COMMAND_TIMEOUT):
        self.command = command
        self.timeout = timeout
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.stdout_thread = None
        self.stderr_thread = None
        self.return_code = None
        self.timed_out = False

    def _read_stdout(self):
        """Thread function to continuously read stdout"""
        for line in iter(self.process.stdout.readline, ''):
            if len(self.stdout_data) + len(line) > MAX_OUTPUT_SIZE:
                logger.warning(f"Output size limit reached ({MAX_OUTPUT_SIZE} bytes)")
                self.stdout_data += "\n[OUTPUT TRUNCATED - SIZE LIMIT EXCEEDED]\n"
                break
            self.stdout_data += line

    def _read_stderr(self):
        """Thread function to continuously read stderr"""
        for line in iter(self.process.stderr.readline, ''):
            if len(self.stderr_data) + len(line) > MAX_OUTPUT_SIZE:
                logger.warning(f"Error output size limit reached ({MAX_OUTPUT_SIZE} bytes)")
                self.stderr_data += "\n[OUTPUT TRUNCATED - SIZE LIMIT EXCEEDED]\n"
                break
            self.stderr_data += line

    def execute(self) -> Dict[str, Any]:
        """Execute the command and handle timeout gracefully"""
        logger.info(f"Executing command: {self.command}")

        try:
            self.process = subprocess.Popen(
                self.command,
                shell=False,  # Run command directly, not via shell
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1  # Line buffered
            )

            # Start threads to read output continuously
            self.stdout_thread = threading.Thread(target=self._read_stdout)
            self.stderr_thread = threading.Thread(target=self._read_stderr)
            self.stdout_thread.daemon = True
            self.stderr_thread.daemon = True
            self.stdout_thread.start()
            self.stderr_thread.start()

            # Wait for the process to complete or timeout
            try:
                self.return_code = self.process.wait(timeout=self.timeout)
                # Process completed, join the threads
                self.stdout_thread.join()
                self.stderr_thread.join()
            except subprocess.TimeoutExpired:
                # Process timed out but we might have partial results
                self.timed_out = True
                logger.warning(f"Command timed out after {self.timeout} seconds. Terminating process.")

                # Try to terminate gracefully first
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)  # Give it 5 seconds to terminate
                except subprocess.TimeoutExpired:
                    # Force kill if it doesn't terminate
                    logger.warning("Process not responding to termination. Killing.")
                    self.process.kill()

                # Update final output
                self.return_code = -1

            # Always consider it a success if we have output, even with timeout
            success = True if self.timed_out and (self.stdout_data or self.stderr_data) else (self.return_code == 0)

            return {
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "partial_results": self.timed_out and (self.stdout_data or self.stderr_data)
            }

        except Exception as e:
            logger.error(f"Error executing command: {str(e)}")
            logger.error(traceback.format_exc())
            return {
                "stdout": self.stdout_data,
                "stderr": f"Error executing command: {str(e)}\n{self.stderr_data}",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": bool(self.stdout_data or self.stderr_data)
            }


def execute_command(command: List[str]) -> Dict[str, Any]:
    """
    Execute a command and return the result

    Args:
        command: The command to execute, as a list of strings

    Returns:
        A dictionary containing the stdout, stderr, and return code
    """
    if not isinstance(command, list):
        logger.error(f"execute_command called with non-list argument: {type(command)}")
        return {
            "stdout": "",
            "stderr": "Internal error: command must be a list",
            "return_code": -1,
            "success": False,
            "timed_out": False,
            "partial_results": False
        }

    request_id = getattr(g, 'request_id', 'unknown')
    logger.info(f"[{request_id}] Executing command: {' '.join(command)}")

    executor = CommandExecutor(command)
    result = executor.execute()

    logger.info(f"[{request_id}] Command completed: success={result['success']}, "
                f"timed_out={result['timed_out']}, return_code={result['return_code']}")

    return result


@app.route("/api/command", methods=["POST"])
@rate_limit
def generic_command():
    """Execute a safe command from the allowlist provided in the request."""
    try:
        params = request.json
        if not params:
            return jsonify({"error": "Request body must be JSON"}), 400

        action = params.get("action", "")

        if not action or action not in COMMAND_ALLOWLIST:
            logger.warning(f"Command endpoint called with unknown or missing action parameter: {action}")
            return jsonify({
                "error": "Action parameter is required and must be one of: " + ", ".join(COMMAND_ALLOWLIST.keys()),
                "success": False
            }), 400

        command_to_run = COMMAND_ALLOWLIST[action]
        result = execute_command(command_to_run)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in command endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": "Internal server error",
            "success": False
        }), 500


@app.route("/api/tools/nmap", methods=["POST"])
@rate_limit
def nmap():
    """Execute nmap scan with the provided parameters."""
    try:
        params = request.json
        if not params:
            return jsonify({"error": "Request body must be JSON", "success": False}), 400

        target = params.get("target", "").strip()
        scan_type = params.get("scan_type", "-sCV").strip()
        ports = params.get("ports", "").strip()
        additional_args = params.get("additional_args", "-T4 -Pn").strip()

        # Validate target
        if not target:
            return jsonify({"error": "Target parameter is required", "success": False}), 400

        if not validate_target(target):
            return jsonify({"error": "Invalid target format", "success": False}), 400

        # Validate port specification
        if ports and not validate_port_spec(ports):
            return jsonify({"error": "Invalid port specification", "success": False}), 400

        # Allowed nmap flags for additional_args
        allowed_nmap_flags = [
            "sV", "sC", "sS", "sT", "sU", "sA", "sN", "sF", "sX", "sM",
            "T0", "T1", "T2", "T3", "T4", "T5",
            "Pn", "PS", "PA", "PU", "PE", "PP", "PM", "PO",
            "A", "O", "v", "d", "n", "R", "6",
            "open", "version-intensity", "version-all", "script", "script-args",
            "min-rate", "max-rate", "min-hostgroup", "max-hostgroup",
            "min-parallelism", "max-parallelism", "min-rtt-timeout",
            "max-rtt-timeout", "initial-rtt-timeout", "host-timeout",
            "scan-delay", "max-scan-delay", "max-retries"
        ]

        # Build command as list
        command = ["nmap"]

        # Add scan type
        if scan_type:
            # Validate scan type format
            if not scan_type.startswith("-") or len(scan_type) > 20:
                return jsonify({"error": "Invalid scan type format", "success": False}), 400
            command.append(scan_type)

        # Add port specification
        if ports:
            command.extend(["-p", ports])

        # Sanitize and add additional arguments
        if additional_args:
            sanitized_args = sanitize_additional_args(additional_args, allowed_nmap_flags)
            if sanitized_args is None:
                return jsonify({"error": "Invalid or disallowed flags in additional_args", "success": False}), 400
            command.extend(sanitized_args)

        # Add target (always last)
        command.append(target)

        result = execute_command(command)
        return jsonify(result)

    except Exception as e:
        logger.error(f"Error in nmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": "Internal server error", "success": False}), 500


@app.route("/api/tools/gobuster", methods=["POST"])
@rate_limit
def gobuster():
    """Execute gobuster with the provided parameters."""
    try:
        params = request.json
        if not params:
            return jsonify({"error": "Request body must be JSON", "success": False}), 400

        url = params.get("url", "").strip()
        mode = params.get("mode", "dir").strip()
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt").strip()
        additional_args = params.get("additional_args", "").strip()

        # Validate URL
        if not url:
            return jsonify({"error": "URL parameter is required", "success": False}), 400

        if not validate_url(url):
            return jsonify({"error": "Invalid URL format", "success": False}), 400

        # Validate mode
        if mode not in ["dir", "dns", "fuzz", "vhost"]:
            return jsonify({
                "error": f"Invalid mode: {mode}. Must be one of: dir, dns, fuzz, vhost",
                "success": False
            }), 400

        # Validate wordlist path
        if not validate_file_path(wordlist, must_exist=False):
            return jsonify({"error": "Invalid wordlist path", "success": False}), 400

        # Allowed gobuster flags
        allowed_gobuster_flags = [
            "t", "threads", "k", "no-tls-validation", "c", "cookies",
            "x", "extensions", "r", "follow-redirect", "s", "status-codes",
            "b", "status-codes-blacklist", "e", "expanded", "n", "no-status",
            "q", "quiet", "z", "no-progress", "o", "output", "v", "verbose",
            "timeout", "delay", "useragent", "username", "password",
            "proxy", "random-agent"
        ]

        # Build command as list
        command = ["gobuster", mode, "-u", url, "-w", wordlist]

        # Sanitize and add additional arguments
        if additional_args:
            sanitized_args = sanitize_additional_args(additional_args, allowed_gobuster_flags)
            if sanitized_args is None:
                return jsonify({"error": "Invalid or disallowed flags in additional_args", "success": False}), 400
            command.extend(sanitized_args)

        result = execute_command(command)
        return jsonify(result)

    except Exception as e:
        logger.error(f"Error in gobuster endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": "Internal server error", "success": False}), 500


@app.route("/api/tools/dirb", methods=["POST"])
@rate_limit
def dirb():
    """Execute dirb with the provided parameters."""
    try:
        params = request.json
        if not params:
            return jsonify({"error": "Request body must be JSON", "success": False}), 400

        url = params.get("url", "").strip()
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt").strip()
        additional_args = params.get("additional_args", "").strip()

        # Validate URL
        if not url:
            return jsonify({"error": "URL parameter is required", "success": False}), 400

        if not validate_url(url):
            return jsonify({"error": "Invalid URL format", "success": False}), 400

        # Validate wordlist path
        if not validate_file_path(wordlist, must_exist=False):
            return jsonify({"error": "Invalid wordlist path", "success": False}), 400

        # Allowed dirb flags
        allowed_dirb_flags = [
            "a", "useragent", "c", "cookie", "f", "fine-tuning",
            "H", "header", "i", "case-insensitive", "l", "dont-stop",
            "N", "ignore-response", "o", "output", "p", "proxy",
            "P", "proxy-auth", "r", "dont-search-recursively",
            "R", "interactive-recursion", "S", "silent", "t", "dont-force-extensions",
            "u", "username", "v", "show-redirections", "w", "dont-warn",
            "X", "append-each-word", "x", "extensions", "z", "milliseconds"
        ]

        # Build command as list
        command = ["dirb", url, wordlist]

        # Sanitize and add additional arguments
        if additional_args:
            sanitized_args = sanitize_additional_args(additional_args, allowed_dirb_flags)
            if sanitized_args is None:
                return jsonify({"error": "Invalid or disallowed flags in additional_args", "success": False}), 400
            command.extend(sanitized_args)

        result = execute_command(command)
        return jsonify(result)

    except Exception as e:
        logger.error(f"Error in dirb endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": "Internal server error", "success": False}), 500


@app.route("/api/tools/nikto", methods=["POST"])
@rate_limit
def nikto():
    """Execute nikto with the provided parameters."""
    try:
        params = request.json
        if not params:
            return jsonify({"error": "Request body must be JSON", "success": False}), 400

        target = params.get("target", "").strip()
        additional_args = params.get("additional_args", "").strip()

        # Validate target (can be URL or hostname/IP)
        if not target:
            return jsonify({"error": "Target parameter is required", "success": False}), 400

        # Accept either URL or target
        if not (validate_url(target) or validate_target(target)):
            return jsonify({"error": "Invalid target format", "success": False}), 400

        # Allowed nikto flags
        allowed_nikto_flags = [
            "Cgidirs", "config", "Display", "dbcheck", "evasion", "Format",
            "help", "id", "list-plugins", "maxtime", "mutate", "nolookup",
            "nossl", "no404", "output", "Pause", "Plugins", "port",
            "RSAcert", "root", "Save", "ssl", "Tuning", "timeout",
            "update", "useproxy", "until", "url", "vhost", "404code",
            "404string"
        ]

        # Build command as list
        command = ["nikto", "-h", target]

        # Sanitize and add additional arguments
        if additional_args:
            sanitized_args = sanitize_additional_args(additional_args, allowed_nikto_flags)
            if sanitized_args is None:
                return jsonify({"error": "Invalid or disallowed flags in additional_args", "success": False}), 400
            command.extend(sanitized_args)

        result = execute_command(command)
        return jsonify(result)

    except Exception as e:
        logger.error(f"Error in nikto endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": "Internal server error", "success": False}), 500


@app.route("/api/tools/sqlmap", methods=["POST"])
@rate_limit
def sqlmap():
    """Execute sqlmap with the provided parameters."""
    try:
        params = request.json
        if not params:
            return jsonify({"error": "Request body must be JSON", "success": False}), 400

        url = params.get("url", "").strip()
        data = params.get("data", "").strip()
        additional_args = params.get("additional_args", "").strip()

        # Validate URL
        if not url:
            return jsonify({"error": "URL parameter is required", "success": False}), 400

        if not validate_url(url):
            return jsonify({"error": "Invalid URL format", "success": False}), 400

        # Allowed sqlmap flags
        allowed_sqlmap_flags = [
            "batch", "level", "risk", "threads", "technique", "dbms",
            "os", "tamper", "delay", "timeout", "retries", "randomize",
            "safe-url", "safe-post", "safe-req", "safe-freq", "test-filter",
            "test-skip", "skip", "skip-static", "param-exclude", "param-filter",
            "dbms-cred", "format", "dump", "dump-all", "search", "exclude-sysdbs",
            "forms", "crawl", "crawl-exclude", "csrf-token", "csrf-url",
            "headers", "cookies", "referer", "user-agent", "host",
            "encoding", "charset", "web-root", "scope", "test-parameter",
            "skip-urlencode", "csrf-method", "force-ssl", "hpp", "eval"
        ]

        # Build command as list
        command = ["sqlmap", "-u", url, "--batch"]

        # Add POST data if provided
        if data:
            command.extend(["--data", data])

        # Sanitize and add additional arguments
        if additional_args:
            sanitized_args = sanitize_additional_args(additional_args, allowed_sqlmap_flags)
            if sanitized_args is None:
                return jsonify({"error": "Invalid or disallowed flags in additional_args", "success": False}), 400
            command.extend(sanitized_args)

        result = execute_command(command)
        return jsonify(result)

    except Exception as e:
        logger.error(f"Error in sqlmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": "Internal server error", "success": False}), 500


@app.route("/api/tools/metasploit", methods=["POST"])
@rate_limit
def metasploit():
    """Execute metasploit module with the provided parameters."""
    resource_file = None
    try:
        params = request.json
        if not params:
            return jsonify({"error": "Request body must be JSON", "success": False}), 400

        module = params.get("module", "").strip()
        options = params.get("options", {})

        if not module:
            return jsonify({"error": "Module parameter is required", "success": False}), 400

        # Validate module path format (basic validation)
        if not re.match(r"^[a-zA-Z0-9_/.-]+$", module):
            return jsonify({"error": "Invalid module path format", "success": False}), 400

        # Validate options is a dictionary
        if not isinstance(options, dict):
            return jsonify({"error": "Options must be a dictionary", "success": False}), 400

        # Validate option keys and values
        for key, value in options.items():
            if not re.match(r"^[a-zA-Z0-9_]+$", key):
                return jsonify({"error": f"Invalid option key: {key}", "success": False}), 400
            if not isinstance(value, (str, int, float, bool)):
                return jsonify({"error": f"Invalid value type for option: {key}", "success": False}), 400

        # Create an MSF resource script with secure temp file
        resource_content = f"use {module}\n"
        for key, value in options.items():
            # Properly escape values to prevent injection
            escaped_value = str(value).replace('"', '\\"').replace("'", "\\'")
            resource_content += f"set {key} {escaped_value}\n"
        resource_content += "exploit\n"

        # Create secure temporary file with restricted permissions
        with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False, prefix='mcp_msf_') as f:
            resource_file = f.name
            f.write(resource_content)

        # Set restrictive permissions (owner read/write only)
        os.chmod(resource_file, 0o600)

        # Build command as list
        command = ["msfconsole", "-q", "-r", resource_file]
        result = execute_command(command)

        return jsonify(result)

    except Exception as e:
        logger.error(f"Error in metasploit endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": "Internal server error", "success": False}), 500

    finally:
        # Clean up the temporary file in finally block to ensure cleanup
        if resource_file and os.path.exists(resource_file):
            try:
                os.remove(resource_file)
                logger.debug(f"Cleaned up temporary resource file: {resource_file}")
            except Exception as e:
                logger.warning(f"Error removing temporary resource file: {str(e)}")


@app.route("/api/tools/hydra", methods=["POST"])
@rate_limit
def hydra():
    """Execute hydra with the provided parameters."""
    try:
        params = request.json
        if not params:
            return jsonify({"error": "Request body must be JSON", "success": False}), 400

        target = params.get("target", "").strip()
        service = params.get("service", "").strip()
        username = params.get("username", "").strip()
        username_file = params.get("username_file", "").strip()
        password = params.get("password", "").strip()
        password_file = params.get("password_file", "").strip()
        additional_args = params.get("additional_args", "").strip()

        # Validate required parameters
        if not target or not service:
            return jsonify({"error": "Target and service parameters are required", "success": False}), 400

        if not (username or username_file) or not (password or password_file):
            return jsonify({
                "error": "Either username or username_file, and either password or password_file are required",
                "success": False
            }), 400

        # Validate target
        if not validate_target(target):
            return jsonify({"error": "Invalid target format", "success": False}), 400

        # Validate service name (alphanumeric, hyphens, underscores only)
        if not re.match(r"^[a-zA-Z0-9_-]+$", service):
            return jsonify({"error": "Invalid service name", "success": False}), 400

        # Validate file paths if provided
        if username_file and not validate_file_path(username_file, must_exist=False):
            return jsonify({"error": "Invalid username file path", "success": False}), 400

        if password_file and not validate_file_path(password_file, must_exist=False):
            return jsonify({"error": "Invalid password file path", "success": False}), 400

        # Allowed hydra flags
        allowed_hydra_flags = [
            "t", "tasks", "V", "vV", "d", "debug", "v", "verbose",
            "e", "nsr", "f", "F", "M", "o", "output", "b", "binary",
            "w", "wait", "W", "waittime", "c", "custom", "s", "port",
            "S", "ssl", "O", "oldssl", "R", "restore", "I", "ignore-restore",
            "T", "tasks", "m", "module", "L", "userfile", "P", "passfile"
        ]

        # Build command as list
        command = ["hydra", "-t", "4"]

        # Add username or username file
        if username:
            command.extend(["-l", username])
        elif username_file:
            command.extend(["-L", username_file])

        # Add password or password file
        if password:
            command.extend(["-p", password])
        elif password_file:
            command.extend(["-P", password_file])

        # Sanitize and add additional arguments
        if additional_args:
            sanitized_args = sanitize_additional_args(additional_args, allowed_hydra_flags)
            if sanitized_args is None:
                return jsonify({"error": "Invalid or disallowed flags in additional_args", "success": False}), 400
            command.extend(sanitized_args)

        # Add target and service (always last)
        command.extend([target, service])

        result = execute_command(command)
        return jsonify(result)

    except Exception as e:
        logger.error(f"Error in hydra endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": "Internal server error", "success": False}), 500


@app.route("/api/tools/john", methods=["POST"])
@rate_limit
def john():
    """Execute john with the provided parameters."""
    try:
        params = request.json
        if not params:
            return jsonify({"error": "Request body must be JSON", "success": False}), 400

        hash_file = params.get("hash_file", "").strip()
        wordlist = params.get("wordlist", "/usr/share/wordlists/rockyou.txt").strip()
        format_type = params.get("format", "").strip()
        additional_args = params.get("additional_args", "").strip()

        # Validate hash file parameter
        if not hash_file:
            return jsonify({"error": "Hash file parameter is required", "success": False}), 400

        if not validate_file_path(hash_file, must_exist=False):
            return jsonify({"error": "Invalid hash file path", "success": False}), 400

        # Validate wordlist path
        if wordlist and not validate_file_path(wordlist, must_exist=False):
            return jsonify({"error": "Invalid wordlist path", "success": False}), 400

        # Validate format type
        if format_type and not re.match(r"^[a-zA-Z0-9_-]+$", format_type):
            return jsonify({"error": "Invalid format type", "success": False}), 400

        # Allowed john flags
        allowed_john_flags = [
            "show", "test", "users", "groups", "shells", "salts",
            "save-memory", "mem-file-size", "field-separator-char",
            "fix-state-delay", "single", "wordlist", "incremental",
            "external", "stdout", "restore", "session", "status",
            "make-charset", "rules", "encoding", "input-encoding",
            "target-encoding", "pot", "format", "nolog", "crack-status",
            "progress-every", "max-run-time"
        ]

        # Build command as list
        command = ["john"]

        # Add format if specified
        if format_type:
            command.append(f"--format={format_type}")

        # Add wordlist if specified
        if wordlist:
            command.append(f"--wordlist={wordlist}")

        # Sanitize and add additional arguments
        if additional_args:
            sanitized_args = sanitize_additional_args(additional_args, allowed_john_flags)
            if sanitized_args is None:
                return jsonify({"error": "Invalid or disallowed flags in additional_args", "success": False}), 400
            command.extend(sanitized_args)

        # Add hash file (always last)
        command.append(hash_file)

        result = execute_command(command)
        return jsonify(result)

    except Exception as e:
        logger.error(f"Error in john endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": "Internal server error", "success": False}), 500


@app.route("/api/tools/wpscan", methods=["POST"])
@rate_limit
def wpscan():
    """Execute wpscan with the provided parameters."""
    try:
        params = request.json
        if not params:
            return jsonify({"error": "Request body must be JSON", "success": False}), 400

        url = params.get("url", "").strip()
        additional_args = params.get("additional_args", "").strip()

        # Validate URL
        if not url:
            return jsonify({"error": "URL parameter is required", "success": False}), 400

        if not validate_url(url):
            return jsonify({"error": "Invalid URL format", "success": False}), 400

        # Allowed wpscan flags
        allowed_wpscan_flags = [
            "enumerate", "exclude-content-based", "plugins-detection",
            "plugins-version-detection", "themes-detection",
            "themes-version-detection", "timthumbs-detection",
            "config-backups-detection", "db-exports-detection",
            "user-agent", "random-user-agent", "http-auth", "max-threads",
            "throttle", "request-timeout", "connect-timeout", "disable-tls-checks",
            "proxy", "proxy-auth", "cookie-string", "cookie-jar",
            "force", "wp-content-dir", "wp-plugins-dir", "api-token",
            "passwords", "usernames", "multicall-max-passwords",
            "login-uri", "password-attack", "stealthy", "detection-mode",
            "scope", "update", "format", "output", "no-banner", "no-update",
            "verbose", "help", "hh", "version"
        ]

        # Build command as list
        command = ["wpscan", "--url", url]

        # Sanitize and add additional arguments
        if additional_args:
            sanitized_args = sanitize_additional_args(additional_args, allowed_wpscan_flags)
            if sanitized_args is None:
                return jsonify({"error": "Invalid or disallowed flags in additional_args", "success": False}), 400
            command.extend(sanitized_args)

        result = execute_command(command)
        return jsonify(result)

    except Exception as e:
        logger.error(f"Error in wpscan endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": "Internal server error", "success": False}), 500


@app.route("/api/tools/enum4linux", methods=["POST"])
@rate_limit
def enum4linux():
    """Execute enum4linux with the provided parameters."""
    try:
        params = request.json
        if not params:
            return jsonify({"error": "Request body must be JSON", "success": False}), 400

        target = params.get("target", "").strip()
        additional_args = params.get("additional_args", "-a").strip()

        # Validate target
        if not target:
            return jsonify({"error": "Target parameter is required", "success": False}), 400

        if not validate_target(target):
            return jsonify({"error": "Invalid target format", "success": False}), 400

        # Allowed enum4linux flags
        allowed_enum4linux_flags = [
            "U", "M", "S", "P", "G", "d", "r", "o", "i", "w",
            "a", "u", "p", "l", "s", "v", "n", "k"
        ]

        # Build command as list
        command = ["enum4linux"]

        # Sanitize and add additional arguments
        if additional_args:
            sanitized_args = sanitize_additional_args(additional_args, allowed_enum4linux_flags)
            if sanitized_args is None:
                return jsonify({"error": "Invalid or disallowed flags in additional_args", "success": False}), 400
            command.extend(sanitized_args)

        # Add target (always last)
        command.append(target)

        result = execute_command(command)
        return jsonify(result)

    except Exception as e:
        logger.error(f"Error in enum4linux endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": "Internal server error", "success": False}), 500


# Health check endpoint
@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    # Check if essential tools are installed
    essential_tools = ["nmap", "gobuster", "dirb", "nikto", "sqlmap", "hydra", "john", "wpscan"]
    tools_status = {}

    for tool in essential_tools:
        try:
            result = execute_command(["which", tool])
            tools_status[tool] = result["success"]
        except Exception as e:
            logger.error(f"Error checking tool {tool}: {str(e)}")
            tools_status[tool] = False

    all_essential_tools_available = all(tools_status.values())

    return jsonify({
        "status": "healthy",
        "message": "Kali Linux Tools API Server is running",
        "version": "0.1.0",
        "tools_status": tools_status,
        "all_essential_tools_available": all_essential_tools_available,
        "request_id": getattr(g, 'request_id', 'unknown')
    })


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the Kali Linux API Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=API_PORT, help=f"Port for the API server (default: {API_PORT})")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()

    # Set configuration from command line arguments
    if args.debug:
        DEBUG_MODE = True
        os.environ["DEBUG_MODE"] = "1"
        logger.setLevel(logging.DEBUG)

    if args.port != API_PORT:
        API_PORT = args.port

    logger.info(f"Starting Kali Linux Tools API Server on port {API_PORT}")
    app.run(host="0.0.0.0", port=API_PORT, debug=DEBUG_MODE)
