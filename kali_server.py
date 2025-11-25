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
import threading
import traceback
from pathlib import Path
from typing import Dict, Any, List, Optional

from flask import Flask, request, jsonify

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

# Valid scan types for different tools
VALID_NMAP_SCAN_TYPES = {"-sS", "-sT", "-sU", "-sV", "-sC", "-sCV", "-sA", "-sN", "-sF", "-sX", "-A"}
VALID_GOBUSTER_MODES = {"dir", "dns", "fuzz", "vhost"}
VALID_HYDRA_SERVICES = {"ssh", "ftp", "telnet", "http-get", "http-post-form", "mysql", "smb", "rdp"}

app = Flask(__name__)


class CommandExecutor:
    """Class to handle command execution with better timeout management"""

    def __init__(self, command: List[str], timeout: int = COMMAND_TIMEOUT):
        """
        Initialize CommandExecutor with a command list.

        Args:
            command: Command as a list of strings (e.g., ["ls", "-la", "/tmp"])
            timeout: Timeout in seconds
        """
        if not isinstance(command, list):
            raise ValueError(f"Command must be a list, got {type(command)}")
        if not command:
            raise ValueError("Command list cannot be empty")

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
        try:
            for line in iter(self.process.stdout.readline, ''):
                self.stdout_data += line
        except Exception as e:
            logger.error(f"Error reading stdout: {e}")

    def _read_stderr(self):
        """Thread function to continuously read stderr"""
        try:
            for line in iter(self.process.stderr.readline, ''):
                self.stderr_data += line
        except Exception as e:
            logger.error(f"Error reading stderr: {e}")

    def execute(self) -> Dict[str, Any]:
        """Execute the command and handle timeout gracefully"""
        logger.info(f"Executing command: {' '.join(self.command)}")

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
                self.stdout_thread.join(timeout=2)
                self.stderr_thread.join(timeout=2)
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
                    self.process.wait()

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
                "partial_results": self.timed_out and bool(self.stdout_data or self.stderr_data)
            }

        except FileNotFoundError as e:
            logger.error(f"Command not found: {self.command[0]}")
            return {
                "stdout": "",
                "stderr": f"Command not found: {self.command[0]}. Please ensure it is installed.",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": False
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
    executor = CommandExecutor(command)
    return executor.execute()


def validate_target(target: str) -> bool:
    """
    Validate that a target (IP/hostname/URL) looks reasonable.
    This is basic validation - more comprehensive checks recommended.

    Args:
        target: The target string to validate

    Returns:
        True if target appears valid
    """
    if not target or len(target) > 500:
        return False

    # Allow IP addresses, hostnames, and URLs
    # This is permissive but prevents obvious injection attempts
    invalid_chars = [';', '&', '|', '`', '$', '\n', '\r']
    return not any(char in target for char in invalid_chars)


def validate_file_path(path: str, must_exist: bool = True) -> bool:
    """
    Validate a file path to prevent directory traversal and injection.

    Args:
        path: The file path to validate
        must_exist: Whether the file must exist

    Returns:
        True if path appears valid
    """
    if not path or len(path) > 1000:
        return False

    # Check for directory traversal attempts
    if '..' in path:
        logger.warning(f"Path contains '..': {path}")
        return False

    # Check for null bytes and other injection characters
    invalid_chars = ['\0', ';', '&', '|', '`', '$', '\n', '\r']
    if any(char in path for char in invalid_chars):
        logger.warning(f"Path contains invalid characters: {path}")
        return False

    # If must exist, verify the file exists
    if must_exist and not Path(path).exists():
        logger.warning(f"Path does not exist: {path}")
        return False

    return True


def sanitize_additional_args(args: str, tool_name: str) -> List[str]:
    """
    Safely parse additional arguments using shlex.
    This prevents command injection through additional_args.

    Args:
        args: Additional arguments string
        tool_name: Name of the tool (for logging)

    Returns:
        List of sanitized arguments
    """
    if not args:
        return []

    try:
        # Use shlex to safely parse the arguments
        parsed = shlex.split(args)

        # Additional validation: check for suspicious patterns
        for arg in parsed:
            # Block common injection patterns
            if any(char in arg for char in [';', '&', '|', '`', '$(']):
                logger.warning(f"Suspicious argument detected for {tool_name}: {arg}")
                return []

        return parsed
    except ValueError as e:
        logger.error(f"Failed to parse additional arguments for {tool_name}: {e}")
        return []


def create_error_response(message: str, status_code: int = 400) -> tuple:
    """
    Create a standardized error response.

    Args:
        message: Error message
        status_code: HTTP status code

    Returns:
        Tuple of (jsonify response, status code)
    """
    return jsonify({"error": message, "success": False}), status_code


def create_success_response(result: Dict[str, Any]) -> tuple:
    """
    Create a standardized success response.

    Args:
        result: Result dictionary from command execution

    Returns:
        Tuple of (jsonify response, status code)
    """
    return jsonify(result), 200


@app.route("/api/command", methods=["POST"])
def generic_command():
    """Execute a safe command from the allowlist provided in the request."""
    try:
        params = request.json
        if not params:
            return create_error_response("Request body must be valid JSON")

        action = params.get("action", "")

        if not action or action not in COMMAND_ALLOWLIST:
            logger.warning(f"Command endpoint called with unknown or missing action parameter: {action}")
            return create_error_response(
                f"Action parameter is required and must be one of: {', '.join(COMMAND_ALLOWLIST.keys())}"
            )

        command_to_run = COMMAND_ALLOWLIST[action]
        result = execute_command(command_to_run)
        return create_success_response(result)

    except Exception as e:
        logger.error(f"Error in command endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return create_error_response(f"Server error: {str(e)}", 500)


@app.route("/api/tools/nmap", methods=["POST"])
def nmap():
    """Execute nmap scan with the provided parameters."""
    try:
        params = request.json
        if not params:
            return create_error_response("Request body must be valid JSON")

        target = params.get("target", "")
        scan_type = params.get("scan_type", "-sCV")
        ports = params.get("ports", "")
        additional_args = params.get("additional_args", "-T4 -Pn")

        # Validate target
        if not target:
            logger.warning("Nmap called without target parameter")
            return create_error_response("Target parameter is required")

        if not validate_target(target):
            logger.warning(f"Invalid target for nmap: {target}")
            return create_error_response("Invalid target format")

        # Validate scan type
        if scan_type not in VALID_NMAP_SCAN_TYPES:
            logger.warning(f"Invalid nmap scan type: {scan_type}")
            return create_error_response(
                f"Invalid scan_type. Must be one of: {', '.join(VALID_NMAP_SCAN_TYPES)}"
            )

        # Build command as a list (safe from injection)
        command = ["nmap", scan_type]

        # Add ports if specified
        if ports:
            # Validate ports format (numbers, commas, hyphens only)
            if not re.match(r'^[\d,\-]+$', ports):
                return create_error_response("Invalid ports format")
            command.extend(["-p", ports])

        # Add additional args safely
        additional_args_list = sanitize_additional_args(additional_args, "nmap")
        if additional_args and not additional_args_list:
            return create_error_response("Invalid additional arguments")
        command.extend(additional_args_list)

        # Add target last
        command.append(target)

        result = execute_command(command)
        return create_success_response(result)

    except Exception as e:
        logger.error(f"Error in nmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return create_error_response(f"Server error: {str(e)}", 500)


@app.route("/api/tools/gobuster", methods=["POST"])
def gobuster():
    """Execute gobuster with the provided parameters."""
    try:
        params = request.json
        if not params:
            return create_error_response("Request body must be valid JSON")

        url = params.get("url", "")
        mode = params.get("mode", "dir")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")

        # Validate URL
        if not url:
            logger.warning("Gobuster called without URL parameter")
            return create_error_response("URL parameter is required")

        if not validate_target(url):
            return create_error_response("Invalid URL format")

        # Validate mode
        if mode not in VALID_GOBUSTER_MODES:
            logger.warning(f"Invalid gobuster mode: {mode}")
            return create_error_response(
                f"Invalid mode: {mode}. Must be one of: {', '.join(VALID_GOBUSTER_MODES)}"
            )

        # Validate wordlist path
        if not validate_file_path(wordlist, must_exist=True):
            return create_error_response("Invalid or non-existent wordlist path")

        # Build command as a list
        command = ["gobuster", mode, "-u", url, "-w", wordlist]

        # Add additional args safely
        additional_args_list = sanitize_additional_args(additional_args, "gobuster")
        if additional_args and not additional_args_list:
            return create_error_response("Invalid additional arguments")
        command.extend(additional_args_list)

        result = execute_command(command)
        return create_success_response(result)

    except Exception as e:
        logger.error(f"Error in gobuster endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return create_error_response(f"Server error: {str(e)}", 500)


@app.route("/api/tools/dirb", methods=["POST"])
def dirb():
    """Execute dirb with the provided parameters."""
    try:
        params = request.json
        if not params:
            return create_error_response("Request body must be valid JSON")

        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")

        # Validate URL
        if not url:
            logger.warning("Dirb called without URL parameter")
            return create_error_response("URL parameter is required")

        if not validate_target(url):
            return create_error_response("Invalid URL format")

        # Validate wordlist path
        if not validate_file_path(wordlist, must_exist=True):
            return create_error_response("Invalid or non-existent wordlist path")

        # Build command as a list
        command = ["dirb", url, wordlist]

        # Add additional args safely
        additional_args_list = sanitize_additional_args(additional_args, "dirb")
        if additional_args and not additional_args_list:
            return create_error_response("Invalid additional arguments")
        command.extend(additional_args_list)

        result = execute_command(command)
        return create_success_response(result)

    except Exception as e:
        logger.error(f"Error in dirb endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return create_error_response(f"Server error: {str(e)}", 500)


@app.route("/api/tools/nikto", methods=["POST"])
def nikto():
    """Execute nikto with the provided parameters."""
    try:
        params = request.json
        if not params:
            return create_error_response("Request body must be valid JSON")

        target = params.get("target", "")
        additional_args = params.get("additional_args", "")

        # Validate target
        if not target:
            logger.warning("Nikto called without target parameter")
            return create_error_response("Target parameter is required")

        if not validate_target(target):
            return create_error_response("Invalid target format")

        # Build command as a list
        command = ["nikto", "-h", target]

        # Add additional args safely
        additional_args_list = sanitize_additional_args(additional_args, "nikto")
        if additional_args and not additional_args_list:
            return create_error_response("Invalid additional arguments")
        command.extend(additional_args_list)

        result = execute_command(command)
        return create_success_response(result)

    except Exception as e:
        logger.error(f"Error in nikto endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return create_error_response(f"Server error: {str(e)}", 500)


@app.route("/api/tools/sqlmap", methods=["POST"])
def sqlmap():
    """Execute sqlmap with the provided parameters."""
    try:
        params = request.json
        if not params:
            return create_error_response("Request body must be valid JSON")

        url = params.get("url", "")
        data = params.get("data", "")
        additional_args = params.get("additional_args", "")

        # Validate URL
        if not url:
            logger.warning("SQLMap called without URL parameter")
            return create_error_response("URL parameter is required")

        if not validate_target(url):
            return create_error_response("Invalid URL format")

        # Build command as a list
        command = ["sqlmap", "-u", url, "--batch"]

        # Add data if provided
        if data:
            # Validate data doesn't contain obvious injection attempts
            if any(char in data for char in [';', '&', '|', '`']):
                return create_error_response("Invalid characters in data parameter")
            command.extend(["--data", data])

        # Add additional args safely
        additional_args_list = sanitize_additional_args(additional_args, "sqlmap")
        if additional_args and not additional_args_list:
            return create_error_response("Invalid additional arguments")
        command.extend(additional_args_list)

        result = execute_command(command)
        return create_success_response(result)

    except Exception as e:
        logger.error(f"Error in sqlmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return create_error_response(f"Server error: {str(e)}", 500)


@app.route("/api/tools/metasploit", methods=["POST"])
def metasploit():
    """Execute metasploit module with the provided parameters."""
    try:
        params = request.json
        if not params:
            return create_error_response("Request body must be valid JSON")

        module = params.get("module", "")
        options = params.get("options", {})

        # Validate module
        if not module:
            logger.warning("Metasploit called without module parameter")
            return create_error_response("Module parameter is required")

        # Validate module path format (prevent path traversal)
        if not re.match(r'^[a-zA-Z0-9/_-]+$', module):
            return create_error_response("Invalid module path format")

        # Validate options
        if not isinstance(options, dict):
            return create_error_response("Options must be a dictionary")

        # Create an MSF resource script
        resource_content = f"use {module}\n"
        for key, value in options.items():
            # Validate key and value
            if not re.match(r'^[a-zA-Z0-9_]+$', str(key)):
                return create_error_response(f"Invalid option key: {key}")
            # Convert value to string and validate
            value_str = str(value)
            if any(char in value_str for char in ['\n', '\r', ';']):
                return create_error_response(f"Invalid option value for {key}")
            resource_content += f"set {key} {value_str}\n"
        resource_content += "exploit\n"

        # Save resource script to a temporary file
        resource_file = "/tmp/mcp_msf_resource.rc"
        try:
            with open(resource_file, "w") as f:
                f.write(resource_content)
        except IOError as e:
            logger.error(f"Failed to write resource file: {e}")
            return create_error_response("Failed to create resource file", 500)

        # Build command as a list
        command = ["msfconsole", "-q", "-r", resource_file]
        result = execute_command(command)

        # Clean up the temporary file
        try:
            os.remove(resource_file)
        except OSError as e:
            logger.warning(f"Error removing temporary resource file: {str(e)}")

        return create_success_response(result)

    except Exception as e:
        logger.error(f"Error in metasploit endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return create_error_response(f"Server error: {str(e)}", 500)


@app.route("/api/tools/hydra", methods=["POST"])
def hydra():
    """Execute hydra with the provided parameters."""
    try:
        params = request.json
        if not params:
            return create_error_response("Request body must be valid JSON")

        target = params.get("target", "")
        service = params.get("service", "")
        username = params.get("username", "")
        username_file = params.get("username_file", "")
        password = params.get("password", "")
        password_file = params.get("password_file", "")
        additional_args = params.get("additional_args", "")

        # Validate target and service
        if not target or not service:
            logger.warning("Hydra called without target or service parameter")
            return create_error_response("Target and service parameters are required")

        if not validate_target(target):
            return create_error_response("Invalid target format")

        # Validate service against allowlist
        if service not in VALID_HYDRA_SERVICES:
            logger.warning(f"Invalid hydra service: {service}")
            return create_error_response(
                f"Invalid service. Must be one of: {', '.join(VALID_HYDRA_SERVICES)}"
            )

        # Validate credentials
        if not (username or username_file) or not (password or password_file):
            logger.warning("Hydra called without username/password parameters")
            return create_error_response("Username/username_file and password/password_file are required")

        # Validate file paths if provided
        if username_file and not validate_file_path(username_file, must_exist=True):
            return create_error_response("Invalid or non-existent username file")
        if password_file and not validate_file_path(password_file, must_exist=True):
            return create_error_response("Invalid or non-existent password file")

        # Build command as a list
        command = ["hydra", "-t", "4"]

        # Add username/username_file
        if username:
            command.extend(["-l", username])
        elif username_file:
            command.extend(["-L", username_file])

        # Add password/password_file
        if password:
            command.extend(["-p", password])
        elif password_file:
            command.extend(["-P", password_file])

        # Add additional args safely
        additional_args_list = sanitize_additional_args(additional_args, "hydra")
        if additional_args and not additional_args_list:
            return create_error_response("Invalid additional arguments")
        command.extend(additional_args_list)

        # Add target and service
        command.extend([target, service])

        result = execute_command(command)
        return create_success_response(result)

    except Exception as e:
        logger.error(f"Error in hydra endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return create_error_response(f"Server error: {str(e)}", 500)


@app.route("/api/tools/john", methods=["POST"])
def john():
    """Execute john with the provided parameters."""
    try:
        params = request.json
        if not params:
            return create_error_response("Request body must be valid JSON")

        hash_file = params.get("hash_file", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        format_type = params.get("format", "")
        additional_args = params.get("additional_args", "")

        # Validate hash file
        if not hash_file:
            logger.warning("John called without hash_file parameter")
            return create_error_response("Hash file parameter is required")

        if not validate_file_path(hash_file, must_exist=True):
            return create_error_response("Invalid or non-existent hash file")

        # Validate wordlist if provided
        if wordlist and not validate_file_path(wordlist, must_exist=True):
            return create_error_response("Invalid or non-existent wordlist file")

        # Build command as a list
        command = ["john"]

        # Add format if specified
        if format_type:
            # Validate format (alphanumeric and hyphens only)
            if not re.match(r'^[a-zA-Z0-9-]+$', format_type):
                return create_error_response("Invalid format type")
            command.append(f"--format={format_type}")

        # Add wordlist
        if wordlist:
            command.append(f"--wordlist={wordlist}")

        # Add additional args safely
        additional_args_list = sanitize_additional_args(additional_args, "john")
        if additional_args and not additional_args_list:
            return create_error_response("Invalid additional arguments")
        command.extend(additional_args_list)

        # Add hash file last
        command.append(hash_file)

        result = execute_command(command)
        return create_success_response(result)

    except Exception as e:
        logger.error(f"Error in john endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return create_error_response(f"Server error: {str(e)}", 500)


@app.route("/api/tools/wpscan", methods=["POST"])
def wpscan():
    """Execute wpscan with the provided parameters."""
    try:
        params = request.json
        if not params:
            return create_error_response("Request body must be valid JSON")

        url = params.get("url", "")
        additional_args = params.get("additional_args", "")

        # Validate URL
        if not url:
            logger.warning("WPScan called without URL parameter")
            return create_error_response("URL parameter is required")

        if not validate_target(url):
            return create_error_response("Invalid URL format")

        # Build command as a list
        command = ["wpscan", "--url", url]

        # Add additional args safely
        additional_args_list = sanitize_additional_args(additional_args, "wpscan")
        if additional_args and not additional_args_list:
            return create_error_response("Invalid additional arguments")
        command.extend(additional_args_list)

        result = execute_command(command)
        return create_success_response(result)

    except Exception as e:
        logger.error(f"Error in wpscan endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return create_error_response(f"Server error: {str(e)}", 500)


@app.route("/api/tools/enum4linux", methods=["POST"])
def enum4linux():
    """Execute enum4linux with the provided parameters."""
    try:
        params = request.json
        if not params:
            return create_error_response("Request body must be valid JSON")

        target = params.get("target", "")
        additional_args = params.get("additional_args", "-a")

        # Validate target
        if not target:
            logger.warning("Enum4linux called without target parameter")
            return create_error_response("Target parameter is required")

        if not validate_target(target):
            return create_error_response("Invalid target format")

        # Build command as a list
        command = ["enum4linux"]

        # Add additional args safely
        additional_args_list = sanitize_additional_args(additional_args, "enum4linux")
        if additional_args and not additional_args_list:
            return create_error_response("Invalid additional arguments")
        command.extend(additional_args_list)

        # Add target last
        command.append(target)

        result = execute_command(command)
        return create_success_response(result)

    except Exception as e:
        logger.error(f"Error in enum4linux endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return create_error_response(f"Server error: {str(e)}", 500)


@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    # Check if essential tools are installed
    essential_tools = ["nmap", "gobuster", "dirb", "nikto"]
    tools_status = {}

    for tool in essential_tools:
        try:
            result = execute_command(["which", tool])
            tools_status[tool] = result["success"]
        except Exception as e:
            logger.warning(f"Error checking tool {tool}: {e}")
            tools_status[tool] = False

    all_essential_tools_available = all(tools_status.values())

    return jsonify({
        "status": "healthy",
        "message": "Kali Linux Tools API Server is running",
        "tools_status": tools_status,
        "all_essential_tools_available": all_essential_tools_available
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
    debug_mode = DEBUG_MODE
    api_port = API_PORT

    if args.debug:
        debug_mode = True
        logger.setLevel(logging.DEBUG)

    if args.port != API_PORT:
        api_port = args.port

    logger.info(f"Starting Kali Linux Tools API Server on port {api_port}")
    logger.info(f"Debug mode: {debug_mode}")
    logger.info(f"Command timeout: {COMMAND_TIMEOUT} seconds")

    app.run(host="0.0.0.0", port=api_port, debug=debug_mode)
