#!/usr/bin/env python3

# This script connect the MCP AI agent to Kali Linux terminal and API Server.

# some of the code here was inspired from https://github.com/whit3rabbit0/project_astro , be sure to check them out

import argparse
import logging
import os
import shlex
import subprocess
import sys
import traceback
import threading
from typing import Dict, Any, List, Union
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
COMMAND_TIMEOUT = 180  # 5 minutes default timeout

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

app = Flask(__name__)


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
            self.stdout_data += line

    def _read_stderr(self):
        """Thread function to continuously read stderr"""
        for line in iter(self.process.stderr.readline, ''):
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


def execute_command(command: Union[List[str], str]) -> Dict[str, Any]:
    """
    Execute a command and return the result

    Args:
        command: The command to execute, as a list of strings or a string (will be safely parsed)

    Returns:
        A dictionary containing the stdout, stderr, and return code
    """
    # Convert string to list safely using shlex
    if isinstance(command, str):
        try:
            command = shlex.split(command)
        except ValueError as e:
            logger.error(f"Invalid command string: {str(e)}")
            return {
                "stdout": "",
                "stderr": f"Invalid command string: {str(e)}",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": False
            }

    # Validate command is not empty
    if not command or not command[0]:
        return {
            "stdout": "",
            "stderr": "Empty command provided",
            "return_code": -1,
            "success": False,
            "timed_out": False,
            "partial_results": False
        }

    executor = CommandExecutor(command)
    return executor.execute()


def build_command_safely(base_command: List[str], **kwargs) -> List[str]:
    """
    Build a command safely by appending validated arguments

    Args:
        base_command: The base command as a list (e.g., ["nmap", "-sV"])
        **kwargs: Key-value pairs to add to the command

    Returns:
        Complete command as a list of strings
    """
    command = base_command.copy()

    for key, value in kwargs.items():
        if value is None or value == "":
            continue

        # Handle boolean flags
        if isinstance(value, bool):
            if value:
                command.append(key)
        # Handle lists (e.g., multiple arguments)
        elif isinstance(value, list):
            command.extend(value)
        # Handle string arguments
        elif isinstance(value, str):
            # If key is an option (starts with -), add both key and value
            if key.startswith('-'):
                command.append(key)
                command.append(value)
            else:
                # Otherwise, value is a standalone argument
                command.append(value)
        else:
            # Convert to string for other types
            command.append(str(value))

    return command


def validate_target(target: str) -> bool:
    """
    Basic validation for target parameters (IP addresses, hostnames, URLs)

    Args:
        target: The target to validate

    Returns:
        True if valid, False otherwise
    """
    if not target or not isinstance(target, str):
        return False

    # Remove common URL schemes
    target_clean = target.replace("http://", "").replace("https://", "")

    # Basic length check
    if len(target_clean) > 255:
        return False

    # Check for obvious command injection attempts
    dangerous_chars = [";", "|", "&", "$", "`", "(", ")", "<", ">", "\n", "\r"]
    for char in dangerous_chars:
        if char in target:
            logger.warning(f"Potentially dangerous character '{char}' found in target: {target}")
            return False

    return True


@app.route("/api/command", methods=["POST"])
def generic_command():
    """Execute a safe command from the allowlist provided in the request."""
    try:
        params = request.json
        action = params.get("action", "")

        if not action or action not in COMMAND_ALLOWLIST:
            logger.warning(f"Command endpoint called with unknown or missing action parameter: {action}")
            return jsonify({
                "error": "Action parameter is required and must be one of: " + ", ".join(COMMAND_ALLOWLIST.keys())
            }), 400

        command_to_run = COMMAND_ALLOWLIST[action]
        result = execute_command(command_to_run)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in command endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


@app.route("/api/tools/nmap", methods=["POST"])
def nmap():
    """Execute nmap scan with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        scan_type = params.get("scan_type", "-sV")
        ports = params.get("ports", "")
        additional_args = params.get("additional_args", "-T4 -Pn")

        if not target:
            logger.warning("Nmap called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400

        # Validate target
        if not validate_target(target):
            logger.warning(f"Invalid target provided: {target}")
            return jsonify({
                "error": "Invalid target parameter"
            }), 400

        # Build command safely as a list
        command = ["nmap"]

        # Add scan type flags
        if scan_type:
            # Parse scan type safely (could be multiple flags like "-sV -sC")
            scan_flags = shlex.split(scan_type)
            command.extend(scan_flags)

        # Add port specification
        if ports:
            command.extend(["-p", ports])

        # Add additional arguments
        if additional_args:
            # Parse additional args safely
            extra_args = shlex.split(additional_args)
            command.extend(extra_args)

        # Add target last
        command.append(target)

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


@app.route("/api/tools/gobuster", methods=["POST"])
def gobuster():
    """Execute gobuster with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        mode = params.get("mode", "dir")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("Gobuster called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400

        # Validate URL
        if not validate_target(url):
            logger.warning(f"Invalid URL provided: {url}")
            return jsonify({
                "error": "Invalid URL parameter"
            }), 400

        # Validate mode
        if mode not in ["dir", "dns", "fuzz", "vhost"]:
            logger.warning(f"Invalid gobuster mode: {mode}")
            return jsonify({
                "error": f"Invalid mode: {mode}. Must be one of: dir, dns, fuzz, vhost"
            }), 400

        # Build command safely as a list
        command = ["gobuster", mode, "-u", url, "-w", wordlist]

        # Add additional arguments
        if additional_args:
            extra_args = shlex.split(additional_args)
            command.extend(extra_args)

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in gobuster endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


@app.route("/api/tools/dirb", methods=["POST"])
def dirb():
    """Execute dirb with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("Dirb called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400

        # Validate URL
        if not validate_target(url):
            logger.warning(f"Invalid URL provided: {url}")
            return jsonify({
                "error": "Invalid URL parameter"
            }), 400

        # Build command safely as a list
        command = ["dirb", url, wordlist]

        # Add additional arguments
        if additional_args:
            extra_args = shlex.split(additional_args)
            command.extend(extra_args)

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in dirb endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


@app.route("/api/tools/nikto", methods=["POST"])
def nikto():
    """Execute nikto with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("Nikto called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400

        # Validate target
        if not validate_target(target):
            logger.warning(f"Invalid target provided: {target}")
            return jsonify({
                "error": "Invalid target parameter"
            }), 400

        # Build command safely as a list
        command = ["nikto", "-h", target]

        # Add additional arguments
        if additional_args:
            extra_args = shlex.split(additional_args)
            command.extend(extra_args)

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nikto endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


@app.route("/api/tools/sqlmap", methods=["POST"])
def sqlmap():
    """Execute sqlmap with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        data = params.get("data", "")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("SQLMap called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400

        # Validate URL
        if not validate_target(url):
            logger.warning(f"Invalid URL provided: {url}")
            return jsonify({
                "error": "Invalid URL parameter"
            }), 400

        # Build command safely as a list
        command = ["sqlmap", "-u", url, "--batch"]

        # Add POST data if provided
        if data:
            command.extend(["--data", data])

        # Add additional arguments
        if additional_args:
            extra_args = shlex.split(additional_args)
            command.extend(extra_args)

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in sqlmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


@app.route("/api/tools/metasploit", methods=["POST"])
def metasploit():
    """Execute metasploit module with the provided parameters."""
    try:
        params = request.json
        module = params.get("module", "")
        options = params.get("options", None)

        if options is None:
            options = {}

        if not module:
            logger.warning("Metasploit called without module parameter")
            return jsonify({
                "error": "Module parameter is required"
            }), 400

        # Validate module name (basic check)
        if not module or not isinstance(module, str):
            return jsonify({
                "error": "Invalid module parameter"
            }), 400

        # Create an MSF resource script
        resource_content = f"use {module}\n"
        for key, value in options.items():
            # Basic sanitization - ensure key and value don't contain newlines
            safe_key = str(key).replace("\n", "").replace("\r", "")
            safe_value = str(value).replace("\n", "").replace("\r", "")
            resource_content += f"set {safe_key} {safe_value}\n"
        resource_content += "exploit\n"

        # Save resource script to a temporary file with more secure name
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
            resource_file = f.name
            f.write(resource_content)

        try:
            # Build command safely as a list
            command = ["msfconsole", "-q", "-r", resource_file]
            result = execute_command(command)
        finally:
            # Clean up the temporary file
            try:
                os.remove(resource_file)
            except Exception as e:
                logger.warning(f"Error removing temporary resource file: {str(e)}")

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in metasploit endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


@app.route("/api/tools/hydra", methods=["POST"])
def hydra():
    """Execute hydra with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        service = params.get("service", "")
        username = params.get("username", "")
        username_file = params.get("username_file", "")
        password = params.get("password", "")
        password_file = params.get("password_file", "")
        additional_args = params.get("additional_args", "")

        if not target or not service:
            logger.warning("Hydra called without target or service parameter")
            return jsonify({
                "error": "Target and service parameters are required"
            }), 400

        # Validate target
        if not validate_target(target):
            logger.warning(f"Invalid target provided: {target}")
            return jsonify({
                "error": "Invalid target parameter"
            }), 400

        if not (username or username_file) or not (password or password_file):
            logger.warning("Hydra called without username/password parameters")
            return jsonify({
                "error": "Username/username_file and password/password_file are required"
            }), 400

        # Build command safely as a list
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

        # Add additional arguments
        if additional_args:
            extra_args = shlex.split(additional_args)
            command.extend(extra_args)

        # Add target and service
        command.append(target)
        command.append(service)

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in hydra endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


@app.route("/api/tools/john", methods=["POST"])
def john():
    """Execute john with the provided parameters."""
    try:
        params = request.json
        hash_file = params.get("hash_file", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        format_type = params.get("format", "")
        additional_args = params.get("additional_args", "")

        if not hash_file:
            logger.warning("John called without hash_file parameter")
            return jsonify({
                "error": "Hash file parameter is required"
            }), 400

        # Build command safely as a list
        command = ["john"]

        # Add format if specified
        if format_type:
            command.append(f"--format={format_type}")

        # Add wordlist if specified
        if wordlist:
            command.append(f"--wordlist={wordlist}")

        # Add additional arguments
        if additional_args:
            extra_args = shlex.split(additional_args)
            command.extend(extra_args)

        # Add hash file
        command.append(hash_file)

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in john endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


@app.route("/api/tools/wpscan", methods=["POST"])
def wpscan():
    """Execute wpscan with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("WPScan called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400

        # Validate URL
        if not validate_target(url):
            logger.warning(f"Invalid URL provided: {url}")
            return jsonify({
                "error": "Invalid URL parameter"
            }), 400

        # Build command safely as a list
        command = ["wpscan", "--url", url]

        # Add additional arguments
        if additional_args:
            extra_args = shlex.split(additional_args)
            command.extend(extra_args)

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in wpscan endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


@app.route("/api/tools/enum4linux", methods=["POST"])
def enum4linux():
    """Execute enum4linux with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "-a")

        if not target:
            logger.warning("Enum4linux called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400

        # Validate target
        if not validate_target(target):
            logger.warning(f"Invalid target provided: {target}")
            return jsonify({
                "error": "Invalid target parameter"
            }), 400

        # Build command safely as a list
        command = ["enum4linux"]

        # Add additional arguments
        if additional_args:
            extra_args = shlex.split(additional_args)
            command.extend(extra_args)

        # Add target
        command.append(target)

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in enum4linux endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


# Health check endpoint
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
            logger.debug(f"Error checking tool {tool}: {str(e)}")
            tools_status[tool] = False

    all_essential_tools_available = all(tools_status.values())

    return jsonify({
        "status": "healthy",
        "message": "Kali Linux Tools API Server is running",
        "tools_status": tools_status,
        "all_essential_tools_available": all_essential_tools_available
    })


@app.route("/mcp/capabilities", methods=["GET"])
def get_capabilities():
    """Return tool capabilities for MCP integration."""
    capabilities = {
        "tools": [
            {
                "name": "nmap_scan",
                "description": "Execute Nmap network scanner",
                "parameters": ["target", "scan_type", "ports", "additional_args"]
            },
            {
                "name": "gobuster_scan",
                "description": "Execute Gobuster directory/file enumeration",
                "parameters": ["url", "mode", "wordlist", "additional_args"]
            },
            {
                "name": "dirb_scan",
                "description": "Execute Dirb web content scanner",
                "parameters": ["url", "wordlist", "additional_args"]
            },
            {
                "name": "nikto_scan",
                "description": "Execute Nikto web server scanner",
                "parameters": ["target", "additional_args"]
            },
            {
                "name": "sqlmap_scan",
                "description": "Execute SQLmap SQL injection scanner",
                "parameters": ["url", "data", "additional_args"]
            },
            {
                "name": "metasploit_run",
                "description": "Execute Metasploit module",
                "parameters": ["module", "options"]
            },
            {
                "name": "hydra_attack",
                "description": "Execute Hydra password cracker",
                "parameters": ["target", "service", "username", "username_file", "password", "password_file", "additional_args"]
            },
            {
                "name": "john_crack",
                "description": "Execute John the Ripper password cracker",
                "parameters": ["hash_file", "wordlist", "format", "additional_args"]
            },
            {
                "name": "wpscan_analyze",
                "description": "Execute WPScan WordPress scanner",
                "parameters": ["url", "additional_args"]
            },
            {
                "name": "enum4linux_scan",
                "description": "Execute Enum4linux SMB enumeration",
                "parameters": ["target", "additional_args"]
            }
        ],
        "version": "1.0.0",
        "server_name": "Kali Tools API Server"
    }
    return jsonify(capabilities)


@app.route("/mcp/tools/kali_tools/<tool_name>", methods=["POST"])
def execute_tool(tool_name):
    """Direct tool execution endpoint for MCP integration."""
    try:

        # Map tool names to their corresponding endpoints
        tool_map = {
            "nmap": nmap,
            "gobuster": gobuster,
            "dirb": dirb,
            "nikto": nikto,
            "sqlmap": sqlmap,
            "metasploit": metasploit,
            "hydra": hydra,
            "john": john,
            "wpscan": wpscan,
            "enum4linux": enum4linux
        }

        if tool_name not in tool_map:
            return jsonify({
                "error": f"Unknown tool: {tool_name}"
            }), 404

        # Call the appropriate tool function
        return tool_map[tool_name]()

    except Exception as e:
        logger.error(f"Error in execute_tool endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


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
