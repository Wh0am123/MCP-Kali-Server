#!/usr/bin/env python3

# This script connect the MCP AI agent to Kali Linux terminal and API Server.

# some of the code here was inspired from https://github.com/whit3rabbit0/project_astro , be sure to check them out

import argparse
import json
import logging
import os
import re
import shlex
import subprocess
import sys
import traceback
import threading
from typing import Dict, Any
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

app = Flask(__name__)

class CommandExecutor:
    """Class to handle command execution with better timeout management"""

    def __init__(self, command, timeout: int = COMMAND_TIMEOUT):
        self.command = command
        self.timeout = timeout
        # Determine if we should use shell mode based on command type
        self.use_shell = isinstance(command, str)
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
                shell=self.use_shell,
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


def execute_command(command) -> Dict[str, Any]:
    """
    Execute a command and return the result.

    Args:
        command: The command to execute (list for safe mode, string for shell mode)

    Returns:
        A dictionary containing the stdout, stderr, and return code
    """
    executor = CommandExecutor(command)
    return executor.execute()


@app.route("/api/command", methods=["POST"])
def generic_command():
    """Execute any command provided in the request."""
    try:
        params = request.json
        command = params.get("command", "")
        
        if not command:
            logger.warning("Command endpoint called without command parameter")
            return jsonify({
                "error": "Command parameter is required"
            }), 400
        
        result = execute_command(command)
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
        scan_type = params.get("scan_type", "-sCV")
        ports = params.get("ports", "")
        additional_args = params.get("additional_args", "-T4 -Pn")
        
        if not target:
            logger.warning("Nmap called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400        
        
        command = ["nmap"] + shlex.split(scan_type)

        if ports:
            command += ["-p", ports]

        if additional_args:
            command += shlex.split(additional_args)

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
        
        # Validate mode
        if mode not in ["dir", "dns", "fuzz", "vhost"]:
            logger.warning(f"Invalid gobuster mode: {mode}")
            return jsonify({
                "error": f"Invalid mode: {mode}. Must be one of: dir, dns, fuzz, vhost"
            }), 400
        
        command = ["gobuster", mode, "-u", url, "-w", wordlist]

        if additional_args:
            command += shlex.split(additional_args)
        
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
        
        command = ["dirb", url, wordlist]

        if additional_args:
            command += shlex.split(additional_args)
        
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
        
        command = ["nikto", "-h", target]

        if additional_args:
            command += shlex.split(additional_args)
        
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
        
        command = ["sqlmap", "-u", url, "--batch"]

        if data:
            command += ["--data", data]

        if additional_args:
            command += shlex.split(additional_args)
        
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
        options = params.get("options", {})
        
        if not module:
            logger.warning("Metasploit called without module parameter")
            return jsonify({
                "error": "Module parameter is required"
            }), 400
        
        # Validate module name (allow only alphanumeric, slashes, underscores, hyphens)
        if not re.match(r'^[a-zA-Z0-9/_-]+$', module):
            return jsonify({"error": "Invalid module name"}), 400

        # Create an MSF resource script with validated options
        resource_content = f"use {module}\n"
        for key, value in options.items():
            # Validate option keys
            if not re.match(r'^[a-zA-Z0-9_]+$', str(key)):
                return jsonify({"error": f"Invalid option key: {key}"}), 400
            resource_content += f"set {key} {value}\n"
        resource_content += "exploit\n"

        # Save resource script to a temporary file
        resource_file = "/tmp/mks_msf_resource.rc"
        with open(resource_file, "w") as f:
            f.write(resource_content)

        command = ["msfconsole", "-q", "-r", resource_file]
        result = execute_command(command)
        
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
        
        if not (username or username_file) or not (password or password_file):
            logger.warning("Hydra called without username/password parameters")
            return jsonify({
                "error": "Username/username_file and password/password_file are required"
            }), 400
        
        command = ["hydra", "-t", "4"]

        if username:
            command += ["-l", username]
        elif username_file:
            command += ["-L", username_file]

        if password:
            command += ["-p", password]
        elif password_file:
            command += ["-P", password_file]

        command += [target, service]

        if additional_args:
            command += shlex.split(additional_args)
        
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
        
        command = ["john"]

        if format_type:
            command.append(f"--format={format_type}")

        if wordlist:
            command.append(f"--wordlist={wordlist}")

        if additional_args:
            command += shlex.split(additional_args)

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
        
        command = ["wpscan", "--url", url]

        if additional_args:
            command += shlex.split(additional_args)
        
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
        
        command = ["enum4linux"] + shlex.split(additional_args) + [target]
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in enum4linux endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


@app.route("/api/tools/medusa", methods=["POST"])
def medusa():
    """Execute medusa password cracker with the provided parameters."""
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
            logger.warning("Medusa called without target or service parameter")
            return jsonify({"error": "Target and service parameters are required"}), 400

        if not (username or username_file) or not (password or password_file):
            logger.warning("Medusa called without username/password parameters")
            return jsonify({"error": "Username/username_file and password/password_file are required"}), 400

        command = ["medusa", "-t", "4", "-h", target, "-M", service]

        if username:
            command += ["-u", username]
        elif username_file:
            command += ["-U", username_file]

        if password:
            command += ["-p", password]
        elif password_file:
            command += ["-P", password_file]

        if additional_args:
            command += shlex.split(additional_args)

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in medusa endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/wapiti", methods=["POST"])
def wapiti():
    """Execute wapiti web vulnerability scanner."""
    try:
        params = request.json
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("Wapiti called without URL parameter")
            return jsonify({"error": "URL parameter is required"}), 400

        command = ["wapiti", "-u", url]

        if additional_args:
            command += shlex.split(additional_args)

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in wapiti endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/joomscan", methods=["POST"])
def joomscan():
    """Execute joomscan Joomla vulnerability scanner."""
    try:
        params = request.json
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("JoomScan called without URL parameter")
            return jsonify({"error": "URL parameter is required"}), 400

        command = ["joomscan", "--url", url]

        if additional_args:
            command += shlex.split(additional_args)

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in joomscan endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/sqlninja", methods=["POST"])
def sqlninja():
    """Execute sqlninja SQL Server injection tool."""
    try:
        params = request.json
        mode = params.get("mode", "t")
        config_file = params.get("config_file", "")
        additional_args = params.get("additional_args", "")

        valid_modes = ["t", "f", "b", "e", "x", "k", "s", "d", "i"]
        if mode not in valid_modes:
            return jsonify({"error": f"Invalid mode: {mode}. Must be one of: {', '.join(valid_modes)}"}), 400

        command = ["sqlninja", "-m", mode]

        if config_file:
            command += ["-f", config_file]

        if additional_args:
            command += shlex.split(additional_args)

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in sqlninja endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/smtp-user-enum", methods=["POST"])
def smtp_user_enum():
    """Execute smtp-user-enum SMTP user enumeration tool."""
    try:
        params = request.json
        target = params.get("target", "")
        method = params.get("method", "VRFY")
        username = params.get("username", "")
        userlist = params.get("userlist", "")
        port = params.get("port", 25)
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("smtp-user-enum called without target parameter")
            return jsonify({"error": "Target parameter is required"}), 400

        if not (username or userlist):
            logger.warning("smtp-user-enum called without username or userlist parameter")
            return jsonify({"error": "Username or userlist parameter is required"}), 400

        if method not in ["VRFY", "EXPN", "RCPT"]:
            return jsonify({"error": f"Invalid method: {method}. Must be one of: VRFY, EXPN, RCPT"}), 400

        command = ["smtp-user-enum", "-M", method, "-t", target, "-p", str(port)]

        if username:
            command += ["-u", username]
        elif userlist:
            command += ["-U", userlist]

        if additional_args:
            command += shlex.split(additional_args)

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in smtp-user-enum endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/xsser", methods=["POST"])
def xsser():
    """Execute xsser XSS vulnerability scanner."""
    try:
        params = request.json
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("XSSer called without URL parameter")
            return jsonify({"error": "URL parameter is required"}), 400

        command = ["xsser", "-u", url]

        if additional_args:
            command += shlex.split(additional_args)

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in xsser endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/unicornscan", methods=["POST"])
def unicornscan():
    """Execute unicornscan asynchronous port scanner."""
    try:
        params = request.json
        target = params.get("target", "")
        ports = params.get("ports", "")
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("Unicornscan called without target parameter")
            return jsonify({"error": "Target parameter is required"}), 400

        target_spec = f"{target}:{ports}" if ports else target
        command = ["unicornscan", target_spec]

        if additional_args:
            command += shlex.split(additional_args)

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in unicornscan endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/dnsmap", methods=["POST"])
def dnsmap():
    """Execute dnsmap DNS subdomain brute-force tool."""
    try:
        params = request.json
        domain = params.get("domain", "")
        wordlist = params.get("wordlist", "")
        additional_args = params.get("additional_args", "")

        if not domain:
            logger.warning("dnsmap called without domain parameter")
            return jsonify({"error": "Domain parameter is required"}), 400

        command = ["dnsmap", domain]

        if wordlist:
            command += ["-w", wordlist]

        if additional_args:
            command += shlex.split(additional_args)

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in dnsmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/cloud-enum", methods=["POST"])
def cloud_enum():
    """Execute cloud_enum cloud storage and service enumeration tool."""
    try:
        params = request.json
        keywords = params.get("keywords", "")
        additional_args = params.get("additional_args", "")

        if not keywords:
            logger.warning("cloud-enum called without keywords parameter")
            return jsonify({"error": "Keywords parameter is required"}), 400

        command = ["cloud_enum"]
        for kw in re.split(r'[,\s]+', keywords):
            if kw:
                command += ["-k", kw]

        if additional_args:
            command += shlex.split(additional_args)

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in cloud-enum endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/padbuster", methods=["POST"])
def padbuster():
    """Execute padbuster padding oracle attack tool."""
    try:
        params = request.json
        url = params.get("url", "")
        sample = params.get("sample", "")
        block_size = params.get("block_size", 8)
        additional_args = params.get("additional_args", "")

        if not url or not sample:
            logger.warning("padbuster called without url or sample parameter")
            return jsonify({"error": "URL and sample parameters are required"}), 400

        command = ["padbuster", url, sample, str(block_size)]

        if additional_args:
            command += shlex.split(additional_args)

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in padbuster endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/sipvicious", methods=["POST"])
def sipvicious():
    """Execute SIPVicious SIP scanning tools (svmap, svwar, svcrack)."""
    try:
        params = request.json
        target = params.get("target", "")
        tool = params.get("tool", "svmap")
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("sipvicious called without target parameter")
            return jsonify({"error": "Target parameter is required"}), 400

        if tool not in ["svmap", "svwar", "svcrack", "svreport"]:
            return jsonify({"error": f"Invalid tool: {tool}. Must be one of: svmap, svwar, svcrack, svreport"}), 400

        command = [tool, target]

        if additional_args:
            command += shlex.split(additional_args)

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in sipvicious endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/polenum", methods=["POST"])
def polenum():
    """Execute polenum password policy enumeration tool."""
    try:
        params = request.json
        target = params.get("target", "")
        username = params.get("username", "")
        password = params.get("password", "")
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("polenum called without target parameter")
            return jsonify({"error": "Target parameter is required"}), 400

        command = ["polenum", "--domain", target]

        if username:
            command += ["--username", username]

        if password:
            command += ["--password", password]

        if additional_args:
            command += shlex.split(additional_args)

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in polenum endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/lynis", methods=["POST"])
def lynis():
    """Execute lynis security auditing tool."""
    try:
        params = request.json
        mode = params.get("mode", "audit system")
        additional_args = params.get("additional_args", "")

        command = ["lynis"] + shlex.split(mode)

        if additional_args:
            command += shlex.split(additional_args)

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in lynis endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/photon", methods=["POST"])
def photon():
    """Execute Photon OSINT web crawler."""
    try:
        params = request.json
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("Photon called without URL parameter")
            return jsonify({"error": "URL parameter is required"}), 400

        command = ["photon", "-u", url]

        if additional_args:
            command += shlex.split(additional_args)

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in photon endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/dnstracer", methods=["POST"])
def dnstracer():
    """Execute dnstracer DNS chain tracer."""
    try:
        params = request.json
        domain = params.get("domain", "")
        additional_args = params.get("additional_args", "")

        if not domain:
            logger.warning("dnstracer called without domain parameter")
            return jsonify({"error": "Domain parameter is required"}), 400

        command = ["dnstracer", domain]

        if additional_args:
            command += shlex.split(additional_args)

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in dnstracer endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/dnswalk", methods=["POST"])
def dnswalk():
    """Execute dnswalk DNS zone consistency checker."""
    try:
        params = request.json
        domain = params.get("domain", "")
        additional_args = params.get("additional_args", "")

        if not domain:
            logger.warning("dnswalk called without domain parameter")
            return jsonify({"error": "Domain parameter is required"}), 400

        if not domain.endswith("."):
            domain += "."

        command = ["dnswalk", domain]

        if additional_args:
            command += shlex.split(additional_args)

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in dnswalk endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


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
        except:
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
    # Return tool capabilities similar to our existing MCP server
    pass

@app.route("/mcp/tools/kali_tools/<tool_name>", methods=["POST"])
def execute_tool(tool_name):
    # Direct tool execution without going through the API server
    pass

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the Kali Linux API Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=API_PORT, help=f"Port for the API server (default: {API_PORT})")
    parser.add_argument("--ip", type=str, default="127.0.0.1", help="IP address to bind the server to (default: 127.0.0.1 for localhost only)")
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
    
    logger.info(f"Starting Kali Linux Tools API Server on {args.ip}:{API_PORT}")
    app.run(host=args.ip, port=API_PORT, debug=DEBUG_MODE)
