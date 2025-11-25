#!/usr/bin/env python3

# This script connect the MCP AI agent to Kali Linux terminal and API Server.

# some of the code here was inspired from https://github.com/whit3rabbit0/project_astro , be sure to check them out

import sys
import os
import argparse
import logging
from typing import Dict, Any, Optional
import requests

from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_KALI_SERVER = "http://localhost:5000"  # change to your linux IP
DEFAULT_REQUEST_TIMEOUT = 300  # 5 minutes default timeout for API requests


class KaliToolsClient:
    """Client for communicating with the Kali Linux Tools API Server"""

    def __init__(self, server_url: str, timeout: int = DEFAULT_REQUEST_TIMEOUT):
        """
        Initialize the Kali Tools Client

        Args:
            server_url: URL of the Kali Tools API Server
            timeout: Request timeout in seconds
        """
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        logger.info(f"Initialized Kali Tools Client connecting to {server_url}")

    def safe_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform a GET request with optional query parameters.

        Args:
            endpoint: API endpoint path (without leading slash)
            params: Optional query parameters

        Returns:
            Response data as dictionary
        """
        if params is None:
            params = {}

        url = f"{self.server_url}/{endpoint}"

        try:
            logger.debug(f"GET {url} with params: {params}")
            response = requests.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def safe_post(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform a POST request with JSON data.

        Args:
            endpoint: API endpoint path (without leading slash)
            json_data: JSON data to send

        Returns:
            Response data as dictionary
        """
        url = f"{self.server_url}/{endpoint}"

        try:
            logger.debug(f"POST {url} with data: {json_data}")
            response = requests.post(url, json=json_data, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def check_health(self) -> Dict[str, Any]:
        """
        Check the health of the Kali Tools API Server

        Returns:
            Health status information
        """
        return self.safe_get("health")


def setup_mcp_server(kali_client: KaliToolsClient) -> FastMCP:
    """
    Set up the MCP server with all tool functions

    Args:
        kali_client: Initialized KaliToolsClient

    Returns:
        Configured FastMCP instance
    """
    mcp = FastMCP("kali-mcp")

    @mcp.tool()
    def nmap_scan(
        target: str,
        scan_type: str = "-sCV",
        ports: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute an Nmap scan against a target.

        Args:
            target: The IP address or hostname to scan
            scan_type: Scan type (e.g., -sCV for service/version detection)
            ports: Comma-separated list of ports or port ranges (e.g., "22,80,443" or "1-1000")
            additional_args: Additional Nmap arguments (e.g., "-T4 -Pn")

        Returns:
            Scan results with stdout, stderr, and status information
        """
        data = {
            "target": target,
            "scan_type": scan_type,
            "ports": ports,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/nmap", data)

    @mcp.tool()
    def gobuster_scan(
        url: str,
        mode: str = "dir",
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Gobuster to find directories, DNS subdomains, or virtual hosts.

        Args:
            url: The target URL
            mode: Scan mode - must be one of: dir, dns, fuzz, vhost
            wordlist: Path to wordlist file on the Kali server
            additional_args: Additional Gobuster arguments

        Returns:
            Scan results with found directories/subdomains
        """
        data = {
            "url": url,
            "mode": mode,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/gobuster", data)

    @mcp.tool()
    def dirb_scan(
        url: str,
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Dirb web content scanner.

        Args:
            url: The target URL
            wordlist: Path to wordlist file on the Kali server
            additional_args: Additional Dirb arguments

        Returns:
            Scan results with discovered directories and files
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/dirb", data)

    @mcp.tool()
    def nikto_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Nikto web server scanner.

        Args:
            target: The target URL or IP address
            additional_args: Additional Nikto arguments

        Returns:
            Scan results with identified vulnerabilities and issues
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/nikto", data)

    @mcp.tool()
    def sqlmap_scan(url: str, data: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute SQLmap SQL injection scanner.

        Args:
            url: The target URL
            data: POST data string for testing POST parameters
            additional_args: Additional SQLmap arguments

        Returns:
            Scan results with SQL injection findings
        """
        post_data = {
            "url": url,
            "data": data,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/sqlmap", post_data)

    @mcp.tool()
    def metasploit_run(module: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Execute a Metasploit module.

        Args:
            module: The Metasploit module path (e.g., "exploit/windows/smb/ms17_010_eternalblue")
            options: Dictionary of module options (e.g., {"RHOSTS": "192.168.1.1", "LHOST": "192.168.1.100"})

        Returns:
            Module execution results
        """
        if options is None:
            options = {}

        data = {
            "module": module,
            "options": options
        }
        return kali_client.safe_post("api/tools/metasploit", data)

    @mcp.tool()
    def hydra_attack(
        target: str,
        service: str,
        username: str = "",
        username_file: str = "",
        password: str = "",
        password_file: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Hydra password cracking tool.

        Args:
            target: Target IP or hostname
            service: Service to attack (e.g., ssh, ftp, http-post-form)
            username: Single username to try
            username_file: Path to username file on the Kali server
            password: Single password to try
            password_file: Path to password file on the Kali server
            additional_args: Additional Hydra arguments

        Returns:
            Attack results with found credentials
        """
        data = {
            "target": target,
            "service": service,
            "username": username,
            "username_file": username_file,
            "password": password,
            "password_file": password_file,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/hydra", data)

    @mcp.tool()
    def john_crack(
        hash_file: str,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        format_type: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute John the Ripper password cracker.

        Args:
            hash_file: Path to file containing hashes on the Kali server
            wordlist: Path to wordlist file on the Kali server
            format_type: Hash format type (e.g., "md5", "sha256")
            additional_args: Additional John arguments

        Returns:
            Cracking results with recovered passwords
        """
        data = {
            "hash_file": hash_file,
            "wordlist": wordlist,
            "format": format_type,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/john", data)

    @mcp.tool()
    def wpscan_analyze(url: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute WPScan WordPress vulnerability scanner.

        Args:
            url: The target WordPress URL
            additional_args: Additional WPScan arguments

        Returns:
            Scan results with WordPress vulnerabilities and information
        """
        data = {
            "url": url,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/wpscan", data)

    @mcp.tool()
    def enum4linux_scan(target: str, additional_args: str = "-a") -> Dict[str, Any]:
        """
        Execute Enum4linux Windows/Samba enumeration tool.

        Args:
            target: The target IP or hostname
            additional_args: Additional enum4linux arguments (default: "-a" for all enumeration)

        Returns:
            Enumeration results with Windows/Samba information
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/enum4linux", data)

    @mcp.tool()
    def server_health() -> Dict[str, Any]:
        """
        Check the health status of the Kali API server.

        Returns:
            Server health information including available tools status
        """
        return kali_client.check_health()

    return mcp


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Run the Kali MCP Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Connect to local Kali server
  python3 mcp_server.py --server http://localhost:5000

  # Connect to remote Kali server with custom timeout
  python3 mcp_server.py --server http://192.168.1.100:5000 --timeout 600

  # Enable debug logging
  python3 mcp_server.py --server http://localhost:5000 --debug
        """
    )
    parser.add_argument(
        "--server",
        type=str,
        default=DEFAULT_KALI_SERVER,
        help=f"Kali API server URL (default: {DEFAULT_KALI_SERVER})"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_REQUEST_TIMEOUT,
        help=f"Request timeout in seconds (default: {DEFAULT_REQUEST_TIMEOUT})"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging"
    )
    return parser.parse_args()


def main():
    """Main entry point for the MCP server."""
    args = parse_args()

    # Configure logging based on debug flag
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")

    # Initialize the Kali Tools client
    kali_client = KaliToolsClient(args.server, args.timeout)

    # Check server health and log the result
    health = kali_client.check_health()
    if "error" in health:
        logger.warning(f"Unable to connect to Kali API server at {args.server}: {health['error']}")
        logger.warning("MCP server will start, but tool execution may fail")
    else:
        logger.info(f"Successfully connected to Kali API server at {args.server}")
        logger.info(f"Server health status: {health.get('status', 'unknown')}")
        if not health.get("all_essential_tools_available", False):
            logger.warning("Not all essential tools are available on the Kali server")
            missing_tools = [
                tool for tool, available in health.get("tools_status", {}).items()
                if not available
            ]
            if missing_tools:
                logger.warning(f"Missing tools: {', '.join(missing_tools)}")

    # Set up and run the MCP server
    mcp = setup_mcp_server(kali_client)
    logger.info("Starting Kali MCP server")
    logger.info(f"Available tools: nmap, gobuster, dirb, nikto, sqlmap, metasploit, hydra, john, wpscan, enum4linux")
    mcp.run()


if __name__ == "__main__":
    main()
