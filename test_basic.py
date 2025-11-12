#!/usr/bin/env python3
"""
Comprehensive unit tests for MCP Kali Server

These tests verify core functionality of the server components.
"""

import pytest
import sys
import os
import json

# Add parent directory to path to import modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


class TestKaliServerImports:
    """Test that server modules can be imported"""

    def test_import_kali_server(self):
        """Test that kali_server module can be imported"""
        try:
            import kali_server
            assert hasattr(kali_server, 'app')
            assert hasattr(kali_server, 'CommandExecutor')
            assert hasattr(kali_server, 'execute_command')
        except ImportError as e:
            pytest.fail(f"Failed to import kali_server: {e}")

    def test_import_mcp_server(self):
        """Test that mcp_server module can be imported"""
        try:
            import mcp_server
            assert hasattr(mcp_server, 'KaliToolsClient')
            assert hasattr(mcp_server, 'setup_mcp_server')
        except ImportError as e:
            pytest.fail(f"Failed to import mcp_server: {e}")


class TestConfiguration:
    """Test configuration and environment variables"""

    def test_default_configuration(self):
        """Test that default configuration values are set"""
        import kali_server

        # Test default values
        assert kali_server.COMMAND_TIMEOUT == 180
        assert isinstance(kali_server.API_PORT, int)
        assert isinstance(kali_server.DEBUG_MODE, bool)

    def test_mcp_client_initialization(self):
        """Test MCP client can be initialized"""
        from mcp_server import KaliToolsClient

        client = KaliToolsClient("http://localhost:5000")
        assert client.server_url == "http://localhost:5000"
        assert client.timeout == 300

    def test_mcp_client_url_stripping(self):
        """Test that MCP client strips trailing slashes from URLs"""
        from mcp_server import KaliToolsClient

        client = KaliToolsClient("http://localhost:5000/")
        assert client.server_url == "http://localhost:5000"


class TestCommandExecutor:
    """Test CommandExecutor class"""

    def test_command_executor_init_with_list(self):
        """Test CommandExecutor initialization with list"""
        from kali_server import CommandExecutor

        executor = CommandExecutor(["echo", "test"], timeout=10)
        assert executor.command == ["echo", "test"]
        assert executor.timeout == 10
        assert executor.return_code is None
        assert executor.timed_out is False

    def test_command_executor_init_defaults(self):
        """Test CommandExecutor initialization with defaults"""
        from kali_server import CommandExecutor, COMMAND_TIMEOUT

        executor = CommandExecutor(["ls"])
        assert executor.command == ["ls"]
        assert executor.timeout == COMMAND_TIMEOUT

    def test_command_executor_execute_simple(self):
        """Test CommandExecutor with simple command"""
        from kali_server import CommandExecutor

        executor = CommandExecutor(["echo", "hello"], timeout=5)
        result = executor.execute()

        assert result["success"] is True
        assert "hello" in result["stdout"]
        assert result["return_code"] == 0
        assert result["timed_out"] is False


class TestExecuteCommand:
    """Test execute_command function"""

    def test_execute_command_with_list(self):
        """Test execute_command with list argument"""
        from kali_server import execute_command

        result = execute_command(["echo", "test"])
        assert isinstance(result, dict)
        assert "stdout" in result
        assert "stderr" in result
        assert "return_code" in result
        assert "success" in result

    def test_execute_command_with_string(self):
        """Test execute_command with string argument (uses shlex)"""
        from kali_server import execute_command

        result = execute_command("echo test")
        assert isinstance(result, dict)
        assert "test" in result["stdout"]
        assert result["success"] is True

    def test_execute_command_with_empty_string(self):
        """Test execute_command with empty string"""
        from kali_server import execute_command

        result = execute_command("")
        assert result["success"] is False
        assert "Empty command" in result["stderr"]

    def test_execute_command_with_empty_list(self):
        """Test execute_command with empty list"""
        from kali_server import execute_command

        result = execute_command([])
        assert result["success"] is False
        assert "Empty command" in result["stderr"]


class TestValidateTarget:
    """Test target validation function"""

    def test_validate_target_valid_ip(self):
        """Test validation with valid IP address"""
        from kali_server import validate_target

        assert validate_target("192.168.1.1") is True
        assert validate_target("10.0.0.1") is True

    def test_validate_target_valid_hostname(self):
        """Test validation with valid hostname"""
        from kali_server import validate_target

        assert validate_target("example.com") is True
        assert validate_target("test.example.com") is True

    def test_validate_target_valid_url(self):
        """Test validation with valid URL"""
        from kali_server import validate_target

        assert validate_target("http://example.com") is True
        assert validate_target("https://example.com") is True

    def test_validate_target_injection_attempts(self):
        """Test validation blocks injection attempts"""
        from kali_server import validate_target

        assert validate_target("192.168.1.1; rm -rf /") is False
        assert validate_target("example.com | cat /etc/passwd") is False
        assert validate_target("test.com && whoami") is False
        assert validate_target("$(whoami)") is False
        assert validate_target("`id`") is False

    def test_validate_target_empty_or_none(self):
        """Test validation with empty or None values"""
        from kali_server import validate_target

        assert validate_target("") is False
        assert validate_target(None) is False

    def test_validate_target_too_long(self):
        """Test validation with overly long target"""
        from kali_server import validate_target

        long_target = "a" * 300
        assert validate_target(long_target) is False


class TestAPIEndpoints:
    """Test API endpoint configurations"""

    def test_health_endpoint_exists(self):
        """Test that health endpoint is registered"""
        from kali_server import app

        # Check that the /health route exists
        rules = [rule.rule for rule in app.url_map.iter_rules()]
        assert '/health' in rules

    def test_api_tool_endpoints_exist(self):
        """Test that tool endpoints are registered"""
        from kali_server import app

        rules = [rule.rule for rule in app.url_map.iter_rules()]

        # Check for key tool endpoints
        expected_endpoints = [
            '/api/tools/nmap',
            '/api/tools/gobuster',
            '/api/tools/nikto',
            '/api/tools/sqlmap',
            '/api/tools/metasploit',
            '/api/tools/hydra',
            '/api/tools/john',
            '/api/tools/wpscan',
            '/api/tools/enum4linux',
            '/api/tools/dirb',
            '/api/command',
            '/mcp/capabilities'
        ]

        for endpoint in expected_endpoints:
            assert endpoint in rules, f"Expected endpoint {endpoint} not found"

    def test_command_allowlist_exists(self):
        """Test that command allowlist is defined"""
        from kali_server import COMMAND_ALLOWLIST

        assert isinstance(COMMAND_ALLOWLIST, dict)
        assert len(COMMAND_ALLOWLIST) > 0
        assert "whoami" in COMMAND_ALLOWLIST


class TestFlaskAppConfiguration:
    """Test Flask app configuration"""

    def test_app_test_client(self):
        """Test that Flask app can create test client"""
        from kali_server import app

        client = app.test_client()
        assert client is not None

    def test_health_endpoint_response(self):
        """Test health endpoint returns proper response"""
        from kali_server import app

        client = app.test_client()
        response = client.get('/health')

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "healthy"
        assert "tools_status" in data
        assert isinstance(data["tools_status"], dict)

    def test_capabilities_endpoint_response(self):
        """Test capabilities endpoint returns proper response"""
        from kali_server import app

        client = app.test_client()
        response = client.get('/mcp/capabilities')

        assert response.status_code == 200
        data = json.loads(response.data)
        assert "tools" in data
        assert isinstance(data["tools"], list)
        assert len(data["tools"]) > 0
        assert data["version"] == "1.0.0"

    def test_api_command_requires_post(self):
        """Test that /api/command requires POST method"""
        from kali_server import app

        client = app.test_client()
        response = client.get('/api/command')

        # Should return 405 Method Not Allowed
        assert response.status_code == 405

    def test_api_command_requires_action(self):
        """Test that /api/command requires action parameter"""
        from kali_server import app

        client = app.test_client()
        response = client.post('/api/command',
                             json={},
                             content_type='application/json')

        assert response.status_code == 400
        data = json.loads(response.data)
        assert "error" in data

    def test_nmap_endpoint_requires_target(self):
        """Test that nmap endpoint requires target parameter"""
        from kali_server import app

        client = app.test_client()
        response = client.post('/api/tools/nmap',
                             json={},
                             content_type='application/json')

        assert response.status_code == 400
        data = json.loads(response.data)
        assert "error" in data
        assert "target" in data["error"].lower()


class TestMCPServerSetup:
    """Test MCP server setup"""

    def test_setup_mcp_server(self):
        """Test that MCP server can be set up"""
        from mcp_server import KaliToolsClient, setup_mcp_server

        client = KaliToolsClient("http://localhost:5000")
        mcp = setup_mcp_server(client)

        assert mcp is not None
        assert hasattr(mcp, 'run')


class TestBuildCommandSafely:
    """Test build_command_safely helper function"""

    def test_build_command_basic(self):
        """Test building basic command"""
        from kali_server import build_command_safely

        result = build_command_safely(["nmap"], target="192.168.1.1")
        assert "nmap" in result
        assert "192.168.1.1" in result

    def test_build_command_with_flags(self):
        """Test building command with flags"""
        from kali_server import build_command_safely

        result = build_command_safely(["nmap"], **{"-p": "80,443"})
        assert "nmap" in result
        assert "-p" in result
        assert "80,443" in result

    def test_build_command_filters_empty_values(self):
        """Test that empty values are filtered out"""
        from kali_server import build_command_safely

        result = build_command_safely(["nmap"], target="", port="80")
        assert "nmap" in result
        assert "80" in result
        assert "" not in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
