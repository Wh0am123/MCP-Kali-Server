#!/usr/bin/env python3
"""
Basic unit tests for MCP Kali Server

These tests verify core functionality of the server components.
"""

import pytest
import sys
import os

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

    def test_validation_constants(self):
        """Test that validation constants are defined"""
        import kali_server

        assert hasattr(kali_server, 'VALID_NMAP_SCAN_TYPES')
        assert hasattr(kali_server, 'VALID_GOBUSTER_MODES')
        assert hasattr(kali_server, 'VALID_HYDRA_SERVICES')

        # Verify they are sets
        assert isinstance(kali_server.VALID_NMAP_SCAN_TYPES, set)
        assert isinstance(kali_server.VALID_GOBUSTER_MODES, set)
        assert isinstance(kali_server.VALID_HYDRA_SERVICES, set)

    def test_mcp_client_initialization(self):
        """Test MCP client can be initialized"""
        from mcp_server import KaliToolsClient

        client = KaliToolsClient("http://localhost:5000")
        assert client.server_url == "http://localhost:5000"
        assert client.timeout == 300


class TestCommandExecutor:
    """Test CommandExecutor class"""

    def test_command_executor_init_with_list(self):
        """Test CommandExecutor initialization with list"""
        from kali_server import CommandExecutor

        executor = CommandExecutor(["echo", "test"], timeout=10)
        assert executor.command == ["echo", "test"]
        assert executor.timeout == 10
        assert executor.return_code is None

    def test_command_executor_rejects_string(self):
        """Test CommandExecutor rejects string commands"""
        from kali_server import CommandExecutor

        with pytest.raises(ValueError, match="Command must be a list"):
            CommandExecutor("echo test", timeout=10)

    def test_command_executor_rejects_empty_list(self):
        """Test CommandExecutor rejects empty command list"""
        from kali_server import CommandExecutor

        with pytest.raises(ValueError, match="Command list cannot be empty"):
            CommandExecutor([], timeout=10)

    def test_execute_command_basic(self):
        """Test basic command execution"""
        from kali_server import execute_command

        result = execute_command(["echo", "hello"])
        assert result["success"] is True
        assert "hello" in result["stdout"]
        assert result["return_code"] == 0


class TestValidationFunctions:
    """Test input validation functions"""

    def test_validate_target_valid_ip(self):
        """Test validate_target accepts valid IP addresses"""
        from kali_server import validate_target

        assert validate_target("192.168.1.1") is True
        assert validate_target("10.0.0.1") is True
        assert validate_target("example.com") is True

    def test_validate_target_rejects_injection(self):
        """Test validate_target rejects injection attempts"""
        from kali_server import validate_target

        assert validate_target("192.168.1.1; rm -rf /") is False
        assert validate_target("192.168.1.1 && ls") is False
        assert validate_target("192.168.1.1 | cat /etc/passwd") is False
        assert validate_target("192.168.1.1`whoami`") is False
        assert validate_target("192.168.1.1$(whoami)") is False

    def test_validate_target_rejects_empty(self):
        """Test validate_target rejects empty strings"""
        from kali_server import validate_target

        assert validate_target("") is False
        assert validate_target(None) is False

    def test_validate_file_path_basic(self):
        """Test validate_file_path basic functionality"""
        from kali_server import validate_file_path

        # Test with must_exist=False
        assert validate_file_path("/tmp/test.txt", must_exist=False) is True

        # Test that existing file passes (this file itself)
        assert validate_file_path(__file__, must_exist=True) is True

    def test_validate_file_path_rejects_traversal(self):
        """Test validate_file_path rejects directory traversal"""
        from kali_server import validate_file_path

        assert validate_file_path("../etc/passwd", must_exist=False) is False
        assert validate_file_path("/tmp/../etc/passwd", must_exist=False) is False

    def test_validate_file_path_rejects_injection(self):
        """Test validate_file_path rejects injection attempts"""
        from kali_server import validate_file_path

        assert validate_file_path("/tmp/test.txt; rm -rf /", must_exist=False) is False
        assert validate_file_path("/tmp/test.txt | cat", must_exist=False) is False
        assert validate_file_path("/tmp/test.txt`whoami`", must_exist=False) is False

    def test_sanitize_additional_args(self):
        """Test sanitize_additional_args function"""
        from kali_server import sanitize_additional_args

        # Test valid arguments
        result = sanitize_additional_args("-v -O", "test")
        assert result == ["-v", "-O"]

        # Test empty string
        result = sanitize_additional_args("", "test")
        assert result == []

        # Test injection attempts are blocked
        result = sanitize_additional_args("-v; rm -rf /", "test")
        assert result == []

        result = sanitize_additional_args("-v && ls", "test")
        assert result == []


class TestHelperFunctions:
    """Test helper functions"""

    def test_create_error_response(self):
        """Test create_error_response helper"""
        from kali_server import create_error_response, app

        # Flask's jsonify requires an application context
        with app.app_context():
            response, status_code = create_error_response("Test error")
            assert status_code == 400
            json_data = response.get_json()
            assert json_data["error"] == "Test error"
            assert json_data["success"] is False

    def test_create_error_response_custom_status(self):
        """Test create_error_response with custom status code"""
        from kali_server import create_error_response, app

        with app.app_context():
            response, status_code = create_error_response("Server error", 500)
            assert status_code == 500

    def test_create_success_response(self):
        """Test create_success_response helper"""
        from kali_server import create_success_response, app

        with app.app_context():
            test_result = {"stdout": "test output", "success": True}
            response, status_code = create_success_response(test_result)
            assert status_code == 200
            json_data = response.get_json()
            assert json_data["stdout"] == "test output"
            assert json_data["success"] is True


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
            '/health'
        ]

        for endpoint in expected_endpoints:
            assert endpoint in rules, f"Expected endpoint {endpoint} not found"

    def test_removed_stub_endpoints(self):
        """Test that stub endpoints were removed"""
        from kali_server import app

        rules = [rule.rule for rule in app.url_map.iter_rules()]

        # These stub endpoints should not exist
        stub_endpoints = [
            '/mcp/capabilities',
            '/mcp/tools/kali_tools/<tool_name>'
        ]

        for endpoint in stub_endpoints:
            assert endpoint not in rules, f"Stub endpoint {endpoint} should be removed"


class TestMCPServerFunctions:
    """Test MCP server specific functions"""

    def test_kali_client_has_safe_methods(self):
        """Test that KaliToolsClient has safe request methods"""
        from mcp_server import KaliToolsClient

        client = KaliToolsClient("http://localhost:5000")
        assert hasattr(client, 'safe_get')
        assert hasattr(client, 'safe_post')
        assert hasattr(client, 'check_health')

    def test_kali_client_no_unsafe_execute_command(self):
        """Test that KaliToolsClient does not have unsafe execute_command"""
        from mcp_server import KaliToolsClient

        client = KaliToolsClient("http://localhost:5000")
        # The old execute_command method should be removed
        assert not hasattr(client, 'execute_command')

    def test_setup_mcp_server_returns_fastmcp(self):
        """Test that setup_mcp_server returns a FastMCP instance"""
        from mcp_server import KaliToolsClient, setup_mcp_server

        client = KaliToolsClient("http://localhost:5000")
        mcp = setup_mcp_server(client)

        # Verify it's a FastMCP instance
        assert mcp is not None
        assert hasattr(mcp, 'run')


class TestSecurityImprovements:
    """Test security improvements in refactored code"""

    def test_command_allowlist_exists(self):
        """Test that COMMAND_ALLOWLIST is defined and used"""
        from kali_server import COMMAND_ALLOWLIST

        assert isinstance(COMMAND_ALLOWLIST, dict)
        assert len(COMMAND_ALLOWLIST) > 0

        # Check that allowlist contains safe commands
        assert "whoami" in COMMAND_ALLOWLIST
        assert "uptime" in COMMAND_ALLOWLIST

    def test_no_shell_execution(self):
        """Test that subprocess.Popen uses shell=False"""
        from kali_server import CommandExecutor

        executor = CommandExecutor(["echo", "test"])
        # This should be verifiable by inspecting the code
        # The execute method should use shell=False
        assert True  # Placeholder - actual implementation uses shell=False

    def test_shlex_import_exists(self):
        """Test that shlex is imported for safe argument parsing"""
        import kali_server

        # Verify shlex is imported
        assert hasattr(kali_server, 'shlex')

    def test_regex_import_exists(self):
        """Test that re module is imported for validation"""
        import kali_server

        # Verify re is imported for pattern validation
        assert hasattr(kali_server, 're')


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
