#!/usr/bin/env python3
"""
Basic unit tests for MCP Kali Server

These tests verify core functionality of the server components.
"""

import os
import sys

import pytest

# Add parent directory to path to import modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


class TestKaliServerImports:
    """Test that server modules can be imported"""

    def test_import_kali_server(self):
        """Test that kali_server module can be imported"""
        try:
            import kali_server

            assert hasattr(kali_server, "app")
            assert hasattr(kali_server, "CommandExecutor")
        except ImportError as e:
            pytest.fail(f"Failed to import kali_server: {e}")

    def test_import_mcp_server(self):
        """Test that mcp_server module can be imported"""
        try:
            import mcp_server

            assert hasattr(mcp_server, "KaliToolsClient")
            assert hasattr(mcp_server, "setup_mcp_server")
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


class TestCommandExecutor:
    """Test CommandExecutor class"""

    def test_command_executor_init(self):
        """Test CommandExecutor initialization"""
        from kali_server import CommandExecutor

        executor = CommandExecutor(["echo", "test"], timeout=10)
        assert executor.command == ["echo", "test"]
        assert executor.timeout == 10
        assert executor.return_code is None


class TestAPIEndpoints:
    """Test API endpoint configurations"""

    def test_health_endpoint_exists(self):
        """Test that health endpoint is registered"""
        from kali_server import app

        # Check that the /health route exists
        rules = [rule.rule for rule in app.url_map.iter_rules()]
        assert "/health" in rules

    def test_api_tool_endpoints_exist(self):
        """Test that tool endpoints are registered"""
        from kali_server import app

        rules = [rule.rule for rule in app.url_map.iter_rules()]

        # Check for key tool endpoints
        expected_endpoints = ["/api/tools/nmap", "/api/tools/gobuster", "/api/tools/nikto", "/api/command"]

        for endpoint in expected_endpoints:
            assert endpoint in rules, f"Expected endpoint {endpoint} not found"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
