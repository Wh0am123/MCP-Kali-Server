# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Systems Cartographer Tool**: New modular agent for mapping complex systems, dependencies, and failure modes
  - Network topology mapping with multiple depth levels
  - Service dependency analysis
  - Process tree mapping
  - Filesystem and mount point analysis
  - Comprehensive system mapping mode
  - Failure mode analysis with resilience recommendations
- API endpoint `/api/tools/cartographer` for systems mapping
- MCP tool `systems_cartographer_map` for AI-assisted infrastructure analysis
- Tests for Systems Cartographer functionality
- Documentation for Systems Cartographer in README
- Initial release preparation
- Comprehensive security documentation
- Environment configuration template (.env.example)
- Proper .gitignore for Python projects
- CHANGELOG.md for version tracking

### Changed
- Code style improvements and linting fixes
- Enhanced documentation in README.md with Systems Cartographer examples
- Updated test suite to include cartographer endpoint verification

### Security
- Added input validation guidelines
- Documented security best practices
- Added security scanning in CI pipeline

## [0.1.0] - TBD

### Added
- MCP Server integration with Kali Linux tools
- API endpoints for security tools (nmap, gobuster, nikto, sqlmap, etc.)
- Command execution framework with timeout management
- Health check endpoint
- CI/CD pipeline with GitHub Actions
- CodeQL security scanning
- Docker support
- Comprehensive README with installation and usage instructions

### Features
- AI-assisted penetration testing capabilities
- Integration with MCP clients (Claude Desktop, 5ire)
- Support for multiple security tools:
  - Network scanning (nmap)
  - Directory enumeration (gobuster, dirb)
  - Web vulnerability scanning (nikto, sqlmap, wpscan)
  - Password cracking (hydra, john)
  - SMB enumeration (enum4linux)
  - Metasploit integration

### Security
- MIT License
- Educational and ethical testing purpose only
- Command execution with proper timeout handling
- Logging and monitoring capabilities

[Unreleased]: https://github.com/canstralian/forked-u-MCP-Kali-Server/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/canstralian/forked-u-MCP-Kali-Server/releases/tag/v0.1.0
