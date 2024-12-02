# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-01-XX

### Added
- XDG Base Directory support for configuration and certificate storage
- Platform-specific paths for macOS and Linux
- Comprehensive security measures for file operations
- Safe YAML parsing with type verification
- Validated OpenSSL command execution
- Atomic file operations
- Strict path validation and sanitization
- Cross-platform OpenSSL path detection

### Changed
- Configuration file moved to platform-specific locations
- Stricter input validation for domains and paths
- More restrictive file permissions (0600/0700)
- Improved error handling and messages
- Standardized code style and formatting

### Security
- Protected against path traversal attacks
- Implemented secure file operations
- Added strict permission controls
- Added input validation and sanitization
- Added safe YAML parsing
- Added command injection protection

### Migration
Users upgrading from versions before 1.0.0 will need to:
1. Run `init` command to migrate existing configuration
2. Update any scripts referencing the old config location
3. Ensure proper file permissions for CA files

## [0.1.0] - Initial Release

- Basic SSL certificate generation functionality
- Configuration file support
- Command-line interface
