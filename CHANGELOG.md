# Changelog

## [2.0.0] - 2023-12-02

### Security Improvements
- Added comprehensive path validation and sanitization
- Implemented secure atomic file operations
- Added process isolation and resource limits
- Added real-time filesystem monitoring
- Prevented execution with elevated privileges
- Enhanced certificate validation with strict X.509 checks
- Added secure memory handling and cleanup
- Implemented triple-overwrite secure deletion
- Added protection against directory traversal attacks
- Added system directory protection

### Added
- New `FileMonitor` class for filesystem integrity checking
- Secure temporary file handling
- Process resource limits
- Enhanced logging with rotation
- Comprehensive error handling
- Force option for certificate regeneration

### Changed
- Improved OpenSSL configuration with stronger security settings
- Enhanced CSR validation
- Enhanced certificate validation
- Improved error messages with detailed information
- Updated dependency constraints

### Fixed
- Fixed potential race conditions in file operations
- Fixed memory leaks in cryptographic operations
- Fixed path traversal vulnerabilities
- Fixed temporary file handling
- Fixed privilege escalation vectors

## [1.0.0] - 2023-12-01

Initial release
