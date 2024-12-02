# AutoSSL

A mission-critical, industrial-grade tool for managing self-signed SSL certificates with comprehensive safety guarantees.

## Core Features

- 🔒 **Industrial-Grade Security**
  - Comprehensive path validation
  - Strict permission enforcement
  - Resource exhaustion prevention
  - Symlink attack protection

- 🛡️ **Mission-Critical Reliability**
  - Transactional state management
  - Crash recovery mechanisms
  - Circuit breaker pattern
  - Resource monitoring

- 🌍 **Cross-Platform Excellence**
  - Native API integration
  - Platform-specific optimizations
  - Graceful fallbacks
  - Consistent behavior

- 📊 **Advanced Monitoring**
  - Detailed logging
  - Resource usage tracking
  - Operation statistics
  - Health monitoring

## System Requirements

- Ruby 2.6 or higher
- OpenSSL (system installation)
- Write permissions for config directory
- Minimum 512MB available memory
- Sufficient disk space (10MB minimum)

## Installation

```bash
gem install auto_ssl
```

## Quick Start

1. Initialize configuration:

```bash
autossl init
```

2. Generate a certificate:

```bash
autossl generate example com
```

## Safety Guarantees

AutoSSL implements multiple layers of safety measures:

### Resource Protection
- Memory usage monitoring
- CPU utilization tracking
- Disk space verification
- Resource limit enforcement

### State Management
- Transactional operations
- Automatic crash recovery
- State corruption prevention
- Atomic file operations

### Security Measures
- Path traversal prevention
- Symlink attack protection
- Strict permission enforcement
- Resource exhaustion prevention

### Reliability Features
- Circuit breaker pattern
- Rate limiting
- Operation timeouts
- Automatic cleanup

## Configuration

### Locations
AutoSSL follows XDG Base Directory Specification:

```
Config: $XDG_CONFIG_HOME/autossl/config.yml
Data:   $XDG_DATA_HOME/autossl/
Logs:   $XDG_DATA_HOME/autossl/autossl.log
State:  $XDG_DATA_HOME/autossl/safety_checks_state.yml
```

### Settings

```yaml
# config.yml
ssl_dir: ~/.local/share/autossl/certificates
ca_file: /path/to/ca.crt
ca_key: /path/to/ca.key
```

### Resource Limits

```yaml
# Resource limits (adjustable in config)
memory_limit: 512MB
cpu_limit: 80%
operation_rate: 100/second
timeout: 30 seconds
```

## Security Model

### File Operations
- All file operations are atomic
- Strict permission checking (600 for files, 700 for directories)
- Path validation and sanitization
- Symlink protection

### State Management
- Transactional state changes
- Crash recovery mechanisms
- Corruption prevention
- Automatic rollback

### Resource Management
- Memory usage monitoring
- CPU utilization tracking
- Disk space verification
- Operation rate limiting

## Error Handling

### Circuit Breaker
Automatically prevents cascading failures:
- Trips after 5 consecutive failures
- 60-second cooling period
- Automatic state recovery
- Operation isolation

### Resource Exhaustion
Prevents system overload:
- Memory usage limits
- CPU utilization caps
- Disk space requirements
- Operation rate limits

### Recovery Mechanisms
- Automatic crash recovery
- State rollback capabilities
- Resource cleanup
- Logging and monitoring

## Monitoring

### Logging
Comprehensive logging at `$XDG_DATA_HOME/autossl/autossl.log`:
- Operation tracking
- Error reporting
- Resource usage
- State changes

### Health Checks
- Memory usage monitoring
- CPU utilization tracking
- Disk space verification
- Operation success rates

## Command Reference

### Initialize

```bash
autossl init [--force]
```
Creates necessary directories and configuration with proper permissions.

### Generate Certificate

```bash
autossl generate DOMAIN TLD [options]
```

Options:
- `--ca-file PATH`: CA certificate location
- `--ca-key PATH`: CA private key location
- `--ssl-dir PATH`: Certificate output directory

### Verify Configuration

```bash
autossl verify
```
Checks configuration and system requirements.

## Troubleshooting

### Common Issues

1. **Resource Limits**
   - Increase available memory
   - Reduce CPU load
   - Free disk space
   - Adjust rate limits

2. **Permission Errors**
   - Check file ownership
   - Verify directory permissions
   - Ensure proper umask
   - Check parent directory permissions

3. **State Recovery**
   - Check transaction logs
   - Verify state file integrity
   - Review operation logs
   - Clear stale locks

### Error Messages

Detailed error messages with solutions:

- "Circuit breaker open": Wait for cooling period or check logs
- "Resource limit exceeded": Free resources or adjust limits
- "Permission denied": Check file/directory permissions
- "State corruption detected": Review transaction logs

## Migration Guide

### From Previous Versions

1. Backup existing certificates and configuration
2. Update to latest version
3. Run `autossl init --force`
4. Verify configuration
5. Test certificate generation

### Configuration Changes

1. New resource limits
2. Enhanced security settings
3. Updated file locations
4. Additional monitoring options

## Contributing

Contributions welcome! Please read our contributing guidelines and submit pull requests.

## License

MIT License - see LICENSE file for details.

## Acknowledgments

This project implements industrial-grade safety measures through the use of Cursor's AI pair programming system, with rigorous human oversight and validation.
