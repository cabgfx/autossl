# AutoSSL

A secure, industrial-grade SSL certificate management tool with comprehensive safety measures and filesystem protection.

## Security Features

- Comprehensive path validation and sanitization
- Secure atomic file operations
- Process isolation and resource limits
- Real-time filesystem monitoring
- Prevention of privileged execution
- Enhanced certificate validation
- Secure memory handling
- Triple-overwrite secure deletion
- Protection against directory traversal
- System directory protection

## Requirements

- Ruby >= 3.2.0
- OpenSSL >= 3.1.0
- Non-root user account
- Dedicated certificate directory
- Minimum 512MB available memory
- Minimum 10MB free disk space

## Installation

```bash
gem install autossl
```

## Usage

### Basic Certificate Generation

```ruby
autossl generate example.com com
```

### Options

- `--force, -f`: Force overwrite existing certificates
- `--ca-file PATH`: Path to CA certificate
- `--ca-key PATH`: Path to CA private key
- `--ssl-dir PATH`: Custom SSL certificate output directory

## Security Considerations

### Directory Safety

The tool implements strict safeguards:
- Prevents operations in system directories
- Validates all paths against directory traversal
- Monitors for unauthorized file changes
- Ensures atomic operations

### Process Security

- Prevents execution as root
- Sets strict resource limits
- Prevents process forking
- Monitors system resource usage

### File Operations

- Atomic write operations
- Secure temporary file handling
- Triple-overwrite secure deletion
- File locking for concurrent access

### Certificate Security

- Strict X.509 validation
- Enhanced CSR validation
- Strong key usage enforcement
- Comprehensive extension validation

## Configuration

Default configuration is created at `~/.config/autossl/config.yml`:

```yaml
ssl_dir: ~/.local/share/autossl/certificates
ca_file: null
ca_key: null
memory_limit: 512
cpu_limit: 80
operation_rate: 100
timeout: 30
log_level: info
security:
  min_key_size: 4096
  cert_validity_days: 365
  require_strong_entropy: true
  openssl_security_level: 2
```

## Best Practices

1. **Directory Setup**:
   - Use a dedicated directory for certificates
   - Ensure proper directory permissions (0700)
   - Keep backups of important certificates

2. **Security**:
   - Never run as root
   - Use strong passwords for private keys
   - Regularly rotate certificates
   - Monitor log files for unauthorized access

3. **Resource Management**:
   - Monitor available disk space
   - Check system memory usage
   - Review process limits
   - Monitor CPU usage

## Error Handling

The tool provides detailed error messages and logging:

```
~/.local/share/autossl/autossl.log
```

Common error categories:
- SecurityError: Security violations
- ValidationError: Input/parameter validation failures
- ResourceError: System resource issues
- GenerationError: Certificate generation failures

## Contributing

1. Fork the repository
2. Create your feature branch
3. Add tests for new features
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Support

- Issue Tracker: [GitHub Issues](https://github.com/username/autossl/issues)
- Documentation: [Wiki](https://github.com/username/autossl/wiki)

## Acknowledgments

- OpenSSL team for cryptographic foundations
- Ruby community for excellent tools and libraries
- Security researchers for valuable feedback
