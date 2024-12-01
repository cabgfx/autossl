# AutoSSL

A secure, cross-platform tool for generating self-signed SSL certificates with proper domain validation.

## Features

- 🔒 Secure certificate generation with OpenSSL
- 🌍 Cross-platform support (macOS and Linux)
- 🏠 XDG Base Directory compliance
- 🛡️ Comprehensive security measures
- 🔐 Safe configuration management
- 📁 Platform-appropriate file storage

## Prerequisites

- Ruby 2.6 or higher
- OpenSSL (system installation or via package manager)
- Write permissions for config directory

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

This will create a certificate for `dev.example.com`

## Configuration

AutoSSL stores its configuration in platform-specific locations:

- **Linux**: `~/.config/autossl/config.yml`
- **macOS**: `~/Library/Application Support/autossl/config.yml`
- If `XDG_CONFIG_HOME` is set, it will be used instead

Certificates are stored in:
- **Linux**: `~/.local/share/autossl/certificates`
- **macOS**: `~/Library/Application Support/autossl/certificates`
- If `XDG_DATA_HOME` is set, it will be used instead

### Configuration Options

- `ca_file`: Path to your CA certificate file
- `ca_key`: Path to your CA private key
- `ssl_dir`: Directory for generated certificates (optional)

## Security Features

AutoSSL implements several security measures:

- Strict path validation and sanitization
- Secure file operations with proper permissions
- Protected against path traversal attacks
- Safe YAML parsing with type verification
- Validated OpenSSL command execution
- Atomic file operations

## Command Reference

### Initialize Configuration

```bash
autossl init
```

This interactive command will:
1. Create necessary directories with secure permissions
2. Guide you through configuration setup
3. Validate all provided paths
4. Store configuration securely

### Generate Certificate

```bash
autossl generate DOMAIN TLD [options]
```

Options:
- `--ca-file PATH`: Override CA certificate file location
- `--ca-key PATH`: Override CA private key location
- `--ssl-dir PATH`: Override certificate output directory

Example:

```bash
autossl generate myapp dev --ssl-dir /custom/path/certs
```

## File Permissions

AutoSSL enforces secure file permissions:
- Configuration files: `0600` (user read/write only)
- Certificate files: `0600` (user read/write only)
- Directories: `0700` (user read/write/execute only)

Ensure your CA files have appropriate permissions before use.

## Troubleshooting

### Common Issues

1. **OpenSSL not found**
   - Ensure OpenSSL is installed
   - Check if OpenSSL is in your PATH
   - Supported locations:
     - `/usr/bin/openssl`
     - `/usr/local/bin/openssl`
     - `/opt/homebrew/bin/openssl` (Apple Silicon)
     - Custom locations via PATH

2. **Permission Denied**
   - Check file/directory ownership
   - Verify required permissions
   - Ensure parent directories are writable

3. **Configuration Issues**
   - Run `autossl init` to reset configuration
   - Check file permissions
   - Verify paths exist and are accessible

### Error Messages

- "CA file and CA key must be specified": Run `autossl init` to configure
- "Invalid domain": Domain contains invalid characters
- "Path escapes base directory": Attempted path traversal detected
- "Could not find OpenSSL executable": OpenSSL not in expected locations

## Migration from Previous Versions

If upgrading from a version before 1.0.0:

1. Configuration files have moved to new locations
2. Run `autossl init` to migrate existing configuration
3. Update any scripts referencing old config locations
4. Verify file permissions match new requirements

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

This project has been significantly enhanced through the use of Cursor's AI pair programming system, with human oversight and approval.
