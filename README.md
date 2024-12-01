# AutoSSL

AutoSSL is a Ruby-based command-line tool designed to automate the creation of self-signed SSL certificates for local development environments. By simplifying the SSL certificate generation process, AutoSSL enables developers to set up secure local servers with ease, enhancing both development workflows and testing environments.

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
  - [Initializing Configuration](#initializing-configuration)
  - [Generating SSL Certificates](#generating-ssl-certificates)
- [Directory Structure](#directory-structure)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Automated Certificate Generation**: Quickly generate private keys, CSRs, extension files, and self-signed SSL certificates.
- **Configurable Paths**: Customize paths to Certificate Authority (CA) files and SSL directories.
- **Interactive Setup**: Easy initialization of configuration through interactive prompts.
- **RSpec Integration**: Comprehensive test suite ensuring reliability and stability.
- **Thor Integration**: Utilizes the Thor gem for robust command-line interface management.

## Prerequisites

- **Ruby**: Ensure you have Ruby installed (version 2.5 or higher is recommended).
- **OpenSSL**: Required for generating keys, CSRs, and certificates.
- **Bundler**: To manage Ruby gem dependencies.

## Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/yourusername/auto_ssl.git
   cd auto_ssl
   ```

2. **Install Dependencies**

   Use Bundler to install the necessary Ruby gems:

   ```bash
   bundle install
   ```

3. **Set Up Executable (Optional)**

   To use `auto_ssl` as a global command, you can create a symbolic link:

   ```bash
   sudo ln -s $(pwd)/auto_ssl.rb /usr/local/bin/auto_ssl
   chmod +x /usr/local/bin/auto_ssl
   ```

   > **Note**: Adjust the path `/usr/local/bin/` as needed based on your system.

## Configuration

AutoSSL uses a YAML configuration file named `.autosslrc` to store paths to the CA files and the SSL directory. This configuration can be initialized and managed using the tool's `init` command.

### Initializing Configuration

Run the following command to create or update the `.autosslrc` file:

```bash
ruby auto_ssl.rb init
```

You will be prompted to enter the following details:

1. **Path to the CA File**

   Enter the absolute path to your CA certificate file (`yourCA.pem`).

2. **Path to the CA Key**

   Enter the absolute path to your CA key file (`yourCA.key`).

3. **Path to the SSL Directory**

   Specify the directory where SSL certificates will be stored (default is `./build`).

#### Example Interaction

```
Enter the path to the CA file: /home/user/CA/yourCA.pem
Enter the path to the CA key: /home/user/CA/yourCA.key
Enter the path to the SSL directory: ./build
Configuration saved to .autosslrc
```

### Example `.autosslrc` Configuration

```yaml
ca_file: "/home/user/CA/yourCA.pem"
ca_key: "/home/user/CA/yourCA.key"
ssl_dir: "./build"
```

> **Best Practices**:
>
> - Use absolute paths to avoid ambiguities related to the current working directory.
> - Ensure that the CA files (`.pem` and `.key`) are secured and have appropriate permissions.

## Usage

AutoSSL provides two primary commands: `init` and `generate`. Below are detailed instructions and examples for each.

### Initializing Configuration

Before generating SSL certificates, initialize the configuration using the `init` command:

```bash
ruby auto_ssl.rb init
```

This command sets up the `.autosslrc` file with the necessary paths.

### Generating SSL Certificates

Use the `generate` command to create SSL certificates for your desired domain and top-level domain (TLD).

#### Command Syntax

```bash
ruby auto_ssl.rb generate DOMAIN TLD [options]
```

#### Parameters

- `DOMAIN`: The subdomain for which the SSL certificate will be generated (e.g., `example`).
- `TLD`: The top-level domain (e.g., `com`, `local`).

#### Options

- `--ca_file`: Override the CA file path specified in `.autosslrc`.
- `--ca_key`: Override the CA key path specified in `.autosslrc`.
- `--ssl_dir`: Override the SSL directory path specified in `.autosslrc`.

#### Examples

1. **Basic Certificate Generation**

   Generate an SSL certificate for `dev.example.com` using the paths specified in `.autosslrc`:

   ```bash
   ruby auto_ssl.rb generate example com
   ```

2. **Overriding Configuration Paths**

   Generate an SSL certificate while specifying custom CA files and SSL directory:

   ```bash
   ruby auto_ssl.rb generate example com --ca_file /custom/path/yourCA.pem --ca_key /custom/path/yourCA.key --ssl_dir ./custom_build
   ```

#### Output

Upon successful execution, the following files will be generated in the specified SSL directory (`ssl_dir`):

- `dev.example.com.key`: Private key.
- `dev.example.com.csr`: Certificate Signing Request.
- `dev.example.com.ext`: Extension configuration file.
- `dev.example.com.crt`: Self-signed SSL certificate.

#### Example Command Execution

```bash
ruby auto_ssl.rb generate example com
```

```
Generating private key...
Generating CSR...
Creating extension file...
Generating self-signed certificate...
Certificates generated successfully in ./build
```

## Directory Structure

Here's an overview of the project's directory structure:

```
auto_ssl/
├── lib/
│   └── cert_manager.rb          # Handles SSL certificate generation logic
├── spec/
│   ├── cert_manager_spec.rb     # Tests for CertManager
│   ├── auto_ssl_spec.rb         # Tests for AutoSSL
│   └── spec_helper.rb           # RSpec configuration
├── .autosslrc                   # YAML configuration file
├── .gitignore                   # Git ignore rules
├── .ruby-version                # Specifies Ruby version
├── .rspec                       # RSpec configuration
├── Gemfile                      # Ruby gem dependencies
├── LICENSE                      # License information
├── README.md                    # Project documentation
└── auto_ssl.rb                  # Main executable script
```

## Testing

AutoSSL includes a comprehensive test suite using RSpec to ensure reliability and correctness of its functionalities.

### Running Tests

1. **Ensure Dependencies Are Installed**

   If not already done, install the dependencies using Bundler:

   ```bash
   bundle install
   ```

2. **Execute the Test Suite**

   Run the following command from the project's root directory:

   ```bash
   bundle exec rspec
   ```

### Test Coverage

The test suite covers the following aspects:

- **AutoSSL Command-Line Interface (`auto_ssl_spec.rb`)**
  - Initialization of configuration.
  - Generation of SSL certificates.
  - Handling of command-line options and arguments.

- **Certificate Manager (`cert_manager_spec.rb`)**
  - Generation of private keys, CSRs, extension files, and certificates.
  - File creation and content verification.

## Contributing

Contributions are welcome! Whether it's bug reports, feature requests, or pull requests, your input helps improve AutoSSL.

### How to Contribute

1. **Fork the Repository**

   Click the "Fork" button on the repository page to create your own copy.

2. **Clone Your Fork**

   ```bash
   git clone https://github.com/yourusername/auto_ssl.git
   cd auto_ssl
   ```

3. **Create a New Branch**

   ```bash
   git checkout -b feature/your-feature-name
   ```

4. **Make Your Changes**

   Implement your feature or fix.

5. **Commit Your Changes**

   ```bash
   git commit -m "Add feature: your feature description"
   ```

6. **Push to Your Fork**

   ```bash
   git push origin feature/your-feature-name
   ```

7. **Submit a Pull Request**

   Navigate to the original repository and create a pull request from your fork.

### Code of Conduct

Please adhere to the [Code of Conduct](LICENSE) when contributing to this project.

## License

AutoSSL is released under the [MIT License](LICENSE). See the [LICENSE](LICENSE) file for more details.

---

&copy; Casper Klenz-Kitenge. All rights reserved.

# Acknowledgements

- [Thor Gem](https://github.com/erikhuda/thor) for command-line interface management.
- [OpenSSL](https://www.openssl.org/) for SSL certificate generation.
- [RSpec](https://rspec.info/) for testing framework.

---

*Feel free to reach out for support or with suggestions!*
