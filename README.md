# AutoSSL

## Overview

AutoSSL is a Ruby-based command-line tool designed to automate the creation of self-signed SSL certificates for local development environments. By leveraging OpenSSL and the Thor gem, this tool simplifies the process of generating private keys, Certificate Signing Requests (CSRs), and SSL certificates, adhering to a consistent format for subdomains.

## Features

- Automated generation of private keys, CSRs, and self-signed certificates
- Customizable subdomain and top-level domain (TLD) configuration
- Easy integration with local development environments
- Utilizes the robust Thor gem for CLI functionality

## Prerequisites

- Ruby 3.1 or higher
- OpenSSL installed on your system
- A pre-existing local CA (Certificate Authority) *— NOTE: This a temporary requirement, to allow v.0.1 to ship — soon, AutoSSL handles this step, too.*

## Installation

1. Install the Thor gem:
    ```bash
    gem install thor
    ```

2. Clone this repository:
    ```bash
    git clone https://github.com/yourusername/auto_ssl.git
    cd auto_ssl
    ```

## Usage

Navigate to the directory where you have cloned the repository and run the script using the following syntax:

```bash
ruby auto_ssl.rb generate DOMAIN TLD
```

For example, to generate a certificate for `dev.example.com`:

```bash
ruby auto_ssl.rb generate example com
```

## Directory Structure

```
auto_ssl/
│
├── lib/
│   └── cert_manager.rb
├── spec/
│   ├── spec_helper.rb
│   ├── auto_ssl_spec.rb
│   └── cert_manager_spec.rb
├── auto_ssl.rb
├── README.md
└── LICENSE
```

## How It Works

1. **Generate Private Key:**
    - Uses OpenSSL to create a 2048-bit RSA private key.
    ```bash
    openssl genrsa -out dev.example.com.key 2048
    ```

2. **Generate CSR:**
    - Generates a Certificate Signing Request (CSR) using the private key. It automatically fills in the necessary fields.
    ```bash
    openssl req -new -key dev.example.com.key -out dev.example.com.csr -subj '/CN=dev.example.com/emailAddress=example@example.com'
    ```

3. **Create `.ext` File:**
    - Generates an extension configuration file required for creating the certificate.
    ```text
    authorityKeyIdentifier=keyid,issuer
    basicConstraints=CA:FALSE
    keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
    subjectAltName = @alt_names

    [alt_names]
    DNS.1 = dev.example.com
    ```

4. **Generate Certificate:**
    - Uses the local CA to create a self-signed certificate.
    ```bash
    openssl x509 -req -in dev.example.com.csr -CA <yourCA>.pem -CAkey <yourCA>.key -CAcreateserial -out dev.example.com.crt -days 825 -sha256 -extfile dev.example.com.ext
    ```



## Configuration

By default, the script operates within the `~/ssl` directory and expects a local CA named `<yourCA>.pem` and `<yourCA>.key`. You can adjust these settings by modifying the script as needed.

## Contributing

We welcome contributions from the community! Please follow these steps:

1. Fork the repository.
2. Create a new feature branch (`git checkout -b feature-branch`).
3. Commit your changes (`git commit -am 'Add new feature'`).
4. Push to the branch (`git push origin feature-branch`).
5. Create a new Pull Request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

Special thanks to all the contributors and the Ruby community for their support and inspiration.

## Contact

For any inquiries or support, please open an issue on GitHub or contact the project maintainers.
