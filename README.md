# AutoSSL — local SSL Certificate Generator

## Overview

The SSL Cert Generator is a Ruby-based command-line tool designed to automate the creation of self-signed SSL certificates for local development environments. By leveraging OpenSSL and the Thor gem, this tool simplifies the process of generating private keys, Certificate Signing Requests (CSRs), and SSL certificates, adhering to a consistent format for subdomains.

## Features

- Automated generation of private keys, CSRs, and self-signed certificates
- Customizable subdomain and top-level domain (TLD) configuration
- Easy integration with local development environments
- Utilizes the robust Thor gem for CLI functionality

## Prerequisites

- Ruby 3.1 or higher
- OpenSSL installed on your system
- A pre-existing local CA (Certificate Authority)

## Installation

1. Install the Thor gem:
    ```bash
    gem install thor
    ```

2. Clone this repository:
    ```bash
    git clone https://github.com/yourusername/ssl-cert-generator.git
    cd ssl-cert-generator
    ```

## Usage

Navigate to the directory where you have cloned the repository and run the script using the following syntax:

```bash
ruby ssl_cert_generator.rb generate DOMAIN TLD
```

For example, to generate a certificate for `dev.example.com`:

```bash
ruby ssl_cert_generator.rb generate example com
```

## Directory Structure

```
ssl-cert-generator/
│
├── ssl_cert_generator.rb
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

5. **Move Generated Files:**
    - Moves the generated `.key` and `.crt` files to a designated directory (default: `~/project/ssl`).

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
