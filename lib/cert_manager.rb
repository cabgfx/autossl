require "fileutils"
require_relative "safe_path"
require_relative "secure_command"

class CertManager
  class Error < StandardError; end

  VALID_DOMAIN_REGEX = /\A[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}\z/i

  def initialize(site, ca_file, ca_key, ssl_dir)
    @site = validate_domain!(site)
    @ssl_dir = validate_ssl_dir!(ssl_dir)
    @ca_file = validate_ca_file!(ca_file)
    @ca_key = validate_ca_key!(ca_key)
  end

  def generate_certificates
    SafePath.secure_mkdir(@ssl_dir, mode: 0o700)

    # Generate all certificate files within the SSL directory
    Dir.chdir(@ssl_dir) do
      generate_private_key
      generate_csr
      create_ext_file
      generate_certificate
    end
  rescue => e
    cleanup_failed_generation
    raise Error, "Certificate generation failed: #{e.message}"
  end

  private

  def validate_domain!(domain)
    unless domain.is_a?(String) && domain.match?(VALID_DOMAIN_REGEX)
      raise Error, "Invalid domain name: #{domain}"
    end
    SecureCommand.escape_string(domain)
  end

  def validate_ssl_dir!(dir)
    path = Pathname.new(dir).expand_path
    SafePath.validate_path(path)
    path.to_s
  end

  def validate_ca_file!(file)
    path = Pathname.new(file).expand_path
    unless path.file? && path.readable?
      raise Error, "CA file is not accessible: #{file}"
    end
    path.to_s
  end

  def validate_ca_key!(key)
    path = Pathname.new(key).expand_path
    unless path.file? && path.readable?
      raise Error, "CA key is not accessible: #{key}"
    end
    path.to_s
  end

  def generate_private_key
    key_file = "#{@site}.key"
    SecureCommand.openssl(
      "genrsa",
      "-out", key_file,
      "2048"
    )
    File.chmod(0o600, key_file)
  end

  def generate_csr
    SecureCommand.openssl(
      "req",
      "-new",
      "-key", "#{@site}.key",
      "-out", "#{@site}.csr",
      "-subj", "/CN=#{@site}/emailAddress=example@example.com"
    )
  end

  def create_ext_file
    ext_content = <<~EXT
      authorityKeyIdentifier=keyid,issuer
      basicConstraints=CA:FALSE
      keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
      subjectAltName = @alt_names

      [alt_names]
      DNS.1 = #{@site}
    EXT

    SafePath.secure_write(
      "#{@site}.ext",
      ext_content,
      mode: 0o600
    )
  end

  def generate_certificate
    SecureCommand.openssl(
      "x509",
      "-req",
      "-in", "#{@site}.csr",
      "-CA", @ca_file,
      "-CAkey", @ca_key,
      "-CAcreateserial",
      "-out", "#{@site}.crt",
      "-days", "825",
      "-sha256",
      "-extfile", "#{@site}.ext"
    )
  end

  def cleanup_failed_generation
    # Clean up any partially generated files
    Dir.glob(File.join(@ssl_dir, "#{@site}.*")).each do |file|
      File.unlink(file) if File.file?(file)
    rescue => e
      warn "Warning: Failed to clean up file #{file}: #{e.message}"
    end
  end
end
