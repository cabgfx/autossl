require "fileutils"
require_relative "safe_path"
require_relative "secure_command"
require_relative "safety_checks"
require "logger"

class CertManager
  class Error < StandardError; end

  VALID_DOMAIN_REGEX = /\A[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}\z/i
  REQUIRED_SPACE = 1024 * 1024  # 1MB should be plenty for certificates

  # Initialize logger
  def self.logger
    @logger ||= Logger.new(File.join(SafePath.data_home, "autossl.log"))
  end

  def initialize(site, ca_file, ca_key, ssl_dir)
    @site = validate_domain!(site)
    @ssl_dir = validate_ssl_dir!(ssl_dir)
    @ca_file = validate_ca_file!(ca_file)
    @ca_key = validate_ca_key!(ca_key)
    @logger = self.class.logger
  end

  def generate_certificates
    # Ensure SSL directory exists and is secure
    SafePath.secure_mkdir(@ssl_dir, mode: 0o700)
    SafetyChecks.validate_available_space!(@ssl_dir, REQUIRED_SPACE)

    # Generate all certificate files within the SSL directory
    generate_private_key
    generate_csr
    create_ext_file
    generate_certificate

    @logger.info("Certificate generation completed for #{@site}")
  rescue => e
    cleanup_failed_generation
    @logger.error("Certificate generation failed: #{e.message}")
    raise Error, "Certificate generation failed: #{e.message}"
  end

  private

  def validate_domain!(domain)
    unless domain.is_a?(String) && domain.match?(VALID_DOMAIN_REGEX)
      @logger.error("Invalid domain name: #{domain}")
      raise Error, "Invalid domain name: #{domain}"
    end
    # Additional sanitization for extra safety
    SafetyChecks.sanitize_filename(domain)
  end

  def validate_ssl_dir!(dir)
    path = Pathname.new(dir).expand_path
    SafePath.validate_path(path)

    # Additional security checks
    if File.exist?(path)
      unless SafetyChecks.secure_directory?(path)
        @logger.error("SSL directory exists but has insecure permissions: #{path}")
        raise Error, "SSL directory exists but has insecure permissions: #{path}"
      end
      SafetyChecks.validate_ownership!(path)
    end

    path.to_s
  end

  def validate_ca_file!(file)
    path = Pathname.new(file).expand_path
    unless path.file? && path.readable?
      @logger.error("CA file is not accessible: #{file}")
      raise Error, "CA file is not accessible: #{file}"
    end

    # Additional security checks
    unless SafetyChecks.secure_file?(path)
      @logger.error("CA file has insecure permissions: #{file}")
      raise Error, "CA file has insecure permissions: #{file}"
    end
    SafetyChecks.check_symlink!(path)

    path.to_s
  end

  def validate_ca_key!(key)
    path = Pathname.new(key).expand_path
    unless path.file? && path.readable?
      @logger.error("CA key is not accessible: #{key}")
      raise Error, "CA key is not accessible: #{key}"
    end

    # Additional security checks
    unless SafetyChecks.secure_file?(path)
      @logger.error("CA key has insecure permissions: #{key}")
      raise Error, "CA key has insecure permissions: #{key}"
    end
    SafetyChecks.check_symlink!(path)

    path.to_s
  end

  def generate_private_key
    key_file = "#{@site}.key"
    key_path = File.join(@ssl_dir, key_file)

    # Pre-flight checks
    SafetyChecks.validate_in_directory!(key_path, @ssl_dir)

    logger.info("Generating private key: #{key_path}")
    SecureCommand.openssl(
      "genrsa",
      "-out", key_file,
      "2048",
      working_dir: @ssl_dir
    )

    # Verify the generated file
    File.chmod(0o600, key_path)
    SafetyChecks.validate_permissions!(key_path, 0o600)
    SafetyChecks.validate_ownership!(key_path)
  end

  def generate_csr
    # Pre-flight checks
    csr_path = File.join(@ssl_dir, "#{@site}.csr")
    key_path = File.join(@ssl_dir, "#{@site}.key")

    SafetyChecks.validate_in_directory!(csr_path, @ssl_dir)
    SafetyChecks.validate_in_directory!(key_path, @ssl_dir)

    logger.info("Generating CSR: #{csr_path}")
    SecureCommand.openssl(
      "req",
      "-new",
      "-key", "#{@site}.key",
      "-out", "#{@site}.csr",
      "-subj", "/CN=#{@site}/emailAddress=example@example.com",
      working_dir: @ssl_dir
    )

    # Verify the generated file
    File.chmod(0o600, csr_path)
    SafetyChecks.validate_permissions!(csr_path, 0o600)
    SafetyChecks.validate_ownership!(csr_path)
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

    ext_path = File.join(@ssl_dir, "#{@site}.ext")
    SafetyChecks.validate_in_directory!(ext_path, @ssl_dir)

    logger.info("Creating extension file: #{ext_path}")
    SafePath.secure_write(
      ext_path,
      ext_content,
      mode: 0o600,
      base_dir: @ssl_dir
    )
  end

  def generate_certificate
    # Pre-flight checks
    cert_path = File.join(@ssl_dir, "#{@site}.crt")
    csr_path = File.join(@ssl_dir, "#{@site}.csr")
    ext_path = File.join(@ssl_dir, "#{@site}.ext")

    [cert_path, csr_path, ext_path].each do |path|
      SafetyChecks.validate_in_directory!(path, @ssl_dir)
    end

    logger.info("Generating certificate: #{cert_path}")
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
      "-extfile", "#{@site}.ext",
      working_dir: @ssl_dir
    )

    # Verify the generated file
    File.chmod(0o600, cert_path)
    SafetyChecks.validate_permissions!(cert_path, 0o600)
    SafetyChecks.validate_ownership!(cert_path)
  end

  def cleanup_failed_generation
    # Clean up any partially generated files
    pattern = File.join(@ssl_dir, "#{@site}.*")

    # SAFETY: Validate ssl_dir again before cleanup
    ssl_real_path = Pathname.new(@ssl_dir).realpath.to_s

    logger.warn("Cleaning up failed certificate generation files in #{@ssl_dir}")
    Dir.glob(pattern).each do |file|
      file_real_path = Pathname.new(file).realpath

      # Multiple safety checks before deletion
      next unless File.file?(file_real_path)                    # Must be a file
      next unless file_real_path.to_s.start_with?(ssl_real_path)  # Must be in ssl_dir
      next unless File.owned?(file_real_path)                   # Must be owned by us
      next unless file_real_path.basename.to_s.match?(/\A#{Regexp.escape(@site)}\..*\z/) # Must match pattern exactly

      File.unlink(file_real_path)
      logger.info("Removed partially generated file: #{file_real_path}")
    rescue => e
      logger.warn("Failed to clean up file #{file}: #{e.message}")
    end
  end
end
