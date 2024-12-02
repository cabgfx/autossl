require "pathname"
require "openssl"
require "fileutils"
require "sys/filesystem"
require "securerandom"
require "etc"
require_relative "safety_checks"
require_relative "secure_command"

class CertificateManager
  include SafetyChecks

  class Error < StandardError; end
  class SecurityError < Error; end
  class GenerationError < Error; end
  class ValidationError < Error; end

  REQUIRED_SPACE = 5 * 1024 * 1024  # 5MB minimum free space
  MAX_GENERATION_ATTEMPTS = 3
  KEY_SIZE = 4096
  CERT_VALIDITY = 365 * 24 * 60 * 60  # 1 year in seconds
  SECURE_HASH = OpenSSL::Digest::SHA384
  SECURE_CIPHER = OpenSSL::Cipher.new("aes-256-gcm")

  # Process and resource limits
  PROCESS_LIMITS = {
    RLIMIT_CPU: 30,     # 30 seconds CPU time
    RLIMIT_NOFILE: 256, # Max file descriptors
    RLIMIT_NPROC: 0,    # Prevent forking
    RLIMIT_FSIZE: 10 * 1024 * 1024  # 10MB max file size
  }.freeze

  def initialize(site, ssl_dir:, force: false)
    @site = validate_site!(site)
    @ssl_dir = validate_and_resolve_path!(ssl_dir)
    @force = force
    @logger = AutoSSL::CLI.logger
    @file_monitor = FileMonitor.new(@ssl_dir)

    # Drop privileges if running as root
    ensure_safe_user!

    # Set process resource limits
    set_process_limits!

    # Ensure all paths are properly contained within ssl_dir
    @key_path = validate_and_resolve_path!(File.join(@ssl_dir, "#{@site}.key"), @ssl_dir)
    @csr_path = validate_and_resolve_path!(File.join(@ssl_dir, "#{@site}.csr"), @ssl_dir)
    @cert_path = validate_and_resolve_path!(File.join(@ssl_dir, "#{@site}.cert"), @ssl_dir)

    # Verify we're not operating on system directories
    verify_safe_directory!(@ssl_dir)

    # Start monitoring for filesystem changes
    @file_monitor.start
  end

  def generate_certificates
    begin
      FileUtils.mkdir_p(@ssl_dir, mode: AutoSSL::CLI::REQUIRED_DIR_MODE)
      check_existing_certificates! unless @force

      # Monitor for changes during the entire operation
      @file_monitor.transaction do
        generate_private_key
        generate_csr
        generate_certificate
      end
    rescue => e
      cleanup_on_error
      raise GenerationError, "Certificate generation failed: #{e.message}"
    ensure
      @file_monitor.stop
    end
  end

  private

  def validate_site!(site)
    raise ValidationError, "Site cannot be nil" if site.nil?
    raise ValidationError, "Site name too long" if site.length > 253
    raise ValidationError, "Invalid site format" unless site.match?(/\A[a-z0-9][a-z0-9.-]*[a-z0-9]\z/i)
    site
  end

  def validate_and_resolve_path!(path, base_dir = nil)
    raise ValidationError, "Path cannot be nil" if path.nil?

    # Convert to absolute path
    absolute_path = File.expand_path(path)
    pathname = Pathname.new(absolute_path)

    # Ensure path is not too long
    validate_path_length!(absolute_path)

    # If base_dir is provided, ensure path is contained within it
    if base_dir
      base_pathname = Pathname.new(File.expand_path(base_dir))
      unless pathname.cleanpath.to_s.start_with?(base_pathname.cleanpath.to_s)
        raise SecurityError, "Path escapes base directory: #{path}"
      end
    end

    # Ensure path doesn't contain dangerous components
    if pathname.each_filename.any? { |part| %w[. .. ~ /].include?(part) || part.include?("/") }
      raise SecurityError, "Path contains invalid components: #{path}"
    end

    absolute_path
  end

  def verify_safe_directory!(dir)
    real_path = Pathname.new(dir).realpath.to_s

    dangerous_paths = [
      "/", "/usr", "/etc", "/var", "/tmp", "/private",
      Dir.home, File.expand_path("~"),
      *ENV.values_at('HOME', 'TMPDIR', 'TMP', 'TEMP').compact
    ].map { |p| Pathname.new(p).realpath.to_s rescue nil }.compact

    if dangerous_paths.any? { |p| real_path.start_with?(p) }
      raise SecurityError, "Operation not allowed in system directory: #{dir}"
    end
  end

  def secure_tempfile(prefix, base_dir)
    attempts = 0
    max_attempts = 3

    begin
      attempts += 1
      temp_path = File.join(base_dir, "#{prefix}.#{SecureRandom.hex(16)}")

      # Ensure temp path is within base_dir
      validate_and_resolve_path!(temp_path, base_dir)

      # Create with O_EXCL to prevent race conditions
      fd = File.open(temp_path, File::WRONLY | File::CREAT | File::EXCL, 0o600)
      return [fd, temp_path]
    rescue Errno::EEXIST
      retry if attempts < max_attempts
      raise SecurityError, "Failed to create secure temporary file after #{max_attempts} attempts"
    end
  end

  def atomic_write(final_path, content)
    dir = File.dirname(final_path)
    prefix = File.basename(final_path)

    fd, temp_path = secure_tempfile(prefix, dir)

    begin
      fd.write(content)
      fd.flush
      # Ensure content is written to disk
      fd.fdatasync rescue fd.fsync

      # Use atomic rename
      File.rename(temp_path, final_path)
    rescue => e
      # Attempt secure deletion on error
      secure_delete(temp_path)
      raise e
    ensure
      fd.close
    end
  end

  def secure_delete(path)
    return unless File.exist?(path)

    # Verify again that path is safe
    validate_and_resolve_path!(path, @ssl_dir)

    begin
      # Get file size before starting deletion
      size = File.size(path)

      File.open(path, "r+b") do |f|
        # Lock file to prevent concurrent access
        f.flock(File::LOCK_EX)

        # Triple overwrite with different patterns
        3.times do
          f.rewind
          f.write(SecureRandom.random_bytes(size))
          f.flush
          f.fdatasync rescue f.fsync
        end

        # Zero out
        f.rewind
        f.write("\0" * size)
        f.flush
        f.fdatasync rescue f.fsync

        # Truncate
        f.truncate(0)
        f.flush
        f.fdatasync rescue f.fsync
      end
    ensure
      # Use force: true to ensure deletion even if something went wrong
      FileUtils.rm_f(path)
    end
  end

  def check_existing_certificates!
    existing = [@key_path, @csr_path, @cert_path].select { |f| File.exist?(f) }
    unless existing.empty?
      raise SecurityError, "Certificate files already exist: #{existing.join(', ')}"
    end
  end

  def secure_memzero(string)
    string.tap do |str|
      str.replace(SecureRandom.random_bytes(str.bytesize))
      str.replace("\0" * str.bytesize)
    end
  end

  def with_secure_buffer
    buffer = String.new
    yield buffer
  ensure
    secure_memzero(buffer) if buffer
  end

  def read_file_securely(path)
    with_secure_buffer do |buffer|
      File.open(path, 'rb') do |file|
        while chunk = file.read(8192)
          buffer << chunk
        end
      end
      buffer
    end
  end

  def write_file_securely(path, content, mode: 0o600)
    temp_path = "#{path}.#{SecureRandom.hex(8)}"
    File.write(temp_path, content, mode: mode)
    File.rename(temp_path, path)
  rescue => e
    File.unlink(temp_path) if defined?(temp_path) && File.exist?(temp_path)
    raise e
  ensure
    secure_memzero(content) if content.is_a?(String)
  end

  def generate_private_key
    attempts = 0

    begin
      check_system_resources
      validate_available_space!(@ssl_dir, REQUIRED_SPACE)
      ensure_secure_environment!

      @logger.info("Generating private key: #{@key_path}")

      with_secure_buffer do |key_buffer|
        # Use SecureCommand to generate the private key
        temp_path = "#{@key_path}.#{SecureRandom.hex(8)}"
        SecureCommand.execute_command(
          "genrsa",
          "-out", temp_path,
          KEY_SIZE.to_s
        )

        key_buffer.replace(read_file_securely(temp_path))
        validate_private_key(key_buffer)
        write_file_securely(@key_path, key_buffer)
        File.unlink(temp_path)
      end
    rescue => e
      attempts += 1
      if attempts < MAX_GENERATION_ATTEMPTS
        @logger.warn("Attempt #{attempts} failed to generate private key: #{e.message}. Retrying...")
        sleep(attempts * 2)  # Exponential backoff
        retry
      else
        raise GenerationError, "Failed to generate private key after #{MAX_GENERATION_ATTEMPTS} attempts: #{e.message}"
      end
    ensure
      GC.start
      SecureRandom.random_bytes(1024).clear  # Force memory overwrite
    end
  end

  def generate_csr
    attempts = 0

    begin
      @logger.info("Generating CSR: #{@csr_path}")

      # Create OpenSSL config for CSR
      config = create_csr_config

      # Use SecureCommand to generate the CSR
      temp_path = "#{@csr_path}.#{SecureRandom.hex(8)}"
      SecureCommand.execute_command(
        "req",
        "-new",
        "-key", @key_path,
        "-out", temp_path,
        "-config", config,
        "-sha384"
      )

      validate_csr(temp_path)
      File.rename(temp_path, @csr_path)
    rescue => e
      File.unlink(temp_path) if defined?(temp_path) && File.exist?(temp_path)
      File.unlink(config) if defined?(config) && File.exist?(config)
      attempts += 1
      if attempts < MAX_GENERATION_ATTEMPTS
        @logger.warn("Attempt #{attempts} failed to generate CSR: #{e.message}. Retrying...")
        sleep(attempts * 2)
        retry
      else
        raise GenerationError, "Failed to generate CSR after #{MAX_GENERATION_ATTEMPTS} attempts: #{e.message}"
      end
    end
  end

  def generate_certificate
    attempts = 0

    begin
      @logger.info("Generating certificate: #{@cert_path}")

      # Create OpenSSL config for certificate
      config = create_cert_config

      # Use SecureCommand to generate the certificate
      temp_path = "#{@cert_path}.#{SecureRandom.hex(8)}"
      SecureCommand.execute_command(
        "x509",
        "-req",
        "-in", @csr_path,
        "-signkey", @key_path,
        "-out", temp_path,
        "-days", (CERT_VALIDITY / 86400).to_s,
        "-sha384",
        "-extensions", "v3_req",
        "-config", config
      )

      validate_certificate(temp_path)
      File.rename(temp_path, @cert_path)
    rescue => e
      File.unlink(temp_path) if defined?(temp_path) && File.exist?(temp_path)
      File.unlink(config) if defined?(config) && File.exist?(config)
      attempts += 1
      if attempts < MAX_GENERATION_ATTEMPTS
        @logger.warn("Attempt #{attempts} failed to generate certificate: #{e.message}. Retrying...")
        sleep(attempts * 2)
        retry
      else
        raise GenerationError, "Failed to generate certificate after #{MAX_GENERATION_ATTEMPTS} attempts: #{e.message}"
      end
    end
  end

  def create_csr_config
    temp_config = "#{@ssl_dir}/#{@site}.csr.cnf.#{SecureRandom.hex(8)}"
    File.write(temp_config, <<~CONFIG, mode: 0o600)
      [ req ]
      default_bits = #{KEY_SIZE}
      default_md = sha384
      prompt = no
      encrypt_key = no
      string_mask = utf8only
      distinguished_name = dn
      req_extensions = req_ext

      [ dn ]
      CN = #{@site}
      O = AutoSSL Generated
      OU = Domain Validation

      [ req_ext ]
      keyUsage = critical,digitalSignature,keyEncipherment
      extendedKeyUsage = critical,serverAuth,clientAuth
      basicConstraints = critical,CA:FALSE
      subjectKeyIdentifier = hash
      subjectAltName = @alt_names

      [ alt_names ]
      DNS.1 = #{@site}
      DNS.2 = www.#{@site}
    CONFIG
    temp_config
  end

  def create_cert_config
    temp_config = "#{@ssl_dir}/#{@site}.cert.cnf.#{SecureRandom.hex(8)}"
    File.write(temp_config, <<~CONFIG, mode: 0o600)
      [ req ]
      default_bits = #{KEY_SIZE}
      default_md = sha384
      prompt = no
      encrypt_key = no
      string_mask = utf8only
      distinguished_name = dn

      [ dn ]
      CN = #{@site}
      O = AutoSSL Generated
      OU = Domain Validation

      [ v3_req ]
      basicConstraints = critical,CA:FALSE
      keyUsage = critical,digitalSignature,keyEncipherment
      extendedKeyUsage = critical,serverAuth,clientAuth
      subjectKeyIdentifier = hash
      authorityKeyIdentifier = keyid,issuer
      subjectAltName = @alt_names

      # Security policies
      nsComment = "AutoSSL Generated Certificate"
      nsCertType = server
      nsCaRevocationUrl = http://crl.#{@site}/ca.crl
      nsRevocationUrl = http://crl.#{@site}/cert.crl

      # OCSP
      authorityInfoAccess = OCSP;URI:http://ocsp.#{@site}/

      [ alt_names ]
      DNS.1 = #{@site}
      DNS.2 = www.#{@site}
    CONFIG
    temp_config
  end

  def validate_private_key(key_path)
    key = OpenSSL::PKey::RSA.new(File.read(key_path))
    raise SecurityError, "Invalid key size" unless key.n.num_bits >= KEY_SIZE
    raise SecurityError, "Invalid public key" unless key.public?
    raise SecurityError, "Invalid private key" unless key.private?

    # Verify key integrity with test encryption/decryption
    test_data = SecureRandom.random_bytes(32)
    encrypted = key.public_encrypt(test_data)
    decrypted = key.private_decrypt(encrypted)
    raise SecurityError, "Key verification failed" unless test_data == decrypted
  rescue OpenSSL::PKey::RSAError => e
    raise SecurityError, "Key validation failed: #{e.message}"
  ensure
    key&.clear
    encrypted&.clear
    decrypted&.clear
    test_data&.clear
  end

  def validate_csr(csr_path)
    csr = OpenSSL::X509::Request.new(File.read(csr_path))

    # Verify CSR signature
    raise SecurityError, "Invalid CSR signature" unless csr.verify(csr.public_key)

    # Verify subject fields
    subject = csr.subject.to_a.to_h
    raise SecurityError, "Invalid CSR subject CN" unless subject['CN'] == @site
    raise SecurityError, "Invalid CSR subject O" unless subject['O'] == 'AutoSSL Generated'
    raise SecurityError, "Invalid CSR subject OU" unless subject['OU'] == 'Domain Validation'

    # Verify public key strength
    public_key = csr.public_key
    if public_key.is_a?(OpenSSL::PKey::RSA)
      raise SecurityError, "Weak RSA key size" unless public_key.n.num_bits >= KEY_SIZE
    end

    # Verify CSR attributes and extensions
    attributes = csr.attributes.map { |attr| [attr.oid, attr.value] }.to_h

    # Check for request extensions
    ext_req = attributes['extReq']
    if ext_req
      extensions = ext_req.value.first.value

      # Verify SAN extension
      san_ext = extensions.find { |ext| ext.first.value == 'subjectAltName' }
      if san_ext
        san_value = OpenSSL::ASN1.decode(san_ext.last.value).value
        dns_names = san_value.map { |name| name.value if name.tag == 2 }.compact

        unless dns_names.include?(@site) && dns_names.include?("www.#{@site}")
          raise SecurityError, "CSR missing required SANs"
        end
      else
        raise SecurityError, "CSR missing SAN extension"
      end
    else
      raise SecurityError, "CSR missing required extensions"
    end

    # Verify no unexpected attributes
    unexpected_attrs = attributes.keys - ['extReq']
    unless unexpected_attrs.empty?
      raise SecurityError, "CSR contains unexpected attributes: #{unexpected_attrs.join(', ')}"
    end
  rescue OpenSSL::X509::RequestError => e
    raise SecurityError, "CSR validation failed: #{e.message}"
  end

  def validate_certificate(cert_path)
    cert = OpenSSL::X509::Certificate.new(File.read(cert_path))

    # Basic certificate validation
    raise SecurityError, "Invalid certificate subject" unless cert.subject.to_s.include?(@site)
    raise SecurityError, "Certificate expired" if cert.not_after <= Time.now.utc
    raise SecurityError, "Certificate not yet valid" if cert.not_before > Time.now.utc

    # Verify certificate signature
    raise SecurityError, "Invalid certificate signature" unless cert.verify(cert.public_key)

    # Verify key usage
    key_usage = cert.extensions.find { |ext| ext.oid == 'keyUsage' }
    unless key_usage && key_usage.value.include?('Digital Signature') &&
           key_usage.value.include?('Key Encipherment')
      raise SecurityError, "Certificate missing required key usage"
    end

    # Verify basic constraints
    basic_constraints = cert.extensions.find { |ext| ext.oid == 'basicConstraints' }
    unless basic_constraints && basic_constraints.value == 'CA:FALSE'
      raise SecurityError, "Certificate must not be a CA"
    end

    # Verify subject alternative names
    san = cert.extensions.find { |ext| ext.oid == 'subjectAltName' }
    unless san && san.value.include?("DNS:#{@site}") &&
           san.value.include?("DNS:www.#{@site}")
      raise SecurityError, "Certificate missing required SANs"
    end

    # Verify public key strength
    public_key = cert.public_key
    if public_key.is_a?(OpenSSL::PKey::RSA)
      raise SecurityError, "Weak RSA key size" unless public_key.n.num_bits >= KEY_SIZE
    end

    # Verify critical extensions
    cert.extensions.each do |ext|
      if ext.critical? && !%w[keyUsage basicConstraints subjectAltName].include?(ext.oid)
        raise SecurityError, "Unsupported critical extension: #{ext.oid}"
      end
    end
  rescue OpenSSL::X509::CertificateError => e
    raise SecurityError, "Certificate validation failed: #{e.message}"
  end

  def cleanup_on_error
    [@key_path, @csr_path, @cert_path].each do |path|
      next unless File.exist?(path)
      begin
        secure_delete(path)
      rescue => e
        @logger.error("Failed to securely cleanup file #{path}: #{e.message}")
      end
    end
  end

  def ensure_safe_user!
    if Process.uid == 0 || Process.euid == 0
      raise SecurityError, "Running as root is not allowed"
    end

    # Ensure we're running as a regular user
    unless Process.uid == Process.euid && Process.gid == Process.egid
      raise SecurityError, "Running with elevated privileges is not allowed"
    end
  end

  def set_process_limits!
    PROCESS_LIMITS.each do |resource, limit|
      begin
        Process.setrlimit(Process.const_get(resource), limit, limit)
      rescue Errno::EPERM => e
        @logger.warn("Failed to set #{resource} limit: #{e.message}")
      end
    end
  end

  # File monitoring class to detect tampering
  class FileMonitor
    def initialize(directory)
      @directory = directory
      @snapshots = {}
      @monitoring = false
      @mutex = Mutex.new
    end

    def start
      @monitoring = true
      take_snapshot
    end

    def stop
      @monitoring = false
    end

    def transaction
      raise "Monitor not started" unless @monitoring

      @mutex.synchronize do
        before_snapshot = take_snapshot
        yield
        after_snapshot = take_snapshot

        # Verify only our expected changes occurred
        detect_unauthorized_changes(before_snapshot, after_snapshot)
      end
    end

    private

    def take_snapshot
      snapshot = {}
      Dir.glob(File.join(@directory, "**/*"), File::FNM_DOTMATCH).each do |path|
        next if File.directory?(path)
        next if path.end_with?(".tmp") # Skip temporary files

        stat = File.stat(path)
        snapshot[path] = {
          size: stat.size,
          mtime: stat.mtime,
          mode: stat.mode,
          ino: stat.ino,
          uid: stat.uid,
          gid: stat.gid
        }
      end
      snapshot
    end

    def detect_unauthorized_changes(before, after)
      # Find files that changed unexpectedly
      (before.keys | after.keys).each do |path|
        next unless before.key?(path) && after.key?(path)

        before_stat = before[path]
        after_stat = after[path]

        # Check for unauthorized changes
        if before_stat[:ino] != after_stat[:ino] ||
           before_stat[:uid] != after_stat[:uid] ||
           before_stat[:gid] != after_stat[:gid] ||
           before_stat[:mode] != after_stat[:mode]
          raise SecurityError, "Unauthorized file modification detected: #{path}"
        end
      end
    end
  end
end
