require "openssl"
require "fileutils"
require "logger"
require "yaml"
require "digest"
require "thor"
require "sys/filesystem"
require "securerandom"
require_relative "lib/safety_checks"
require_relative "lib/secure_command"
require_relative "lib/secure_yaml"

module AutoSSL
  class CLI < Thor
    include SafetyChecks

    Error = Class.new(StandardError)
    SecurityError = Class.new(Error)
    ValidationError = Class.new(Error)
    ResourceError = Class.new(Error)
    ConfigError = Class.new(Error)

    # Security constants
    MAX_DOMAIN_LENGTH = 253  # RFC 1035
    REQUIRED_FILE_MODE = 0o600
    REQUIRED_DIR_MODE = 0o700
    MAX_CONFIG_SIZE = 1024 * 1024  # 1MB
    SECURE_HASH = OpenSSL::Digest::SHA384

    # Configuration constants
    CONFIG_DIR = File.join(
      ENV.fetch("XDG_CONFIG_HOME") { File.expand_path("~/.config") },
      "autossl"
    )
    CONFIG_FILE = File.join(CONFIG_DIR, "config.yml")
    DEFAULT_SSL_DIR = File.join(
      ENV.fetch("XDG_DATA_HOME") { File.expand_path("~/.local/share") },
      "autossl/certificates"
    )

    class << self
      def logger
        @logger ||= begin
          log_dir = File.dirname(DEFAULT_SSL_DIR)
          FileUtils.mkdir_p(log_dir, mode: REQUIRED_DIR_MODE)
          log_path = File.join(log_dir, "autossl.log")

          # Rotate log if it exceeds 10MB
          if File.exist?(log_path) && File.size(log_path) > 10 * 1024 * 1024
            File.rename(log_path, "#{log_path}.old")
          end

          logger = Logger.new(log_path, "daily")
          logger.level = Logger::INFO
          logger.formatter = proc do |severity, datetime, progname, msg|
            "[#{datetime.utc.iso8601(3)}] [#{severity}] [#{Process.pid}] #{msg}\n"
          end
          logger
        end
      end

      def exit_on_failure?
        true
      end
    end

    desc "init", "Initialize AutoSSL configuration"
    method_option :force, type: :boolean, aliases: "-f", desc: "Force overwrite existing configuration"
    def init
      begin
        check_system_resources
        ensure_secure_environment!

        if File.exist?(CONFIG_FILE) && !options[:force]
          raise ConfigError, "Configuration already exists. Use --force to overwrite."
        end

        # Create configuration directory with secure permissions
        FileUtils.mkdir_p(CONFIG_DIR, mode: REQUIRED_DIR_MODE)

        # Generate default configuration
        config = {
          "ssl_dir" => DEFAULT_SSL_DIR,
          "ca_file" => nil,
          "ca_key" => nil,
          "memory_limit" => 512,
          "cpu_limit" => 80,
          "operation_rate" => 100,
          "timeout" => 30,
          "log_level" => "info",
          "security" => {
            "min_key_size" => 4096,
            "cert_validity_days" => 365,
            "require_strong_entropy" => true,
            "openssl_security_level" => 2
          }
        }

        SecureYAML.dump(config, CONFIG_FILE, mode: REQUIRED_FILE_MODE)

        logger.info("Configuration initialized at #{CONFIG_FILE}")
        puts "Configuration initialized at #{CONFIG_FILE}"
      rescue => e
        error_message = "Initialization failed: #{e.message}"
        logger.error(error_message)
        raise Error, error_message
      end
    end

    desc "generate DOMAIN TLD", "Generate SSL certificate for domain"
    method_option :ca_file, type: :string, desc: "Path to CA certificate"
    method_option :ca_key, type: :string, desc: "Path to CA private key"
    method_option :ssl_dir, type: :string, desc: "SSL certificate output directory"
    method_option :force, type: :boolean, aliases: "-f", desc: "Force overwrite existing certificates"
    def generate(domain, tld)
      begin
        check_system_resources
        ensure_secure_environment!
        validate_input!(domain, tld)

        config = SecureYAML.load_file(CONFIG_FILE)

        # Resolve and validate paths
        ca_file = resolve_path(options[:ca_file] || config["ca_file"], "CA certificate")
        ca_key = resolve_path(options[:ca_key] || config["ca_key"], "CA private key")
        ssl_dir = resolve_path(options[:ssl_dir] || config["ssl_dir"] || DEFAULT_SSL_DIR, "SSL directory")

        verify_ca_files!(ca_file, ca_key)

        site = "#{domain}.#{tld}"
        cert_manager = CertificateManager.new(
          site,
          ssl_dir: ssl_dir,
          force: options[:force]
        )

        cert_manager.generate_certificates

        logger.info("Successfully generated certificates for #{site}")
        puts "Successfully generated certificates for #{site}"
      rescue => e
        error_message = "Certificate generation failed: #{e.message}"
        logger.error(error_message)
        raise Error, error_message
      end
    end

    private

    def logger
      self.class.logger
    end

    def validate_input!(domain, tld)
      raise ValidationError, "Domain cannot be nil" if domain.nil?
      raise ValidationError, "TLD cannot be nil" if tld.nil?

      unless domain.match?(/\A[a-z0-9][a-z0-9-]*[a-z0-9]\z/i) && domain.length <= MAX_DOMAIN_LENGTH
        raise ValidationError, "Invalid domain format: #{domain}"
      end

      unless tld.match?(/\A[a-z]{2,}\z/i) && tld.length <= 63
        raise ValidationError, "Invalid TLD format: #{tld}"
      end

      full_domain = "#{domain}.#{tld}"
      if full_domain.length > MAX_DOMAIN_LENGTH
        raise ValidationError, "Domain name exceeds maximum length: #{full_domain}"
      end
    end

    def resolve_path(path, description)
      return nil if path.nil?

      expanded_path = File.expand_path(path)
      validate_path_length!(expanded_path)

      unless File.exist?(expanded_path)
        raise ValidationError, "#{description} not found: #{path}"
      end

      expanded_path
    end

    def verify_ca_files!(ca_file, ca_key)
      [ca_file, ca_key].each do |file|
        next if file.nil?

        validate_path_length!(file)
        validate_permissions!(file, REQUIRED_FILE_MODE)
        validate_ownership!(file)

        # Verify file integrity
        begin
          if file == ca_file
            OpenSSL::X509::Certificate.new(File.read(file))
          else
            OpenSSL::PKey::RSA.new(File.read(file))
          end
        rescue => e
          raise SecurityError, "Invalid CA file format (#{file}): #{e.message}"
        end
      end
    end
  end
end
