require "thor"
require "yaml"
require_relative "lib/cert_manager"
require_relative "lib/safe_path"
require_relative "lib/secure_yaml"
require "rbconfig"
require "logger"

class AutoSSL < Thor
  class Error < StandardError; end

  # Initialize logger
  def self.logger
    @logger ||= Logger.new(File.join(data_home, "autossl.log"))
  end

  # Platform-aware configuration paths
  def self.config_home
    case RbConfig::CONFIG["host_os"]
    when /darwin/
      # macOS follows XDG spec if set, otherwise uses ~/Library/Application Support
      ENV.fetch("XDG_CONFIG_HOME") do
        File.expand_path("~/Library/Application Support")
      end
    else
      # Linux and others follow XDG spec
      ENV.fetch("XDG_CONFIG_HOME") do
        File.expand_path("~/.config")
      end
    end
  end

  def self.data_home
    case RbConfig::CONFIG["host_os"]
    when /darwin/
      # macOS follows XDG spec if set, otherwise uses ~/Library/Application Support
      ENV.fetch("XDG_DATA_HOME") do
        File.expand_path("~/Library/Application Support")
      end
    else
      # Linux and others follow XDG spec
      ENV.fetch("XDG_DATA_HOME") do
        File.expand_path("~/.local/share")
      end
    end
  end

  # Application paths
  CONFIG_FILE = File.join(config_home, "autossl/config.yml")
  DEFAULT_SSL_DIR = File.join(data_home, "autossl/certificates")

  desc "generate DOMAIN TLD", "Generates a self-signed SSL certificate for the given DOMAIN and TLD"
  option :ca_file, type: :string, desc: "Path to the CA file"
  option :ca_key, type: :string, desc: "Path to the CA key"
  option :ssl_dir, type: :string, desc: "Path to the SSL directory"
  def generate(domain, tld)
    validate_input!(domain, tld)

    begin
      config = load_config

      ca_file = resolve_path(options[:ca_file] || config["ca_file"], "CA file")
      ca_key = resolve_path(options[:ca_key] || config["ca_key"], "CA key")
      ssl_dir = resolve_path(options[:ssl_dir] || config["ssl_dir"] || DEFAULT_SSL_DIR, "SSL directory")

      site = "dev.#{domain}.#{tld}"
      cert_manager = CertManager.new(site, ca_file, ca_key, ssl_dir)
      cert_manager.generate_certificates

      logger.info("Successfully generated certificates for #{site} in #{ssl_dir}")
      puts "Successfully generated certificates for #{site} in #{ssl_dir}"
    rescue => e
      error_message = "Certificate generation failed: #{e.message}"
      logger.error(error_message)
      raise Thor::Error, error_message
    end
  end

  desc "init", "Initialize the AutoSSL configuration"
  def init
    ensure_config_directory
    config = load_config

    config["ca_file"] = ask_path("Enter the path to the CA file:", default: config["ca_file"])
    config["ca_key"] = ask_path("Enter the path to the CA key:", default: config["ca_key"])
    config["ssl_dir"] = ask_path("Enter the path to the SSL directory:", default: config["ssl_dir"] || DEFAULT_SSL_DIR)

    # Validate all paths before saving
    validate_config!(config)

    # Ensure SSL directory exists with proper permissions
    SafePath.secure_mkdir(config["ssl_dir"], mode: 0o700)

    # Save configuration
    save_config(config)

    logger.info("Configuration saved to #{CONFIG_FILE}")
    puts "Configuration saved to #{CONFIG_FILE}"
  rescue => e
    error_message = "Configuration failed: #{e.message}"
    logger.error(error_message)
    raise Thor::Error, error_message
  end

  def self.exit_on_failure?
    true
  end

  private

  def logger
    self.class.logger
  end

  def validate_input!(domain, tld)
    unless domain.match?(/\A[a-z0-9][a-z0-9-]*[a-z0-9]\z/i)
      logger.error("Invalid domain: #{domain}")
      raise Error, "Invalid domain: #{domain}"
    end

    unless tld.match?(/\A[a-z]{2,}\z/i)
      logger.error("Invalid TLD: #{tld}")
      raise Error, "Invalid TLD: #{tld}"
    end
  end

  def resolve_path(path, description)
    return nil if path.nil?

    expanded_path = File.expand_path(path)
    unless File.exist?(expanded_path)
      logger.error("#{description} not found: #{path}")
      raise Error, "#{description} not found: #{path}"
    end

    expanded_path
  end

  def ask_path(prompt, default: nil)
    path = ask(prompt, default: default)
    return nil if path.empty?

    # Expand path and handle ~
    File.expand_path(path)
  end

  def ensure_config_directory
    config_dir = File.dirname(CONFIG_FILE)
    SafePath.secure_mkdir(config_dir, mode: 0o700)
  end

  def load_config
    return {} unless File.exist?(CONFIG_FILE)

    begin
      SecureYAML.load_file(CONFIG_FILE, base_dir: File.dirname(CONFIG_FILE))
    rescue => e
      logger.error("Failed to load config: #{e.message}")
      raise Error, "Failed to load config: #{e.message}"
    end
  end

  def save_config(config)
    SecureYAML.dump(config, CONFIG_FILE, base_dir: File.dirname(CONFIG_FILE), mode: 0o600)
    logger.info("Successfully saved configuration to #{CONFIG_FILE}")
  end

  def validate_config!(config)
    ["ca_file", "ca_key", "ssl_dir"].each do |key|
      next if config[key].nil?

      path = config[key]
      case key
      when "ca_file", "ca_key"
        unless File.file?(path) && File.readable?(path)
          logger.error("#{key.tr("_", " ").capitalize} is not accessible: #{path}")
          raise Error, "#{key.tr("_", " ").capitalize} is not accessible: #{path}"
        end
      when "ssl_dir"
        # Directory will be created if it doesn't exist
        parent_dir = File.dirname(path)
        unless File.directory?(parent_dir) && File.writable?(parent_dir)
          logger.error("Parent directory for SSL directory is not writable: #{parent_dir}")
          raise Error, "Parent directory for SSL directory is not writable: #{parent_dir}"
        end
      end
    end
  end
end

# Only start Thor if this file is run directly
AutoSSL.start(ARGV) if __FILE__ == $0
