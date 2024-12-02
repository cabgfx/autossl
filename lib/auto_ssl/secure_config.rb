require 'yaml'
require 'openssl'
require 'base64'

module AutoSSL
  class SecureConfig
    REQUIRED_KEYS = %w[ssl_dir ca_file ca_key memory_limit cpu_limit operation_rate timeout]
    MAX_CONFIG_SIZE = 16384  # 16KB

    class ConfigError < StandardError; end

    def initialize(config_path)
      @config_path = config_path
      @config_hash = nil
      @last_mtime = nil
      @config_lock = Monitor.new
    end

    def load
      @config_lock.synchronize do
        validate_config_file
        raw_config = read_config_file
        parsed_config = parse_and_validate(raw_config)
        verify_paths(parsed_config)
        @config_hash = parsed_config
      end
    end

    def [](key)
      @config_lock.synchronize do
        reload_if_changed
        @config_hash[key]
      end
    end

    private

    def validate_config_file
      stat = File.stat(@config_path)

      raise ConfigError, "Config file too large" if stat.size > MAX_CONFIG_SIZE
      raise ConfigError, "Insecure permissions" unless stat.mode & 0o777 <= 0o600
      raise ConfigError, "Not owned by current user" unless stat.owned?
    end

    def read_config_file
      content = AtomicFile.read(@config_path)
      @last_mtime = File.mtime(@config_path)
      content
    end

    def parse_and_validate(raw_config)
      config = YAML.safe_load(raw_config, permitted_classes: [], aliases: false)
      raise ConfigError, "Invalid config format" unless config.is_a?(Hash)

      missing_keys = REQUIRED_KEYS - config.keys
      raise ConfigError, "Missing required keys: #{missing_keys.join(', ')}" if missing_keys.any?

      validate_values(config)
      config
    end

    def validate_values(config)
      validate_numeric(config['memory_limit'], 'memory_limit', min: 128, max: 4096)
      validate_numeric(config['cpu_limit'], 'cpu_limit', min: 10, max: 90)
      validate_numeric(config['operation_rate'], 'operation_rate', min: 1, max: 1000)
      validate_numeric(config['timeout'], 'timeout', min: 1, max: 300)

      validate_path(config['ssl_dir'], 'ssl_dir')
      validate_path(config['ca_file'], 'ca_file')
      validate_path(config['ca_key'], 'ca_key')
    end

    def validate_numeric(value, key, min:, max:)
      unless value.is_a?(Numeric) && value >= min && value <= max
        raise ConfigError, "#{key} must be between #{min} and #{max}"
      end
    end

    def validate_path(path, key)
      expanded = File.expand_path(path)
      raise ConfigError, "#{key} contains path traversal" if expanded.include?('..')
      raise ConfigError, "#{key} is not absolute" unless expanded.start_with?('/')
    end

    def verify_paths(config)
      ['ssl_dir', 'ca_file', 'ca_key'].each do |key|
        path = config[key]
        if File.exist?(path)
          stat = File.stat(path)
          if stat.symlink?
            raise ConfigError, "#{key} cannot be a symlink"
          end
          if (stat.mode & 0o777) > (key == 'ssl_dir' ? 0o700 : 0o600)
            raise ConfigError, "#{key} has insecure permissions"
          end
        end
      end
    end

    def reload_if_changed
      return unless @last_mtime
      current_mtime = File.mtime(@config_path)
      load if current_mtime != @last_mtime
    end
  end
end
