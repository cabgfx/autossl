require "yaml"
require "date"
require_relative "safe_path"
require "logger"
require "digest"

module SecureYAML
  class Error < StandardError; end
  class ValidationError < StandardError; end
  class SecurityError < StandardError; end

  # Whitelist of allowed classes for YAML deserialization
  ALLOWED_CLASSES = [
    Symbol,
    Time,
    Date,
    DateTime
  ].freeze

  # Maximum YAML file size (5MB)
  MAX_YAML_SIZE = 5 * 1024 * 1024

  # Maximum nesting depth for YAML structures
  MAX_NESTING_DEPTH = 10

  # Validation schema for configuration
  SCHEMA = {
    "ssl_dir" => { required: true, type: String },
    "ca_file" => { required: true, type: String },
    "ca_key" => { required: true, type: String },
    "memory_limit" => { required: false, type: Integer, min: 128, max: 4096 },
    "cpu_limit" => { required: false, type: Integer, min: 10, max: 90 },
    "operation_rate" => { required: false, type: Integer, min: 1, max: 1000 },
    "timeout" => { required: false, type: Integer, min: 1, max: 300 }
  }.freeze

  class << self
    def logger
      @logger ||= begin
        logger = Logger.new(File.join(SafePath.data_home, "autossl.log"))
        logger.level = Logger::INFO
        logger.formatter = proc do |severity, datetime, progname, msg|
          "[#{datetime.utc.iso8601}] [#{severity}] [YAML] [#{Process.pid}] #{msg}\n"
        end
        logger
      end
    end

    def load_file(path, base_dir: nil)
      content = SafePath.secure_read(path, base_dir: base_dir)

      # Check file size
      if content.bytesize > MAX_YAML_SIZE
        raise SecurityError, "YAML file exceeds maximum allowed size"
      end

      # Load and validate YAML content
      data = safe_load(content)
      validate_structure!(data)
      data
    rescue Psych::Exception => e
      logger.error("YAML parsing error: #{e.message}")
      raise Error, "YAML parsing error: #{e.message}"
    end

    def safe_load(yaml_content)
      YAML.safe_load(
        yaml_content,
        permitted_classes: ALLOWED_CLASSES,
        aliases: false,
        symbolize_names: false
      )
    rescue Psych::Exception => e
      logger.error("YAML parsing error: #{e.message}")
      raise Error, "YAML parsing error: #{e.message}"
    end

    def dump(data, path, base_dir: nil, mode: 0o600)
      # Validate input type
      unless data.is_a?(Hash)
        raise ValidationError, "Can only dump Hash objects, got: #{data.class}"
      end

      # Verify data structure and types
      validate_structure!(data)

      # Calculate checksum before serialization
      original_checksum = Digest::SHA256.hexdigest(data.to_s)

      # Serialize to YAML
      yaml_content = YAML.dump(data)

      # Verify serialization didn't corrupt data
      reloaded_data = safe_load(yaml_content)
      reloaded_checksum = Digest::SHA256.hexdigest(reloaded_data.to_s)

      unless original_checksum == reloaded_checksum
        raise SecurityError, "YAML serialization verification failed"
      end

      # Write file securely
      SafePath.secure_write(path, yaml_content, mode: mode, base_dir: base_dir)

      logger.info("Successfully dumped YAML to #{path}")
    rescue => e
      logger.error("Failed to dump YAML: #{e.message}")
      raise Error, "Failed to dump YAML: #{e.message}"
    end

    private

    def validate_structure!(data, depth = 0)
      # Check nesting depth
      if depth > MAX_NESTING_DEPTH
        raise ValidationError, "YAML structure exceeds maximum nesting depth"
      end

      case data
      when Hash
        data.each do |key, value|
          validate_key!(key)
          validate_structure!(value, depth + 1)
        end
      when Array
        data.each { |value| validate_structure!(value, depth + 1) }
      when String, Integer, Float, TrueClass, FalseClass, NilClass, *ALLOWED_CLASSES
        # These types are allowed
      else
        raise ValidationError, "Unsupported type in YAML structure: #{data.class}"
      end
    end

    def validate_key!(key)
      unless key.is_a?(String)
        raise ValidationError, "YAML keys must be strings, got: #{key.class}"
      end

      if key.empty? || key.length > 128
        raise ValidationError, "Invalid YAML key length: #{key}"
      end

      unless key.match?(/\A[a-zA-Z0-9_.-]+\z/)
        raise ValidationError, "Invalid characters in YAML key: #{key}"
      end
    end

    def validate_against_schema!(data)
      SCHEMA.each do |key, rules|
        if rules[:required] && !data.key?(key)
          raise ValidationError, "Missing required key: #{key}"
        end

        next unless data.key?(key)
        value = data[key]

        unless value.is_a?(rules[:type])
          raise ValidationError, "Invalid type for #{key}: expected #{rules[:type]}, got #{value.class}"
        end

        if rules[:min] && value < rules[:min]
          raise ValidationError, "Value for #{key} below minimum: #{value} < #{rules[:min]}"
        end

        if rules[:max] && value > rules[:max]
          raise ValidationError, "Value for #{key} above maximum: #{value} > #{rules[:max]}"
        end
      end
    end
  end
end
