require "yaml"
require "date"
require_relative "safe_path"
require "logger"

module SecureYAML
  class Error < StandardError; end

  ALLOWED_CLASSES = [Symbol, Time, Date].freeze

  # Initialize logger
  def self.logger
    @logger ||= Logger.new(File.join(SafePath.data_home, "autossl.log"))
  end

  module_function

  def load_file(path, base_dir: nil)
    content = SafePath.secure_read(path, base_dir: base_dir)
    safe_load(content)
  end

  def safe_load(yaml_content)
    YAML.safe_load(
      yaml_content,
      permitted_classes: ALLOWED_CLASSES,
      aliases: false
    )
  rescue Psych::Exception => e
    logger.error("YAML parsing error: #{e.message}")
    raise Error, "YAML parsing error: #{e.message}"
  end

  def dump(data, path, base_dir: nil, mode: 0o600)
    unless data.is_a?(Hash)
      logger.error("Can only dump Hash objects, got: #{data.class}")
      raise Error, "Can only dump Hash objects, got: #{data.class}"
    end

    # Verify all values are of allowed types
    verify_types(data)

    yaml_content = YAML.dump(data)
    SafePath.secure_write(path, yaml_content, mode: mode, base_dir: base_dir)
    logger.info("Successfully dumped YAML to #{path}")
  end

  def verify_types(obj, path = [])
    case obj
    when Hash
      obj.each do |k, v|
        verify_types(v, path + [k])
      end
    when Array
      obj.each_with_index do |v, i|
        verify_types(v, path + [i])
      end
    when String, Numeric, TrueClass, FalseClass, NilClass, *ALLOWED_CLASSES
      # These types are allowed
    else
      location = path.empty? ? "root" : "at path: #{path.join(".")}"
      logger.error("Unsupported type #{obj.class} #{location}")
      raise Error, "Unsupported type #{obj.class} #{location}"
    end
  end
end
