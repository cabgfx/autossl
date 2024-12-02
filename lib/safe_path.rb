require "pathname"
require_relative "safety_checks"
require "logger"
require "securerandom"
require "fileutils"

module SafePath
  class Error < StandardError; end

  class PathTraversalError < Error; end

  class PermissionError < Error; end

  class ValidationError < Error; end

  DEFAULT_DIRECTORY_PERMISSIONS = 0o700
  DEFAULT_FILE_PERMISSIONS = 0o600

  module_function

  # Initialize logger
  def logger
    @logger ||= Logger.new(File.join(data_home, "autossl.log"))
  end

  def data_home
    # Define the data home directory, adjust as needed
    ENV["XDG_DATA_HOME"] || File.join(Dir.home, ".local", "share")
  end

  def validate_path(path, base_dir = nil)
    # Initial path normalization
    path = Pathname.new(path).cleanpath
    SafetyChecks.validate_path_length!(path)

    # Convert to absolute path if relative
    unless path.absolute?
      raise ValidationError, "Base directory must be provided for relative paths" unless base_dir
      base_dir = Pathname.new(base_dir).cleanpath
      path = (base_dir + path).cleanpath
    end

    # Resolve symlinks and normalize
    real_path = begin
      SafetyChecks.check_symlink!(path)
    rescue
      raise SecurityError, "Path contains symbolic links or is invalid: #{path}"
    end

    if base_dir
      begin
        SafetyChecks.validate_in_directory!(real_path, base_dir)
      rescue SafetyChecks::SecurityError => e
        logger.error("Path traversal attempt: #{e.message}")
        raise PathTraversalError, e.message
      end
    end

    real_path
  end

  def secure_write(path, content, mode: DEFAULT_FILE_PERMISSIONS, base_dir: nil)
    validate_path(path, base_dir)
    temp_path = path.sub_ext(".tmp#{SecureRandom.uuid}")

    File.open(temp_path, File::CREAT | File::EXCL | File::WRONLY, mode) do |f|
      f.flock(File::LOCK_EX)
      f.write(content)
      f.flush
      f.fsync # Ensure content is written to disk
      f.flock(File::LOCK_UN)
    end

    # Verify temp file permissions and ownership
    SafetyChecks.validate_permissions!(temp_path, mode)
    SafetyChecks.validate_ownership!(temp_path)

    # Atomic rename
    File.rename(temp_path, path)
    logger.info("Successfully wrote to #{path}")
  rescue => e
    logger.error("Failed to write to #{path}: #{e.message}")
    raise
  ensure
    File.unlink(temp_path) if File.exist?(temp_path)
  end

  def secure_read(path, base_dir: nil)
    validate_path(path, base_dir)

    unless path.readable?
      logger.error("File is not readable: #{path}")
      raise PermissionError, "File is not readable: #{path}"
    end

    # Verify it's a regular file with proper permissions
    unless SafetyChecks.secure_file?(path)
      logger.error("File has insecure permissions or is not a regular file: #{path}")
      raise SecurityError, "File has insecure permissions or is not a regular file: #{path}"
    end

    logger.info("Reading file: #{path}")
    File.read(path)
  rescue Errno::ENOENT
    logger.error("File not found: #{path}")
    raise
  rescue Errno::EACCES
    logger.error("Permission denied reading file: #{path}")
    raise
  rescue => e
    logger.error("Failed to read file #{path}: #{e.message}")
    raise
  end

  def secure_mkdir(path, mode: DEFAULT_DIRECTORY_PERMISSIONS, base_dir: nil)
    # For directories, validate the parent first
    parent = Pathname.new(path).parent
    validate_path(parent, base_dir) if base_dir

    # Check available space
    SafetyChecks.validate_available_space!(parent)

    # Create directory with secure permissions
    FileUtils.mkdir_p(path, mode: mode)
    logger.info("Created directory: #{path}")

    # Validate the created directory
    created_path = validate_path(path, base_dir)
    SafetyChecks.validate_permissions!(created_path, mode)
    SafetyChecks.validate_ownership!(created_path)

    created_path
  rescue Errno::EEXIST
    logger.warn("Directory already exists: #{path}")
  end

  def within_base_dir?(path, base_dir)
    validate_path(path, base_dir)
    true
  rescue Error
    false
  end
end
