require "fileutils"
require "pathname"
require "logger"
require "digest"

# The SafePath module provides methods for secure file and directory operations,
# ensuring that all paths are validated and sanitized to prevent security vulnerabilities.
module SafePath
  # Custom error for permission-related issues
  class PermissionError < StandardError; end
  class SecurityError < StandardError; end
  class SanitizationError < StandardError; end
  class ValidationError < StandardError; end

  # Path to the data directory
  DATA_HOME = ENV.fetch("XDG_DATA_HOME") { File.expand_path("~/.local/share") }

  # Security constants
  MAX_SYMLINK_DEPTH = 8
  SECURE_DIRECTORY_MODE = 0o700
  SECURE_FILE_MODE = 0o600
  ALLOWED_CHARACTERS = /\A[a-zA-Z0-9\-_.]+\z/.freeze

  class << self
    def logger
      @logger ||= begin
        log_path = File.join(DATA_HOME, "autossl.log")
        logger = Logger.new(log_path, 'daily')
        logger.level = Logger::INFO
        logger.formatter = proc do |severity, datetime, progname, msg|
          "[#{datetime.utc.iso8601}] [#{severity}] [#{Process.pid}] #{msg}\n"
        end
        logger
      end
    end

    def secure_mkdir(path, mode: SECURE_DIRECTORY_MODE)
      expanded_path = validate_path!(path)

      # Create parent directories if they don't exist
      FileUtils.mkdir_p(File.dirname(expanded_path), mode: mode)

      # Create target directory if it doesn't exist
      unless File.directory?(expanded_path)
        FileUtils.mkdir(expanded_path, mode: mode)
      end

      # Verify directory security
      verify_directory_security!(expanded_path, mode)

      expanded_path
    rescue => e
      logger.error("Failed to create directory #{path}: #{e.message}")
      raise SecurityError, "Failed to create directory: #{e.message}"
    end

    def secure_write(path, content, mode: SECURE_FILE_MODE, base_dir: nil)
      expanded_path = validate_path!(path, base_dir)

      # Write to temporary file first
      temp_path = "#{expanded_path}.#{Process.pid}.tmp"
      File.open(temp_path, 'w', mode) do |f|
        f.write(content)
        f.flush
        f.fsync # Ensure content is written to disk
      end

      # Move temporary file to final location atomically
      File.rename(temp_path, expanded_path)

      # Verify file security
      verify_file_security!(expanded_path, mode)

      # Verify content integrity
      verify_content_integrity!(expanded_path, content)
    rescue => e
      # Clean up temporary file if it exists
      File.unlink(temp_path) if temp_path && File.exist?(temp_path)
      logger.error("Failed to write file #{path}: #{e.message}")
      raise SecurityError, "Failed to write file: #{e.message}"
    end

    private

    def validate_path!(path, base_dir = nil)
      expanded_path = File.expand_path(path)

      if base_dir
        base_dir = File.expand_path(base_dir)
        unless expanded_path.start_with?(base_dir)
          raise SecurityError, "Path traversal attempt detected"
        end
      end

      # Check for symlink attacks
      current_path = Pathname.new(expanded_path)
      symlink_count = 0

      while current_path.symlink?
        raise SecurityError, "Too many symbolic links" if symlink_count >= MAX_SYMLINK_DEPTH
        current_path = current_path.readlink
        symlink_count += 1
      end

      # Validate path components
      path_components = expanded_path.split(File::SEPARATOR)
      path_components.each do |component|
        next if component.empty?
        unless component.match?(ALLOWED_CHARACTERS)
          raise SecurityError, "Invalid characters in path component: #{component}"
        end
      end

      expanded_path
    end

    def verify_directory_security!(path, mode)
      stat = File.stat(path)
      unless stat.directory?
        raise SecurityError, "Path is not a directory: #{path}"
      end

      actual_mode = stat.mode & 0o777
      unless actual_mode <= mode
        raise SecurityError, "Directory has insecure permissions: #{actual_mode.to_s(8)}"
      end

      unless stat.owned?
        raise SecurityError, "Directory not owned by current user"
      end
    end

    def verify_file_security!(path, mode)
      stat = File.stat(path)
      unless stat.file?
        raise SecurityError, "Path is not a regular file: #{path}"
      end

      actual_mode = stat.mode & 0o777
      unless actual_mode <= mode
        raise SecurityError, "File has insecure permissions: #{actual_mode.to_s(8)}"
      end

      unless stat.owned?
        raise SecurityError, "File not owned by current user"
      end
    end

    def verify_content_integrity!(path, expected_content)
      actual_content = File.read(path)
      expected_digest = Digest::SHA256.hexdigest(expected_content)
      actual_digest = Digest::SHA256.hexdigest(actual_content)

      unless actual_digest == expected_digest
        raise SecurityError, "File content integrity check failed"
      end
    end
  end
end
