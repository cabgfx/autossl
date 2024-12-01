require "pathname"

module SafePath
  class Error < StandardError; end

  class PathTraversalError < Error; end

  class PermissionError < Error; end

  class ValidationError < Error; end

  module_function

  def validate_path(path, base_dir = nil)
    path = Pathname.new(path).cleanpath

    # Convert to absolute path if relative
    unless path.absolute?
      raise ValidationError, "Base directory must be provided for relative paths" unless base_dir
      base_dir = Pathname.new(base_dir).cleanpath
      path = (base_dir + path).cleanpath
    end

    # Resolve symlinks and normalize
    real_path = begin
      path.realpath
    rescue
      nil
    end
    raise ValidationError, "Path does not exist or is not accessible: #{path}" unless real_path

    # If base_dir provided, ensure path is contained within it
    if base_dir
      base_real = begin
        Pathname.new(base_dir).realpath
      rescue
        nil
      end
      raise ValidationError, "Base directory is invalid: #{base_dir}" unless base_real
      unless real_path.to_s.start_with?(base_real.to_s)
        raise PathTraversalError, "Path escapes base directory: #{path}"
      end
    end

    real_path
  end

  def secure_write(path, content, mode: 0o600, base_dir: nil)
    path = validate_path(path, base_dir)

    # Ensure parent directory exists and is writable
    parent = path.parent
    unless parent.directory? && parent.writable?
      raise PermissionError, "Parent directory is not writable: #{parent}"
    end

    # Write to temporary file first
    temp_path = path.sub_ext(".tmp" + Random.rand(100000).to_s)
    begin
      File.open(temp_path, File::CREAT | File::EXCL | File::WRONLY, mode) do |f|
        f.write(content)
        f.flush
        f.fsync # Ensure content is written to disk
      end

      # Atomic rename
      File.rename(temp_path, path)
    ensure
      File.unlink(temp_path) if File.exist?(temp_path)
    end

    path
  end

  def secure_read(path, base_dir: nil)
    path = validate_path(path, base_dir)

    unless path.readable?
      raise PermissionError, "File is not readable: #{path}"
    end

    File.read(path)
  end

  def secure_mkdir(path, mode: 0o700, base_dir: nil)
    # For directories, we need to validate the parent first
    parent = Pathname.new(path).parent
    validate_path(parent, base_dir) if base_dir

    FileUtils.mkdir_p(path, mode: mode)
    validate_path(path, base_dir) # Validate the created directory
  end

  def within_base_dir?(path, base_dir)
    validate_path(path, base_dir)
    true
  rescue Error
    false
  end
end
