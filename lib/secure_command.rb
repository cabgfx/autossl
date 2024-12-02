require "open3"
require "shellwords"
require "rbconfig"
require "logger"

module SecureCommand
  class Error < StandardError; end

  class CommandError < Error; end

  # Define common paths based on platform
  OPENSSL_PATHS = case RbConfig::CONFIG["host_os"]
  when /darwin/
    [
      "/opt/homebrew/bin/openssl",    # Apple Silicon Homebrew
      "/usr/local/bin/openssl",       # Intel Homebrew
      "/usr/bin/openssl"              # System OpenSSL
    ]
  when /linux/
    [
      "/usr/bin/openssl",
      "/usr/local/bin/openssl",
      "/opt/openssl/bin/openssl"      # Custom OpenSSL installations
    ]
  else
    [
      "/usr/bin/openssl",
      "/usr/local/bin/openssl"
    ]
  end.freeze

  # Define allowed OpenSSL commands and their allowed options
  ALLOWED_COMMANDS = {
    "genrsa" => ["-out", "2048"],
    "req" => ["-new", "-key", "-out", "-subj"],
    "x509" => ["-req", "-in", "-CA", "-CAkey", "-CAcreateserial", "-out", "-days", "-sha256", "-extfile"]
  }.freeze

  # Initialize logger
  def self.logger
    @logger ||= Logger.new(File.join(SafePath.data_home, "autossl.log"))
  end

  module_function

  def openssl(*args, working_dir: nil)
    # Validate OpenSSL command and arguments
    validate_openssl_args!(args)

    # Build command with explicit path to OpenSSL
    openssl_path = find_openssl_path
    command = [openssl_path, *args]

    logger.info("Executing OpenSSL command: #{command.join(" ")}")

    # Execute in specified working directory with file locking
    Dir.chdir(working_dir || Dir.pwd) do
      execute_command(command)
    end
  end

  def execute_command(command)
    stdout, stderr, status = Open3.capture3(*command)

    unless status.success?
      logger.error("OpenSSL command failed (exit #{status.exitstatus}): #{stderr}")
      raise CommandError, "Command failed (exit #{status.exitstatus}): #{stderr}"
    end

    logger.info("OpenSSL command output: #{stdout.strip}")
    stdout
  end

  def validate_openssl_args!(args)
    command = args.first
    unless ALLOWED_COMMANDS.key?(command)
      logger.error("Unsupported OpenSSL command: #{command}")
      raise Error, "Unsupported OpenSSL command: #{command}"
    end

    # Validate all arguments against whitelist
    args.each_with_index do |arg, i|
      next if i == 0 # Skip the command itself

      if arg.start_with?("-")
        unless ALLOWED_COMMANDS[command].include?(arg)
          logger.error("Unsupported option for #{command}: #{arg}")
          raise Error, "Unsupported option for #{command}: #{arg}"
        end
      else
        # For non-option arguments, ensure they are valid
        unless ALLOWED_COMMANDS[command].include?(arg)
          logger.error("Unexpected argument for #{command}: #{arg}")
          raise Error, "Unexpected argument for #{command}: #{arg}"
        end
      end
    end
  end

  def find_openssl_path
    # First try using PATH
    openssl_path = find_in_path("openssl")
    return openssl_path if openssl_path

    # Then try platform-specific paths
    openssl_path = OPENSSL_PATHS.find { |p| File.executable?(p) }
    unless openssl_path
      logger.error("Could not find OpenSSL executable")
      raise Error, "Could not find OpenSSL executable"
    end

    openssl_path
  end

  def find_in_path(cmd)
    exts = ENV["PATHEXT"] ? ENV["PATHEXT"].split(";") : [""]
    ENV["PATH"].split(File::PATH_SEPARATOR).each do |path|
      exts.each do |ext|
        exe = File.join(path, "#{cmd}#{ext}")
        return exe if File.executable?(exe) && !File.directory?(exe)
      end
    end
    nil
  end

  def escape_string(str)
    # Remove any potentially dangerous characters
    cleaned = str.gsub(/[^a-zA-Z0-9._-]/, "")

    # Ensure the string isn't empty and doesn't start with a dash
    if cleaned.empty? || cleaned.start_with?("-")
      logger.error("Invalid string after sanitization: #{str}")
      raise Error, "Invalid string after sanitization: #{str}"
    end

    cleaned
  end
end
