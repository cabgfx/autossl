require 'open3'
require 'shellwords'
require 'rbconfig'

module SecureCommand
  class Error < StandardError; end
  class CommandError < Error; end

  # Define common paths based on platform
  OPENSSL_PATHS = case RbConfig::CONFIG['host_os']
  when /darwin/
    [
      '/opt/homebrew/bin/openssl',    # Apple Silicon Homebrew
      '/usr/local/bin/openssl',       # Intel Homebrew
      '/usr/bin/openssl'              # System OpenSSL
    ]
  when /linux/
    [
      '/usr/bin/openssl',
      '/usr/local/bin/openssl',
      '/opt/openssl/bin/openssl'      # Custom OpenSSL installations
    ]
  else
    [
      '/usr/bin/openssl',
      '/usr/local/bin/openssl'
    ]
  end.freeze

  module_function

  def openssl(*args, working_dir: nil)
    # Validate OpenSSL command and arguments
    validate_openssl_args!(args)

    # Build command with explicit path to OpenSSL
    openssl_path = find_openssl_path
    command = [openssl_path, *args]

    # Execute in specified working directory
    Dir.chdir(working_dir || Dir.pwd) do
      execute_command(command)
    end
  end

  def execute_command(command)
    stdout, stderr, status = Open3.capture3(*command)

    unless status.success?
      raise CommandError, "Command failed (exit #{status.exitstatus}): #{stderr}"
    end

    stdout
  end

  def validate_openssl_args!(args)
    # Whitelist of allowed OpenSSL commands and their allowed options
    ALLOWED_COMMANDS = {
      'genrsa' => ['-out'],
      'req' => ['-new', '-key', '-out', '-subj'],
      'x509' => ['-req', '-in', '-CA', '-CAkey', '-CAcreateserial', '-out', '-days', '-sha256', '-extfile']
    }.freeze

    command = args.first
    unless ALLOWED_COMMANDS.key?(command)
      raise Error, "Unsupported OpenSSL command: #{command}"
    end

    # Validate all arguments against whitelist
    args.each_with_index do |arg, i|
      next if i == 0 # Skip the command itself

      if arg.start_with?('-')
        unless ALLOWED_COMMANDS[command].include?(arg)
          raise Error, "Unsupported option for #{command}: #{arg}"
        end
      end
    end
  end

  def find_openssl_path
    # First try using PATH
    openssl_path = find_in_path('openssl')
    return openssl_path if openssl_path

    # Then try platform-specific paths
    openssl_path = OPENSSL_PATHS.find { |p| File.executable?(p) }
    raise Error, "Could not find OpenSSL executable" unless openssl_path

    openssl_path
  end

  def find_in_path(cmd)
    exts = ENV['PATHEXT'] ? ENV['PATHEXT'].split(';') : ['']
    ENV['PATH'].split(File::PATH_SEPARATOR).each do |path|
      exts.each do |ext|
        exe = File.join(path, "#{cmd}#{ext}")
        return exe if File.executable?(exe) && !File.directory?(exe)
      end
    end
    nil
  end

  def escape_string(str)
    # Remove any potentially dangerous characters
    cleaned = str.gsub(/[^a-zA-Z0-9._-]/, '')

    # Ensure the string isn't empty and doesn't start with a dash
    if cleaned.empty? || cleaned.start_with?('-')
      raise Error, "Invalid string after sanitization: #{str}"
    end

    cleaned
  end
end
