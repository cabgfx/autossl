require "open3"
require "shellwords"
require "rbconfig"
require "logger"
require "timeout"
require "digest"

module SecureCommand
  class Error < StandardError; end
  class CommandError < Error; end
  class SecurityError < Error; end
  class TimeoutError < Error; end

  # Security constants
  MAX_COMMAND_LENGTH = 4096
  MAX_OUTPUT_SIZE = 10 * 1024 * 1024  # 10MB
  EXECUTION_TIMEOUT = 300  # 5 minutes
  MAX_RETRIES = 3

  # Paths to the OpenSSL executable based on the host OS
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
                      "/usr/local/bin/openssl"
                    ]
                  else
                    []
                  end.freeze

  # Allowed OpenSSL commands
  ALLOWED_COMMANDS = %w[
    genrsa
    req
    x509
    verify
    dgst
    enc
  ].freeze

  class << self
    def logger
      @logger ||= begin
        logger = Logger.new(File.join(SafePath::DATA_HOME, "autossl.log"))
        logger.level = Logger::INFO
        logger.formatter = proc do |severity, datetime, progname, msg|
          "[#{datetime.utc.iso8601}] [#{severity}] [CMD] [#{Process.pid}] #{msg}\n"
        end
        logger
      end
    end

    def openssl_executable
      @openssl_executable ||= begin
        path = OPENSSL_PATHS.find { |p| File.executable?(p) }
        unless path
          raise SecurityError, "OpenSSL executable not found in approved paths"
        end

        # Verify OpenSSL binary integrity
        verify_openssl_binary(path)
        path
      end
    end

    def execute_command(*args, working_dir: nil, timeout: EXECUTION_TIMEOUT)
      # Validate command and arguments
      validate_command!(*args)

      # Prepare command with full path to OpenSSL
      full_command = [openssl_executable, *args]

      # Change to working directory if specified
      Dir.chdir(working_dir || Dir.pwd) do
        execute_with_safety(*full_command, timeout: timeout)
      end
    end

    private

    def validate_command!(*args)
      # Validate command length
      command_str = args.join(' ')
      if command_str.length > MAX_COMMAND_LENGTH
        raise SecurityError, "Command length exceeds maximum allowed"
      end

      # Validate OpenSSL subcommand
      subcommand = args.first.to_s.downcase
      unless ALLOWED_COMMANDS.include?(subcommand)
        raise SecurityError, "Unauthorized OpenSSL command: #{subcommand}"
      end

      # Check for shell metacharacters
      args.each do |arg|
        if arg.to_s =~ /[;&|`$><]/
          raise SecurityError, "Command contains prohibited characters"
        end
      end
    end

    def execute_with_safety(*command, timeout: EXECUTION_TIMEOUT)
      output = ""
      error = ""
      exit_status = nil
      retries = 0

      begin
        # Set resource limits
        Process.setrlimit(Process::RLIMIT_CPU, 30, 30) # 30 seconds CPU time
        Process.setrlimit(Process::RLIMIT_NOFILE, 1024, 1024) # File descriptor limit

        Timeout.timeout(timeout) do
          Open3.popen3(*command) do |stdin, stdout, stderr, wait_thread|
            # Close stdin immediately
            stdin.close

            # Read output with size limits
            output = read_with_limit(stdout, MAX_OUTPUT_SIZE)
            error = read_with_limit(stderr, MAX_OUTPUT_SIZE)

            exit_status = wait_thread.value
          end
        end

        unless exit_status.success?
          raise CommandError, "Command failed: #{error}"
        end

        output
      rescue Timeout::Error
        Process.kill('TERM', wait_thread.pid) if defined?(wait_thread) && wait_thread
        raise TimeoutError, "Command execution timed out"
      rescue => e
        retries += 1
        if retries < MAX_RETRIES
          logger.warn("Command failed, retrying (#{retries}/#{MAX_RETRIES}): #{e.message}")
          sleep(retries)  # Exponential backoff
          retry
        else
          raise CommandError, "Command failed after #{MAX_RETRIES} attempts: #{e.message}"
        end
      ensure
        # Clean up any temporary files or resources
        cleanup_resources
      end
    end

    def read_with_limit(io, limit)
      result = ""
      bytes_read = 0

      while chunk = io.read(8192)
        bytes_read += chunk.bytesize
        if bytes_read > limit
          raise SecurityError, "Command output exceeds size limit"
        end
        result << chunk
      end

      result
    end

    def verify_openssl_binary(path)
      # Get file hash
      file_hash = Digest::SHA256.file(path).hexdigest

      # Compare with known good hash or verify signature
      # This should be implemented according to your security requirements
      # For example, verifying against a trusted hash database or checking code signatures

      stat = File.stat(path)
      unless stat.owned? && (stat.mode & 0o777) <= 0o755
        raise SecurityError, "OpenSSL binary has incorrect permissions"
      end
    end

    def cleanup_resources
      # Ensure all file handles are closed
      ObjectSpace.each_object(File) do |f|
        next if f.closed?
        next if [STDIN, STDOUT, STDERR].include?(f)
        f.close
      end

      # Force garbage collection
      GC.start
    end
  end
end

