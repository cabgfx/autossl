require 'open3'
require 'timeout'

module AutoSSL
  class SecureCommand
    ALLOWED_COMMANDS = {
      'openssl' => {
        allowed_args: %w[genrsa req x509 verify],
        allowed_options: %w[-new -key -out -subj -days -rand],
        path: '/usr/bin/openssl'
      }
    }.freeze

    class CommandError < StandardError; end
    class SecurityError < StandardError; end

    def self.execute_command(*args, timeout: 30, working_dir: nil)
      command = args.first
      validate_command!(command, args)

      # Use explicit path to prevent PATH manipulation attacks
      command_path = ALLOWED_COMMANDS[command][:path]

      # Prepare clean environment
      env = {
        'PATH' => '/usr/bin:/bin',
        'HOME' => '/nonexistent',
        'LANG' => 'C',
        'SSL_CERT_DIR' => OpenSSL::X509::DEFAULT_CERT_DIR
      }

      # Prepare command with explicit paths
      full_command = [command_path, *args[1..]]

      # Set up execution options
      options = {
        chdir: working_dir,
        unsetenv_others: true
      }

      begin
        Timeout.timeout(timeout) do
          stdout, stderr, status = Open3.capture3(env, *full_command, options)

          unless status.success?
            raise CommandError, "Command failed: #{stderr}"
          end

          stdout
        end
      rescue Timeout::Error
        Process.kill('TERM', status.pid) if status&.pid
        raise CommandError, "Command timed out after #{timeout} seconds"
      end
    end

    private

    def self.validate_command!(command, args)
      unless ALLOWED_COMMANDS.key?(command)
        raise SecurityError, "Command not allowed: #{command}"
      end

      command_config = ALLOWED_COMMANDS[command]

      args[1..].each do |arg|
        next if arg.start_with?('-') && command_config[:allowed_options].include?(arg)
        next if command_config[:allowed_args].include?(arg)

        if arg.match?(/[;&|]/)
          raise SecurityError, "Command injection attempt detected"
        end

        unless arg.match?(/\A[a-zA-Z0-9_\-\.\/]+\z/)
          raise SecurityError, "Invalid argument format: #{arg}"
        end
      end
    end
  end
end
