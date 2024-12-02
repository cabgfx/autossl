require 'logger'

# The SafetyChecks module provides methods to ensure system resources and paths adhere to defined safety constraints.
module SafetyChecks
  # Custom error classes for specific security violations
  class ResourceError < StandardError; end
  class PathLengthError < StandardError; end
  class SecurityError < StandardError; end
  class CircuitBreakerError < StandardError; end

  # System constraints
  MAX_PATH_LENGTH = 255
  MAX_MEMORY_USAGE = 512  # MB
  MAX_CPU_USAGE = 80      # Percentage
  MAX_DISK_USAGE = 95     # Percentage

  # Critical thresholds
  CRITICAL_MEMORY_THRESHOLD = 0.85  # 85% of MAX_MEMORY_USAGE
  CRITICAL_CPU_THRESHOLD = 0.90     # 90% of MAX_CPU_USAGE
  CRITICAL_DISK_THRESHOLD = 0.95    # 95% of MAX_DISK_USAGE

  # Circuit breaker configuration
  FAILURE_THRESHOLD = 3
  RESET_TIMEOUT = 300  # 5 minutes

  # Class variable to track circuit breaker state
  @circuit_breakers = {}
  @monitoring_thread = nil
  @monitor_mutex = Mutex.new

  class << self
    attr_reader :circuit_breakers, :monitor_mutex
  end

  def self.logger
    @logger ||= begin
      logger = Logger.new(File.join(SafePath::DATA_HOME, "autossl.log"))
      logger.level = Logger::INFO
      logger.formatter = proc do |severity, datetime, progname, msg|
        "#{datetime.utc.iso8601} [#{severity}] [PID:#{Process.pid}] #{msg}\n"
      end
      logger
    end
  end

  def self.check_system_resources
    check_memory_usage
    check_cpu_usage
    check_file_descriptors
    check_disk_space
  end

  def self.validate_path_length!(path)
    absolute_path = File.expand_path(path)
    if absolute_path.length > MAX_PATH_LENGTH
      msg = "Path length exceeds maximum allowed (#{MAX_PATH_LENGTH}): #{absolute_path}"
      logger.error(msg)
      raise PathLengthError, msg
    end
  end

  def self.validate_permissions!(path, required_mode)
    actual_mode = File.stat(path).mode & 0o777
    unless actual_mode <= required_mode
      raise SecurityError, "Insecure permissions on #{path}: #{actual_mode.to_s(8)} > #{required_mode.to_s(8)}"
    end
  end

  def self.validate_ownership!(path)
    stat = File.stat(path)
    unless stat.owned?
      raise SecurityError, "File #{path} not owned by current user"
    end
  end

  def self.start_monitoring
    monitor_mutex.synchronize do
      return if @monitoring_thread&.alive?

      @monitoring_thread = Thread.new do
        begin
          loop do
            check_system_resources
            cleanup_circuit_breakers
            sleep 60  # Check every minute
          end
        rescue => e
          logger.error("Monitoring thread error: #{e.message}")
          retry
        end
      end
    end
  end

  def self.stop_monitoring
    monitor_mutex.synchronize do
      if @monitoring_thread&.alive?
        @monitoring_thread.exit
        @monitoring_thread = nil
      end
    end
  end

  private

  def self.current_memory_usage
    `ps -o rss= -p #{Process.pid}`.to_i / 1024
  end

  def self.current_cpu_usage
    Process.times.total
  end

  def self.check_memory_usage(limit = 512)
    usage = current_memory_usage
    if usage > limit
      raise ResourceError, "Memory usage exceeded: #{usage}MB > #{limit}MB"
    end
  end

  def self.check_cpu_usage(limit = 80)
    usage = current_cpu_usage
    if usage > limit
      raise ResourceError, "CPU usage exceeded: #{usage}% > #{limit}%"
    end
  end

  def self.check_file_descriptors(max = 256)
    count = Dir.glob("/proc/#{Process.pid}/fd/*").length
    if count > max
      raise ResourceError, "Too many open files: #{count} > #{max}"
    end
  end

  def self.check_disk_space(path = Dir.pwd, min_space = 100 * 1024 * 1024)
    stat = File.stat(path)
    available = stat.dev
    if available < min_space
      raise ResourceError, "Insufficient disk space: #{available} < #{min_space} bytes"
    end
  end

  def self.cleanup_circuit_breakers
    circuit_breakers.delete_if do |operation, state|
      state[:last_failure] < Time.now - RESET_TIMEOUT
    end
  end
end
