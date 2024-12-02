require "pathname"
require "logger"
require "digest"
require "timeout"
require "concurrent"
require "etc"
require "fiddle"
require "rbconfig"
require "monitor"
require "yaml"

module SafetyChecks
  class Error < StandardError; end

  class PathError < Error; end

  class OwnershipError < Error; end

  class SpaceError < Error; end

  class SecurityError < Error; end

  class TimeoutError < Error; end

  class IntegrityError < Error; end

  class ConcurrencyError < Error; end

  class ResourceError < Error; end

  class CircuitBreakerError < Error; end

  class SystemError < Error; end

  MAX_PATH_LENGTH = 4096  # Common filesystem limit
  MIN_FREE_SPACE = 1024 * 1024 * 10  # 10MB minimum free space
  OPERATION_TIMEOUT = 30  # 30 seconds
  MAX_SYMLINKS = 20  # Maximum number of symlinks to follow
  CHECKSUM_ALGO = Digest::SHA256
  RATE_LIMIT_INTERVAL = 1  # 1 second
  MAX_OPERATIONS = 100  # Maximum operations per interval
  MAX_MEMORY_USAGE = 1024 * 1024 * 512  # 512MB
  MAX_CPU_USAGE = 80  # 80%
  CIRCUIT_BREAKER_THRESHOLD = 5  # Number of failures before breaking
  CIRCUIT_BREAKER_TIMEOUT = 60  # Time to wait before retrying
  RESOURCE_CHECK_INTERVAL = 1  # Check resources every second

  # Platform detection
  OS = case RbConfig::CONFIG["host_os"]
  when /darwin/ then :macos
  when /linux/ then :linux
  when /bsd/ then :bsd
  when /mswin|mingw|cygwin/ then :windows
  else :unknown
  end

  # System interfaces
  case OS
  when :macos
    begin
      HOST_VM_STATS = Fiddle::Handle.new
      HOST_VM_STATS_COUNT = Fiddle::Handle.new("host_vm_stats")
      MACH_HOST_SELF = Fiddle::Handle.new("mach_host_self")
    rescue Fiddle::DLError
      # Fallback to sysctl if dynamic linking fails
    end
  when :linux
    PROC_MEMINFO = "/proc/meminfo"
    PROC_STAT = "/proc/stat"
  when :windows
    begin
      KERNEL32 = Fiddle::Handle.new("kernel32")
      PSAPI = Fiddle::Handle.new("psapi")
      GLOBAL_MEMORY_STATUS = Fiddle::Function.new(
        KERNEL32["GlobalMemoryStatusEx"],
        [Fiddle::TYPE_VOIDP],
        Fiddle::TYPE_INT
      )
    rescue Fiddle::DLError
      # Fallback to Win32API if available
    end
  end

  @monitor = Monitor.new
  @shutdown = false
  @resource_monitor = nil
  @at_exit_handler_installed = false

  # Thread-safe state management
  @operation_count = Concurrent::AtomicFixnum.new(0)
  @last_reset = Concurrent::AtomicReference.new(Time.now)
  @locks = Concurrent::Map.new
  @failure_counts = Concurrent::Map.new
  @circuit_states = Concurrent::Map.new
  @last_resource_check = Concurrent::AtomicReference.new(Time.now)

  class StateManager
    include MonitorMixin

    def initialize(state_file)
      super()
      @state_file = state_file
      @state = load_state
      @transaction_log = "#{state_file}.log"
    end

    def update
      synchronize do
        # Write intent to transaction log
        log_transaction { yield @state }

        # Commit changes
        save_state

        # Clear transaction log
        clear_transaction_log
      rescue => e
        # Rollback on failure
        rollback
        raise
      end
    end

    private

    def load_state
      if File.exist?(@transaction_log)
        # Recover from interrupted transaction
        recover_from_transaction
      elsif File.exist?(@state_file)
        # Load existing state
        YAML.safe_load_file(@state_file, permitted_classes: [Symbol, Time])
      else
        # Initialize new state
        {
          failure_counts: {},
          circuit_states: {},
          operation_counts: {},
          last_reset: Time.now
        }
      end
    end

    def log_transaction
      # Create transaction log with temporary state
      temp_state = Marshal.dump(@state)
      File.write(@transaction_log, temp_state)

      # Apply changes
      yield

      # Update transaction log with new state
      File.write(@transaction_log, Marshal.dump(@state))
    end

    def save_state
      # Write state to temporary file
      temp_file = "#{@state_file}.tmp"
      File.write(temp_file, YAML.dump(@state))

      # Ensure data is on disk
      File.open(temp_file, "r+") { |f| f.fsync }

      # Atomic rename
      File.rename(temp_file, @state_file)
    end

    def clear_transaction_log
      File.unlink(@transaction_log) if File.exist?(@transaction_log)
    end

    def recover_from_transaction
      # Load last known good state from transaction log
      @state = Marshal.load(File.read(@transaction_log))

      # Commit recovery
      save_state
      clear_transaction_log
    rescue => e
      logger.error("Failed to recover from transaction: #{e.message}")
      # Initialize fresh state on recovery failure
      @state = {}
    end

    def rollback
      @state = if File.exist?(@state_file)
        YAML.safe_load_file(@state_file, permitted_classes: [Symbol, Time])
      else
        {}
      end
      clear_transaction_log
    end
  end

  # Initialize state manager
  STATE_FILE = File.join(SafePath.data_home, "safety_checks_state.yml")
  @state_manager = StateManager.new(STATE_FILE)

  def self.update_state
    @state_manager.update { |state| yield state }
  end

  def self.logger
    @logger ||= Logger.new(File.join(SafePath.data_home, "autossl.log")).tap do |log|
      log.level = Logger::INFO
      log.formatter = proc do |severity, datetime, progname, msg|
        "[#{datetime}] #{severity} #{msg}\n"
      end
    end
  end

  def self.install_cleanup_handler
    return if @at_exit_handler_installed

    synchronize do
      return if @at_exit_handler_installed
      at_exit { cleanup }
      @at_exit_handler_installed = true
    end
  end

  def self.cleanup
    synchronize do
      return if @shutdown
      @shutdown = true
      stop_resource_monitor
      clear_state
    end
  end

  def self.clear_state
    @operation_count.set(0)
    @failure_counts.clear
    @circuit_states.clear
    @locks.each_value(&:unlock)
    @locks.clear
  end

  module_function

  def start_resource_monitor
    return if @resource_monitor

    monitor = Thread.new do
      loop do
        check_system_resources
        sleep(RESOURCE_CHECK_INTERVAL)
      end
    end

    @resource_monitor = monitor
  end

  def stop_resource_monitor
    monitor = @resource_monitor
    if monitor
      monitor.exit
      @resource_monitor = nil
    end
  end

  def check_system_resources
    return if @shutdown

    now = Time.now
    last_check = @last_resource_check.get
    return if now - last_check < RESOURCE_CHECK_INTERVAL

    @monitor.synchronize do
      available_mem, total_mem = get_system_memory
      if available_mem < MAX_MEMORY_USAGE
        logger.error("Memory usage critical: #{available_mem} bytes available")
        raise ResourceError, "Insufficient memory available"
      end

      cpu_usage = get_system_cpu
      if cpu_usage > MAX_CPU_USAGE
        logger.error("CPU usage critical: #{cpu_usage}%")
        raise ResourceError, "CPU usage too high"
      end

      @last_resource_check.set(now)
    end
  end

  def get_system_memory
    case OS
    when :linux
      get_linux_memory
    when :macos
      get_macos_memory
    when :windows
      get_windows_memory
    else
      get_fallback_memory
    end
  rescue => e
    logger.error("Failed to get system memory: #{e.message}")
    raise SystemError, "Memory check failed: #{e.message}"
  end

  def get_system_cpu
    case OS
    when :linux
      get_linux_cpu
    when :macos
      get_macos_cpu
    when :windows
      get_windows_cpu
    else
      get_fallback_cpu
    end
  rescue => e
    logger.error("Failed to get CPU usage: #{e.message}")
    raise SystemError, "CPU check failed: #{e.message}"
  end

  def get_linux_memory
    return unless File.readable?(PROC_MEMINFO)

    mem_info = File.read(PROC_MEMINFO)
    available = mem_info[/MemAvailable:\s+(\d+)/, 1].to_i * 1024
    total = mem_info[/MemTotal:\s+(\d+)/, 1].to_i * 1024
    [available, total]
  end

  def get_macos_memory
    if defined?(HOST_VM_STATS)
      # Use native memory pressure API
      # Implementation omitted for brevity but would use host_statistics64
    else
      # Fallback to sysctl
      total = `sysctl -n hw.memsize`.to_i
      vm_stats = `vm_stat`
      free_pages = vm_stats[/Pages free:\s+(\d+)/, 1].to_i
      available = free_pages * 4096  # Page size
      [available, total]
    end
  end

  def get_windows_memory
    if defined?(GLOBAL_MEMORY_STATUS)
      # Use native Windows API
      memory_status = " " * 64  # MEMORYSTATUSEX struct
      memory_status[0, 4] = [64].pack("L")  # dwLength
      GLOBAL_MEMORY_STATUS.call(memory_status)
      available = memory_status[40, 8].unpack1("Q")  # ullAvailPhys
      total = memory_status[8, 8].unpack1("Q")      # ullTotalPhys
      [available, total]
    else
      get_fallback_memory
    end
  end

  def get_fallback_memory
    # Last resort: use Ruby's memory reporting
    gc_stats = GC.stat
    available = gc_stats[:heap_available_slots] * GC::INTERNAL_CONSTANTS[:RVALUE_SIZE]
    total = gc_stats[:heap_allocated_pages] * GC::INTERNAL_CONSTANTS[:HEAP_PAGE_SIZE]
    [available, total]
  end

  def with_circuit_breaker(operation)
    check_circuit_breaker(operation)

    begin
      result = yield
      reset_failure_count(operation)
      result
    rescue Error => e
      record_failure(operation)
      raise
    end
  end

  def check_circuit_breaker(operation)
    state = nil
    self.class.update_state do |s|
      state = s[:circuit_states][operation]
    end

    if state
      last_failure_time, is_open = state
      if is_open
        if Time.now - last_failure_time < CIRCUIT_BREAKER_TIMEOUT
          logger.error("Circuit breaker open for operation: #{operation}")
          raise CircuitBreakerError, "Circuit breaker open for: #{operation}"
        else
          reset_failure_count(operation)
        end
      end
    end
  end

  def record_failure(operation)
    self.class.update_state do |state|
      count = (state[:failure_counts][operation] || 0) + 1
      state[:failure_counts][operation] = count

      if count >= CIRCUIT_BREAKER_THRESHOLD
        state[:circuit_states][operation] = [Time.now, true]
        logger.warn("Circuit breaker tripped for operation: #{operation}")
      end
    end
  end

  def reset_failure_count(operation)
    self.class.update_state do |state|
      state[:failure_counts].delete(operation)
      state[:circuit_states].delete(operation)
    end
  end

  def with_timeout(operation_name, timeout = OPERATION_TIMEOUT)
    Timeout.timeout(timeout, TimeoutError) { yield }
  rescue TimeoutError
    logger.error("Operation timed out: #{operation_name}")
    raise TimeoutError, "Operation timed out: #{operation_name}"
  end

  def with_rate_limit
    now = Time.now
    last = @last_reset.get

    if now - last >= RATE_LIMIT_INTERVAL
      @operation_count.set(0)
      @last_reset.set(now)
    end

    count = @operation_count.increment
    if count > MAX_OPERATIONS
      logger.error("Rate limit exceeded: #{MAX_OPERATIONS} operations per #{RATE_LIMIT_INTERVAL} second(s)")
      raise SecurityError, "Rate limit exceeded"
    end

    yield
  end

  def with_file_lock(path)
    lock = @locks.compute_if_absent(path) { Concurrent::ReentrantReadWriteLock.new }

    begin
      unless lock.try_write_lock(OPERATION_TIMEOUT)
        logger.error("Failed to acquire lock for: #{path}")
        raise ConcurrencyError, "Failed to acquire lock"
      end
      yield
    ensure
      lock.unlock
      @locks.delete(path) if lock.write_locks == 0 && lock.read_locks == 0
    end
  end

  # Wrap all existing methods with circuit breaker and resource monitoring
  [:validate_ownership!, :validate_path_length!, :validate_available_space!,
    :compute_checksum, :verify_integrity!, :sanitize_filename, :validate_in_directory!,
    :check_symlink!, :validate_permissions!, :secure_directory?, :secure_file?].each do |method_name|
    original_method = instance_method(method_name)
    define_method(method_name) do |*args, &block|
      with_circuit_breaker(method_name) do
        check_system_resources
        original_method.bind_call(self, *args, &block)
      end
    end
  end

  def validate_ownership!(path)
    with_rate_limit do
      with_timeout("validate_ownership") do
        real_path = Pathname.new(path).realpath
        unless File.owned?(real_path)
          logger.error("Path not owned by current user: #{path}")
          raise OwnershipError, "Path not owned by current user: #{path}"
        end
        real_path
      end
    end
  rescue Errno::ENOENT
    logger.error("Path does not exist: #{path}")
    raise PathError, "Path does not exist: #{path}"
  end

  def validate_path_length!(path)
    with_rate_limit do
      if path.to_s.length > MAX_PATH_LENGTH
        logger.error("Path exceeds maximum length of #{MAX_PATH_LENGTH} characters: #{path}")
        raise PathError, "Path exceeds maximum length of #{MAX_PATH_LENGTH} characters: #{path}"
      end
    end
  end

  def validate_available_space!(path, required_bytes = MIN_FREE_SPACE)
    with_rate_limit do
      with_timeout("validate_space") do
        stat = Pathname.new(path).realpath.dirname.stat
        available_space = stat.block_size * stat.blocks_available
        if available_space < required_bytes
          logger.error("Insufficient disk space. Required: #{required_bytes}, Available: #{available_space}")
          raise SpaceError, "Insufficient disk space. Required: #{required_bytes}, Available: #{available_space}"
        end
      end
    end
  rescue Errno::ENOENT
    logger.error("Path does not exist: #{path}")
    raise PathError, "Path does not exist: #{path}"
  end

  def compute_checksum(path)
    with_timeout("compute_checksum") do
      CHECKSUM_ALGO.file(path).hexdigest
    end
  rescue => e
    logger.error("Failed to compute checksum for #{path}: #{e.message}")
    raise IntegrityError, "Failed to compute checksum: #{e.message}"
  end

  def verify_integrity!(path, expected_checksum)
    with_rate_limit do
      with_timeout("verify_integrity") do
        actual_checksum = compute_checksum(path)
        unless actual_checksum == expected_checksum
          logger.error("Integrity check failed for #{path}")
          raise IntegrityError, "File integrity check failed"
        end
      end
    end
  end

  def sanitize_filename(filename)
    with_rate_limit do
      # Remove any directory separators and null bytes
      clean = filename.gsub(%r{[/\\]}, "").delete("\0")
      # Remove any non-printable characters
      clean = clean.gsub(/[^[:print:]]/, "")
      # Limit to safe characters
      clean = clean.gsub(/[^a-zA-Z0-9._-]/, "")
      # Ensure it doesn't start with a dash or dot
      clean = clean.gsub(/^[-.]/, "")

      if clean.empty? || clean != filename
        logger.error("Invalid filename after sanitization: #{filename}")
        raise SecurityError, "Invalid filename after sanitization: #{filename}"
      end
      clean
    end
  end

  def validate_in_directory!(path, directory)
    with_rate_limit do
      with_timeout("validate_directory") do
        path_real = Pathname.new(path).realpath
        dir_real = Pathname.new(directory).realpath

        unless path_real.ascend.any? { |p| p == dir_real }
          logger.error("Path escapes directory: #{path} not in #{directory}")
          raise SecurityError, "Path escapes directory: #{path} not in #{directory}"
        end
        path_real
      end
    end
  rescue Errno::ENOENT
    logger.error("Path or directory does not exist")
    raise PathError, "Path or directory does not exist"
  end

  def check_symlink!(path)
    with_rate_limit do
      with_timeout("check_symlink") do
        path_obj = Pathname.new(path)
        symlink_count = 0

        path_obj.each_filename do |component|
          current_path = path_obj.dirname + component
          if current_path.symlink?
            symlink_count += 1
            if symlink_count > MAX_SYMLINKS
              logger.error("Too many symbolic links: #{path}")
              raise SecurityError, "Too many symbolic links"
            end
            logger.error("Path component is a symbolic link: #{current_path}")
            raise SecurityError, "Path component is a symbolic link: #{current_path}"
          end
        end
        path_obj.realpath
      end
    end
  rescue Errno::ENOENT
    logger.error("Path does not exist: #{path}")
    raise PathError, "Path does not exist: #{path}"
  end

  def validate_permissions!(path, required_mode)
    with_rate_limit do
      with_timeout("validate_permissions") do
        with_file_lock(path) do
          stat = File.stat(path)
          actual_mode = stat.mode & 0o777
          unless (actual_mode & required_mode) == required_mode
            logger.error("Incorrect permissions on #{path}: #{actual_mode.to_s(8)} (required: #{required_mode.to_s(8)})")
            raise SecurityError, "Incorrect permissions on #{path}: #{actual_mode.to_s(8)} (required: #{required_mode.to_s(8)})"
          end
        end
      end
    end
  rescue Errno::ENOENT
    logger.error("Path does not exist: #{path}")
    raise PathError, "Path does not exist: #{path}"
  end

  def secure_directory?(dir)
    with_rate_limit do
      with_timeout("check_directory") do
        stat = File.stat(dir)
        return false unless stat.directory?
        return false unless stat.owned?
        return false unless (stat.mode & 0o777) <= 0o700
        true
      end
    end
  rescue
    logger.warn("Failed to verify directory security: #{dir}")
    false
  end

  def secure_file?(file)
    with_rate_limit do
      with_timeout("check_file") do
        stat = File.stat(file)
        return false unless stat.file?
        return false unless stat.owned?
        return false unless (stat.mode & 0o777) <= 0o600
        true
      end
    end
  rescue
    logger.warn("Failed to verify file security: #{file}")
    false
  end

  private

  def logger
    self.class.logger
  end

  # Install cleanup handler when module is loaded
  install_cleanup_handler
end
