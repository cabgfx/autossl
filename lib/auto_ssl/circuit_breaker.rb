require 'monitor'
require 'concurrent'

module AutoSSL
  class CircuitBreaker
    include MonitorMixin

    FAILURE_THRESHOLD = 5
    RESET_TIMEOUT = 30
    HALF_OPEN_TIMEOUT = 5

    States = Struct.new(:closed, :open, :half_open) do
      def initialize
        super(:closed, :open, :half_open)
      end
    end

    STATE = States.new

    def initialize
      super() # Initialize MonitorMixin
      @state = STATE.closed
      @failure_count = Concurrent::AtomicFixnum.new(0)
      @last_failure_time = Concurrent::AtomicReference.new(nil)
      @last_attempt_time = Concurrent::AtomicReference.new(nil)
    end

    def protect
      mon_synchronize do
        case @state
        when STATE.open
          handle_open_state
        when STATE.half_open
          handle_half_open_state
        end

        begin
          result = yield
          handle_success
          result
        rescue => error
          handle_failure(error)
          raise CircuitOpenError, "Circuit breaker is open: #{error.message}"
        end
      end
    end

    private

    def handle_open_state
      if ready_to_try?
        @state = STATE.half_open
      else
        raise CircuitOpenError, "Circuit breaker is open"
      end
    end

    def handle_half_open_state
      if @last_attempt_time.get &&
         Time.now - @last_attempt_time.get < HALF_OPEN_TIMEOUT
        raise CircuitOpenError, "Circuit breaker is recovering"
      end
    end

    def handle_success
      @failure_count.value = 0
      @state = STATE.closed if @state == STATE.half_open
      @last_attempt_time.set(Time.now)
    end

    def handle_failure(error)
      @failure_count.increment
      @last_failure_time.set(Time.now)
      @last_attempt_time.set(Time.now)

      if @failure_count.value >= FAILURE_THRESHOLD
        @state = STATE.open
      end
    end

    def ready_to_try?
      last_failure = @last_failure_time.get
      last_failure && Time.now - last_failure >= RESET_TIMEOUT
    end
  end

  class RateLimiter
    include MonitorMixin

    def initialize(max_requests:, time_window:)
      super() # Initialize MonitorMixin
      @max_requests = max_requests
      @time_window = time_window
      @requests = Concurrent::Array.new
    end

    def allow_request?
      mon_synchronize do
        now = Time.now
        cleanup_old_requests(now)

        if @requests.size < @max_requests
          @requests << now
          true
        else
          false
        end
      end
    end

    def wait_for_slot
      loop do
        return if allow_request?
        sleep 0.1
      end
    end

    private

    def cleanup_old_requests(now)
      cutoff = now - @time_window
      @requests.delete_if { |time| time < cutoff }
    end
  end
end
