require 'monitor'

module AutoSSL
  class StateMachine
    include MonitorMixin

    STATES = %i[
      initialized
      validating
      generating_key
      generating_csr
      signing_certificate
      verifying
      completed
      failed
    ]

    class StateTransitionError < StandardError; end

    def initialize
      super() # Initialize MonitorMixin
      @state = :initialized
      @state_data = {}
      @audit_log = AuditLog.new
    end

    def transition_to(new_state, metadata = {})
      mon_synchronize do
        validate_transition(@state, new_state)
        old_state = @state
        @state_data[@state] = metadata.merge(
          timestamp: Time.now.utc,
          process_id: Process.pid,
          thread_id: Thread.current.object_id
        )

        begin
          yield if block_given?
          @state = new_state
          @audit_log.record_transition(old_state, new_state, :success)
        rescue => e
          @state = :failed
          @audit_log.record_transition(old_state, :failed, :error, error: e)
          raise StateTransitionError, "Failed transitioning from #{old_state} to #{new_state}: #{e.message}"
        end
      end
    end

    private

    def validate_transition(from, to)
      valid = case from
      when :initialized
        [:validating]
      when :validating
        [:generating_key, :failed]
      when :generating_key
        [:generating_csr, :failed]
      when :generating_csr
        [:signing_certificate, :failed]
      when :signing_certificate
        [:verifying, :failed]
      when :verifying
        [:completed, :failed]
      else
        []
      end

      unless valid.include?(to)
        raise StateTransitionError, "Invalid transition: #{from} -> #{to}"
      end
    end
  end

  class AuditLog
    def initialize
      @log_file = AtomicFile.new(File.join(ENV['XDG_DATA_HOME'], 'autossl', 'audit.log'))
    end

    def record_transition(from, to, result, metadata = {})
      entry = {
        timestamp: Time.now.utc,
        from_state: from,
        to_state: to,
        result: result,
        process_id: Process.pid,
        thread_id: Thread.current.object_id
      }.merge(metadata)

      @log_file.append(entry.to_json + "\n")
    end
  end
end
