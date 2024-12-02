require 'monitor'

module AutoSSL
  class CertificateOperation
    include MonitorMixin

    def initialize
      super() # Initialize MonitorMixin
      @operations = {}
      @resource_monitor = ResourceMonitor.new
    end

    def acquire_lock(domain)
      mon_synchronize do
        raise SecurityError, "Operation in progress" if @operations[domain]
        @operations[domain] = {
          started_at: Time.now,
          pid: Process.pid,
          thread_id: Thread.current.object_id
        }
      end
    end

    def release_lock(domain)
      mon_synchronize { @operations.delete(domain) }
    end

    def with_certificate_operation(domain)
      acquire_lock(domain)
      begin
        @resource_monitor.start_monitoring
        yield
      ensure
        @resource_monitor.stop_monitoring
        release_lock(domain)
      end
    end
  end

  class ResourceMonitor
    MEMORY_THRESHOLD = 0.85 # 85% of available memory
    CPU_THRESHOLD = 0.80    # 80% CPU utilization

    def start_monitoring
      @monitor_thread = Thread.new do
        while true
          current_memory = Process.memory
          current_cpu = Process.cpu_times.total

          if current_memory > MEMORY_THRESHOLD || current_cpu > CPU_THRESHOLD
            Process.kill('TERM', Process.pid)
          end

          sleep 0.1
        end
      end
    end

    def stop_monitoring
      @monitor_thread&.kill
      @monitor_thread&.join
    end
  end
end
