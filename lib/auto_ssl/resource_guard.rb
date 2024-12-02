module AutoSSL
  class ResourceGuard
    def self.enforce_limits
      Process.setrlimit(Process::RLIMIT_AS, 512 * 1024 * 1024) # 512MB memory limit
      Process.setrlimit(Process::RLIMIT_CPU, 30) # 30 seconds CPU time
      Process.setrlimit(Process::RLIMIT_NOFILE, 256) # Max 256 file descriptors

      # Set process priority
      Process.setpriority(Process::PRIO_PROCESS, 0, 19)
    end
  end
end
