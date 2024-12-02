module AutoSSL
  class Sandbox
    def self.isolate
      fork do
        Process.setsid
        Dir.chdir "/"
        File.umask(0o077)

        STDIN.reopen("/dev/null")
        STDOUT.reopen("/dev/null", "w")
        STDERR.reopen("/dev/null", "w")

        ResourceGuard.enforce_limits

        yield
      end
    end
  end
end
