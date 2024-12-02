module AutoSSL
  class AtomicFile
    def self.write(path, content)
      temp_path = "#{path}.#{SecureRandom.hex(8)}.tmp"
      File.open(temp_path, File::RDWR | File::CREAT, 0o600) do |f|
        f.flock(File::LOCK_EX)
        f.write(content)
        f.flush
        f.fsync
      end

      File.rename(temp_path, path)
    rescue
      File.unlink(temp_path) if File.exist?(temp_path)
      raise
    end
  end
end
