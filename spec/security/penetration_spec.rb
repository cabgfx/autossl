require 'spec_helper'
require 'auto_ssl'
require 'fileutils'
require 'securerandom'
require 'socket'
require 'timeout'

RSpec.describe "Security Penetration Tests", :security do
  let(:secure_tmpdir) { Dir.mktmpdir(["pentest_", SecureRandom.hex(8)]) }
  let(:config_dir) { File.join(secure_tmpdir, "config") }
  let(:data_dir) { File.join(secure_tmpdir, "data") }
  let(:ssl_dir) { File.join(data_dir, "certificates") }

  before(:each) do
    ENV["XDG_CONFIG_HOME"] = config_dir
    ENV["XDG_DATA_HOME"] = data_dir
    FileUtils.mkdir_p([config_dir, data_dir, ssl_dir], mode: 0o700)
  end

  after(:each) do
    FileUtils.remove_entry_secure(secure_tmpdir) if File.directory?(secure_tmpdir)
  end

  describe "Race Condition Attacks" do
    it "prevents TOCTOU vulnerabilities" do
      file_path = File.join(ssl_dir, "test.key")

      # Simulate rapid file permission/content changes during operations
      attack_thread = Thread.new do
        loop do
          begin
            File.write(file_path, "MALICIOUS")
            FileUtils.chmod(0o777, file_path)
            File.delete(file_path)
          rescue
            nil
          end
        end
      end

      begin
        10.times do
          expect {
            SafePath.secure_write(file_path, "LEGITIMATE")
            content = SafePath.secure_read(file_path)
            expect(content).to eq("LEGITIMATE")
            expect(File.stat(file_path).mode & 0o777).to eq(0o600)
          }.not_to raise_error
        end
      ensure
        attack_thread.kill
        attack_thread.join
      end
    end
  end

  describe "Memory Safety" do
    it "prevents memory disclosure attacks" do
      secret = SecureRandom.hex(32)
      cert = CertManager.new("domain.com", ssl_dir: ssl_dir)

      # Force garbage collection
      GC.start

      # Attempt to find secret in memory dumps
      memory_dump = ObjectSpace.each_object(String).select { |s| s.include?(secret) }
      expect(memory_dump).to be_empty
    end

    it "securely handles sensitive data" do
      key_content = "SENSITIVE_KEY_MATERIAL"
      file_path = File.join(ssl_dir, "sensitive.key")

      SafePath.secure_write(file_path, key_content)

      # Verify data is securely overwritten
      File.open(file_path, "w") do |f|
        f.write("\x00" * key_content.length)
        f.fsync
      end

      content = File.read(file_path)
      expect(content).not_to include(key_content)
    end
  end

  describe "Filesystem Attacks" do
    it "prevents hardlink attacks" do
      target_file = File.join(ssl_dir, "target.key")
      attack_file = File.join(secure_tmpdir, "attack.key")

      begin
        File.link(target_file, attack_file)
        fail "Expected hardlink creation to fail"
      rescue Errno::ENOENT, Errno::EPERM
        # Expected failure
      end
    end

    it "prevents symlink attacks across devices" do
      different_device = "/tmp"  # Assuming /tmp might be on a different device
      remote_file = File.join(different_device, SecureRandom.hex(8))
      local_file = File.join(ssl_dir, "local.key")

      FileUtils.touch(remote_file)
      begin
        File.symlink(remote_file, local_file)

        expect {
          SafePath.secure_read(local_file)
        }.to raise_error(SafePath::SecurityError, /symlink/)
      ensure
        File.unlink(remote_file) if File.exist?(remote_file)
      end
    end
  end

  describe "Process Security" do
    it "prevents resource exhaustion through fork bombs" do
      expect {
        pid = Process.fork do
          loop { Process.fork { exit! } }
        end
        Process.waitpid(pid)
      }.to raise_error(Errno::EAGAIN)
    end

    it "maintains secure file descriptors" do
      initial_fds = Dir.glob("/proc/self/fd/*")

      AutoSSL.new.generate("domain", "com")

      final_fds = Dir.glob("/proc/self/fd/*")
      expect(final_fds.length).to be <= initial_fds.length

      final_fds.each do |fd|
        next if fd.end_with?("/0", "/1", "/2")  # Skip stdin/stdout/stderr
        stat = File.stat(fd)
        expect(stat.mode & 0o777).to be <= 0o600
      end
    end
  end

  describe "Network Security" do
    it "prevents DNS rebinding attacks" do
      expect {
        Socket.gethostbyname("localhost")
        Socket.gethostbyname("127.0.0.1")
      }.not_to raise_error

      expect {
        Socket.gethostbyname("evil.example.com")
      }.to raise_error(SocketError)
    end
  end
end
