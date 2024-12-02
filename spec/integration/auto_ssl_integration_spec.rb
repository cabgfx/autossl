require 'spec_helper'
require 'auto_ssl'
require 'fileutils'
require 'securerandom'
require 'pathname'

RSpec.describe "AutoSSL Integration", :integration do
  let(:secure_tmpdir) { Dir.mktmpdir(["autossl_integration_", SecureRandom.hex(8)]) }
  let(:config_dir) { File.join(secure_tmpdir, "config") }
  let(:data_dir) { File.join(secure_tmpdir, "data") }
  let(:ssl_dir) { File.join(data_dir, "certificates") }
  let(:config_file) { File.join(config_dir, "config.yml") }
  let(:ca_file) { File.join(data_dir, "ca.crt") }
  let(:ca_key) { File.join(data_dir, "ca.key") }

  let(:test_domain) { "example" }
  let(:test_tld) { "com" }
  let(:test_site) { "#{test_domain}.#{test_tld}" }

  before(:all) do
    # Disable actual OpenSSL operations
    RSpec.configure do |config|
      config.before(:each) do
        allow(SecureCommand).to receive(:execute_command).and_return("TEST OUTPUT")
      end
    end
  end

  before(:each) do
    # Set up test environment
    ENV["XDG_CONFIG_HOME"] = config_dir
    ENV["XDG_DATA_HOME"] = data_dir

    # Create directories with secure permissions
    [config_dir, data_dir, ssl_dir].each do |dir|
      FileUtils.mkdir_p(dir, mode: 0o700)
    end

    # Create test CA files
    File.write(ca_file, "TEST CA CERT")
    File.write(ca_key, "TEST CA KEY")
    FileUtils.chmod(0o600, [ca_file, ca_key])

    # Create valid configuration
    config = {
      "ssl_dir" => ssl_dir,
      "ca_file" => ca_file,
      "ca_key" => ca_key,
      "memory_limit" => 512,
      "cpu_limit" => 80,
      "operation_rate" => 100,
      "timeout" => 30
    }
    SecureYAML.dump(config, config_file)
  end

  after(:each) do
    FileUtils.remove_entry_secure(secure_tmpdir) if File.directory?(secure_tmpdir)
  end

  describe "Certificate Generation Flow" do
    it "successfully generates certificates with proper security" do
      auto_ssl = AutoSSL.new
      expect { auto_ssl.generate(test_domain, test_tld) }.not_to raise_error

      # Verify generated files
      expected_files = %w[key csr crt].map { |ext| File.join(ssl_dir, "#{test_site}.#{ext}") }
      expected_files.each do |file|
        expect(File.exist?(file)).to be true
        expect(File.stat(file).mode & 0o777).to eq(0o600)
        expect(File.stat(file).owned?).to be true
      end
    end

    it "maintains security during concurrent operations" do
      threads = []
      results = Queue.new
      domains = 5.times.map { |i| "domain#{i}" }

      domains.each do |domain|
        threads << Thread.new do
          begin
            AutoSSL.new.generate(domain, test_tld)
            results.push([:success, domain])
          rescue => e
            results.push([:error, domain, e])
          end
        end
      end

      threads.each(&:join)
      errors = results.to_a.select { |r| r[0] == :error }
      expect(errors).to be_empty, "Concurrent operations failed: #{errors.inspect}"
    end

    it "handles resource exhaustion gracefully" do
      allow(SafetyChecks).to receive(:check_system_resources)
        .and_raise(SafetyChecks::ResourceError, "Low memory")

      expect {
        AutoSSL.new.generate(test_domain, test_tld)
      }.to raise_error(Thor::Error, /Certificate generation failed/)

      # Verify no partial files were left behind
      Dir.glob(File.join(ssl_dir, "*")).each do |file|
        expect(File.stat(file).mode & 0o777).to eq(0o600)
      end
    end
  end

  describe "Security Boundaries" do
    it "prevents privilege escalation attempts" do
      injection_attempts = [
        ["../../../root/.ssh/authorized_keys", "com"],
        ["domain", "com/../../../etc/passwd"],
        ["domain; rm -rf /", "com"],
        ["domain", "com; touch /tmp/pwned"]
      ]

      injection_attempts.each do |domain, tld|
        expect {
          AutoSSL.new.generate(domain, tld)
        }.to raise_error(Thor::Error, /validation|security/i)
      end
    end

    it "maintains file security during errors" do
      allow(CertManager).to receive(:new).and_raise(StandardError, "Simulated failure")

      expect {
        AutoSSL.new.generate(test_domain, test_tld)
      }.to raise_error(Thor::Error)

      [config_dir, data_dir, ssl_dir].each do |dir|
        expect(File.stat(dir).mode & 0o777).to eq(0o700)
      end

      [config_file, ca_file, ca_key].each do |file|
        next unless File.exist?(file)
        expect(File.stat(file).mode & 0o777).to eq(0o600)
      end
    end
  end

  describe "Resource Management" do
    it "cleans up resources after operations" do
      initial_fds = Dir.glob("/proc/#{Process.pid}/fd/*").length

      AutoSSL.new.generate(test_domain, test_tld)

      # Allow for GC to run
      GC.start
      sleep 0.1

      final_fds = Dir.glob("/proc/#{Process.pid}/fd/*").length
      expect(final_fds).to be <= initial_fds
    end

    it "respects system resource limits" do
      resource_checks = []
      allow(SafetyChecks).to receive(:check_system_resources) do
        resource_checks << Time.now
        true
      end

      AutoSSL.new.generate(test_domain, test_tld)

      expect(resource_checks.length).to be > 0
      expect(resource_checks.each_cons(2).all? { |a, b| b - a >= 1 }).to be true
    end
  end
end
