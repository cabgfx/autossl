require 'spec_helper'
require 'auto_ssl'
require 'fileutils'
require 'securerandom'

RSpec.describe AutoSSL do
  # Use secure temporary directory creation
  let(:secure_tmpdir) { Dir.mktmpdir(["autossl_test_", SecureRandom.hex(8)]) }
  let(:config_dir) { File.join(secure_tmpdir, 'config') }
  let(:config_file) { File.join(config_dir, 'config.yml') }
  let(:ca_file) { File.join(secure_tmpdir, 'ca.crt') }
  let(:ca_key) { File.join(secure_tmpdir, 'ca.key') }
  let(:ssl_dir) { File.join(secure_tmpdir, 'ssl') }

  before(:each) do
    # Secure directory creation with proper permissions
    FileUtils.mkdir_p(config_dir, mode: 0o700)
    FileUtils.mkdir_p(ssl_dir, mode: 0o700)

    # Create test files with secure permissions
    File.write(ca_file, "TEST CA CERT")
    File.write(ca_key, "TEST CA KEY")
    FileUtils.chmod(0o600, [ca_file, ca_key])

    # Create test configuration
    config = {
      'ca_file' => ca_file,
      'ca_key' => ca_key,
      'ssl_dir' => ssl_dir,
      'memory_limit' => 512,
      'cpu_limit' => 80
    }

    File.write(config_file, YAML.dump(config))
    FileUtils.chmod(0o600, config_file)
  end

  after(:each) do
    # Secure cleanup
    FileUtils.remove_entry_secure(secure_tmpdir) if File.directory?(secure_tmpdir)
  end

  describe 'Security Validations' do
    it 'rejects insecure file permissions' do
      FileUtils.chmod(0o777, config_file)
      expect {
        described_class.new.load_config
      }.to raise_error(AutoSSL::SecurityError, /insecure permissions/)
    end

    it 'prevents directory traversal attacks' do
      malicious_path = File.join(ssl_dir, '../../../etc/passwd')
      expect {
        described_class.new.generate('example', 'com', ssl_dir: malicious_path)
      }.to raise_error(AutoSSL::SecurityError, /path traversal/)
    end

    it 'validates domain name format' do
      expect {
        described_class.new.generate('invalid!domain', 'com')
      }.to raise_error(AutoSSL::ValidationError, /Invalid domain/)
    end

    it 'enforces domain length limits' do
      long_domain = 'a' * 300
      expect {
        described_class.new.generate(long_domain, 'com')
      }.to raise_error(AutoSSL::ValidationError, /exceeds maximum length/)
    end
  end

  describe 'Resource Controls' do
    it 'enforces memory limits' do
      allow(SafetyChecks).to receive(:current_memory_usage).and_return(1024)
      expect {
        described_class.new.generate('example', 'com')
      }.to raise_error(SafetyChecks::ResourceError, /Memory usage exceeded/)
    end

    it 'enforces CPU limits' do
      allow(SafetyChecks).to receive(:current_cpu_usage).and_return(95)
      expect {
        described_class.new.generate('example', 'com')
      }.to raise_error(SafetyChecks::ResourceError, /CPU usage exceeded/)
    end
  end

  describe 'Certificate Generation' do
    let(:domain) { 'example' }
    let(:tld) { 'com' }
    let(:site) { "#{domain}.#{tld}" }

    it 'generates certificates with secure permissions' do
      allow(SecureCommand).to receive(:execute_command).and_return("OK")

      described_class.new.generate(domain, tld)

      cert_path = File.join(ssl_dir, "#{site}.crt")
      key_path = File.join(ssl_dir, "#{site}.key")

      expect(File.exist?(cert_path)).to be true
      expect(File.exist?(key_path)).to be true
      expect(File.stat(key_path).mode & 0o777).to eq(0o600)
      expect(File.stat(cert_path).mode & 0o777).to eq(0o600)
    end

    it 'validates certificate integrity' do
      allow(SecureCommand).to receive(:execute_command).and_return("OK")

      cert_manager = CertManager.new(site, ssl_dir: ssl_dir)
      expect {
        cert_manager.generate_certificates
      }.not_to raise_error

      key_path = File.join(ssl_dir, "#{site}.key")
      File.truncate(key_path, 0)

      expect {
        cert_manager.verify_key_security(key_path)
      }.to raise_error(SecurityError, /key validation failed/)
    end
  end

  describe 'Configuration Management' do
    it 'prevents loading oversized configurations' do
      large_config = { 'data' => 'x' * (AutoSSL::MAX_CONFIG_SIZE + 1) }
      File.write(config_file, YAML.dump(large_config))

      expect {
        described_class.new.load_config
      }.to raise_error(AutoSSL::SecurityError, /exceeds maximum size/)
    end

    it 'validates configuration values' do
      invalid_config = {
        'memory_limit' => 999999,
        'cpu_limit' => 200
      }
      File.write(config_file, YAML.dump(invalid_config))

      expect {
        described_class.new.validate_config!(invalid_config)
      }.to raise_error(AutoSSL::ValidationError, /Invalid .* limit/)
    end
  end
end
