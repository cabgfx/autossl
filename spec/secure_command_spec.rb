require 'spec_helper'
require 'secure_command'
require 'securerandom'
require 'timeout'

RSpec.describe SecureCommand do
  let(:secure_tmpdir) { Dir.mktmpdir(["securecommand_test_", SecureRandom.hex(8)]) }
  let(:test_dir) { File.join(secure_tmpdir, "test_dir") }
  let(:test_file) { File.join(test_dir, "test.txt") }

  before(:each) do
    FileUtils.mkdir_p(test_dir, mode: 0o700)

    # Reset memoized OpenSSL path
    described_class.instance_variable_set(:@openssl_executable, nil)

    # Mock system commands unless explicitly testing them
    allow(described_class).to receive(:openssl_executable).and_return("/usr/bin/openssl")
  end

  after(:each) do
    FileUtils.remove_entry_secure(secure_tmpdir) if File.directory?(secure_tmpdir)
  end

  describe '.openssl_executable' do
    it 'finds OpenSSL in approved paths' do
      # Reset memoized path
      described_class.instance_variable_set(:@openssl_executable, nil)

      # Mock file existence and executable status
      allow(File).to receive(:executable?).and_return(false)
      allow(File).to receive(:executable?).with('/usr/bin/openssl').and_return(true)

      expect(described_class.openssl_executable).to eq('/usr/bin/openssl')
    end

    it 'rejects unauthorized OpenSSL locations' do
      allow(File).to receive(:executable?).and_return(false)

      expect {
        described_class.openssl_executable
      }.to raise_error(SecureCommand::SecurityError, /OpenSSL executable not found/)
    end

    it 'verifies OpenSSL binary integrity' do
      allow(File).to receive(:executable?).with('/usr/bin/openssl').and_return(true)
      allow(described_class).to receive(:verify_openssl_binary).and_raise(
        SecureCommand::SecurityError, "Binary verification failed"
      )

      expect {
        described_class.openssl_executable
      }.to raise_error(SecureCommand::SecurityError, /Binary verification failed/)
    end
  end

  describe '.execute_command' do
    let(:valid_args) { ["genrsa", "-out", "test.key", "2048"] }

    it 'executes valid OpenSSL commands' do
      allow(Open3).to receive(:popen3).and_yield(
        StringIO.new,
        StringIO.new("Success"),
        StringIO.new(""),
        double(value: double(success?: true))
      )

      result = described_class.execute_command(*valid_args)
      expect(result).to eq("Success")
    end

    it 'enforces command length limits' do
      long_args = ["genrsa", "-out", "x" * SecureCommand::MAX_COMMAND_LENGTH]

      expect {
        described_class.execute_command(*long_args)
      }.to raise_error(SecureCommand::SecurityError, /length exceeds maximum/)
    end

    it 'validates OpenSSL subcommands' do
      invalid_args = ["malicious", "-out", "test.key"]

      expect {
        described_class.execute_command(*invalid_args)
      }.to raise_error(SecureCommand::SecurityError, /Unauthorized OpenSSL command/)
    end

    it 'prevents command injection' do
      injection_attempts = [
        ["genrsa; rm -rf /", "test.key"],
        ["genrsa", "test.key; echo 'pwned'"],
        ["genrsa", "`touch /tmp/pwned`"],
        ["genrsa", "$(/bin/bash)"],
        ["genrsa", "$(touch /tmp/pwned)"],
        ["genrsa", "&& touch /tmp/pwned"],
        ["genrsa", "|| touch /tmp/pwned"]
      ]

      injection_attempts.each do |args|
        expect {
          described_class.execute_command(*args)
        }.to raise_error(SecureCommand::SecurityError, /prohibited characters/)
      end
    end

    it 'enforces execution timeouts' do
      allow(Open3).to receive(:popen3) { sleep 2 }

      expect {
        described_class.execute_command(*valid_args, timeout: 1)
      }.to raise_error(SecureCommand::TimeoutError)
    end

    it 'limits output size' do
      large_output = "x" * (SecureCommand::MAX_OUTPUT_SIZE + 1)
      allow(Open3).to receive(:popen3).and_yield(
        StringIO.new,
        StringIO.new(large_output),
        StringIO.new(""),
        double(value: double(success?: true))
      )

      expect {
        described_class.execute_command(*valid_args)
      }.to raise_error(SecureCommand::SecurityError, /output exceeds size limit/)
    end
  end

  describe 'resource limits' do
    it 'enforces CPU time limits' do
      allow(Process).to receive(:setrlimit).and_call_original

      described_class.execute_command(*valid_args)

      expect(Process).to have_received(:setrlimit).with(
        Process::RLIMIT_CPU,
        kind_of(Numeric),
        kind_of(Numeric)
      )
    end

    it 'enforces file descriptor limits' do
      allow(Process).to receive(:setrlimit).and_call_original

      described_class.execute_command(*valid_args)

      expect(Process).to have_received(:setrlimit).with(
        Process::RLIMIT_NOFILE,
        kind_of(Numeric),
        kind_of(Numeric)
      )
    end
  end
end
