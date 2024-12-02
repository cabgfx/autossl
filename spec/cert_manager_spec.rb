require 'spec_helper'
require 'cert_manager'
require 'fileutils'
require 'securerandom'

RSpec.describe CertManager do
  let(:secure_tmpdir) { Dir.mktmpdir(["certmanager_test_", SecureRandom.hex(8)]) }
  let(:ssl_dir) { File.join(secure_tmpdir, 'ssl') }
  let(:domain) { 'example' }
  let(:tld) { 'com' }
  let(:site) { "#{domain}.#{tld}" }
  let(:cert_manager) { described_class.new(site, ssl_dir: ssl_dir) }

  before(:each) do
    FileUtils.mkdir_p(ssl_dir, mode: 0o700)

    # Mock SafetyChecks
    allow(SafetyChecks).to receive(:check_system_resources).and_return(true)
    allow(SafetyChecks).to receive(:validate_available_space!).and_return(true)
  end

  after(:each) do
    FileUtils.remove_entry_secure(secure_tmpdir) if File.directory?(secure_tmpdir)
  end

  describe 'Certificate Generation' do
    context 'with valid inputs' do
      it 'generates a complete certificate set' do
        expect { cert_manager.generate_certificates }.not_to raise_error

        expect(File.exist?(File.join(ssl_dir, "#{site}.key"))).to be true
        expect(File.exist?(File.join(ssl_dir, "#{site}.csr"))).to be true
        expect(File.exist?(File.join(ssl_dir, "#{site}.crt"))).to be true

        # Verify permissions
        Dir.glob(File.join(ssl_dir, '*')).each do |file|
          expect(File.stat(file).mode & 0o777).to eq(0o600)
        end
      end

      it 'handles resource exhaustion gracefully' do
        allow(SafetyChecks).to receive(:check_system_resources)
          .and_raise(SafetyChecks::ResourceError, "Low memory")

        expect { cert_manager.generate_certificates }
          .to raise_error(CertManager::GenerationError, /system resources/)
      end
    end

    context 'with security violations' do
      it 'detects insecure SSL directory permissions' do
        FileUtils.chmod(0o777, ssl_dir)
        expect { cert_manager.generate_certificates }
          .to raise_error(SecurityError, /directory permissions/)
      end

      it 'prevents symlink attacks' do
        malicious_link = File.join(ssl_dir, "#{site}.key")
        FileUtils.ln_s('/etc/passwd', malicious_link)

        expect { cert_manager.generate_certificates }
          .to raise_error(SecurityError, /symlink/)
      end

      it 'validates file content integrity' do
        allow(cert_manager).to receive(:generate_private_key).and_return(true)
        key_path = File.join(ssl_dir, "#{site}.key")
        File.write(key_path, "compromised content")

        expect { cert_manager.verify_key_security(key_path) }
          .to raise_error(SecurityError, /validation failed/)
      end
    end

    context 'with system errors' do
      it 'handles OpenSSL failures' do
        allow(SecureCommand).to receive(:execute_command)
          .and_raise(SecureCommand::CommandError)

        expect { cert_manager.generate_certificates }
          .to raise_error(CertManager::GenerationError)
      end

      it 'implements exponential backoff for retries' do
        attempts = 0
        allow(SecureCommand).to receive(:execute_command) do
          attempts += 1
          raise SecureCommand::CommandError if attempts < 3
          true
        end

        expect { cert_manager.generate_certificates }.not_to raise_error
        expect(attempts).to eq(3)
      end
    end
  end

  describe 'Input Validation' do
    it 'rejects invalid domain names' do
      ['invalid..domain', 'domain with spaces', 'domain/with/slashes'].each do |invalid_domain|
        expect { described_class.new(invalid_domain, ssl_dir: ssl_dir) }
          .to raise_error(CertManager::Error, /Invalid domain/)
      end
    end

    it 'enforces domain length limits' do
      long_domain = 'a' * 255 + '.com'
      expect { described_class.new(long_domain, ssl_dir: ssl_dir) }
        .to raise_error(CertManager::Error, /exceeds maximum length/)
    end

    it 'validates SSL directory path' do
      expect { described_class.new(site, ssl_dir: '/nonexistent/path') }
        .to raise_error(CertManager::Error, /SSL directory/)
    end
  end

  describe 'Resource Management' do
    it 'enforces disk space requirements' do
      allow(SafetyChecks).to receive(:validate_available_space!)
        .and_raise(SafetyChecks::ResourceError)

      expect { cert_manager.generate_certificates }
        .to raise_error(CertManager::GenerationError, /disk space/)
    end

    it 'cleans up on failure' do
      allow(cert_manager).to receive(:generate_private_key)
        .and_raise(StandardError, "Simulated failure")

      expect { cert_manager.generate_certificates rescue nil }
        .not_to change { Dir.glob(File.join(ssl_dir, '*')).count }
    end
  end
end
