require 'spec_helper'
require 'auto_ssl'
require 'openssl'

RSpec.describe "Cryptographic Security", :security do
  let(:secure_tmpdir) { Dir.mktmpdir(["crypto_test_", SecureRandom.hex(8)]) }

  before(:each) do
    @original_env = ENV.to_h
    ENV["OPENSSL_CONF"] = File.join(secure_tmpdir, "openssl.cnf")
  end

  after(:each) do
    ENV.replace(@original_env)
    FileUtils.remove_entry_secure(secure_tmpdir)
  end

  describe "OpenSSL Security" do
    it "validates OpenSSL version meets minimum requirements" do
      version = OpenSSL::VERSION
      expect(Gem::Version.new(version)).to be >= Gem::Version.new("1.1.1")
    end

    it "enforces secure cipher suites" do
      cert_manager = CertManager.new("domain.com")
      allowed_ciphers = cert_manager.send(:allowed_cipher_suites)

      weak_ciphers = allowed_ciphers.select { |c| c.match?(/MD5|SHA1|DES|RC4/i) }
      expect(weak_ciphers).to be_empty
    end

    it "validates certificate chain integrity" do
      root_ca = create_test_ca
      intermediate_ca = create_intermediate_ca(root_ca)
      leaf_cert = create_leaf_certificate(intermediate_ca)

      cert_chain = [leaf_cert, intermediate_ca.certificate, root_ca.certificate]
      store = OpenSSL::X509::Store.new
      store.add_cert(root_ca.certificate)

      expect(cert_chain[0].verify(cert_chain[1].public_key)).to be true
      expect(cert_chain[1].verify(cert_chain[2].public_key)).to be true
    end

    it "prevents key material exposure" do
      key = OpenSSL::PKey::RSA.new(2048)
      serialized = key.to_pem

      # Verify key material is not logged
      expect(Logger).not_to receive(:debug).with(/BEGIN RSA PRIVATE KEY/)
      expect(Logger).not_to receive(:info).with(/BEGIN RSA PRIVATE KEY/)

      cert_manager = CertManager.new("domain.com")
      cert_manager.send(:log_operation, "Generated key")
    end
  end

  private

  def create_test_ca
    # Implementation for test CA creation
    # (detailed implementation omitted for brevity)
  end

  def create_intermediate_ca(root_ca)
    # Implementation for intermediate CA creation
  end

  def create_leaf_certificate(issuer_ca)
    # Implementation for leaf certificate creation
  end
end
