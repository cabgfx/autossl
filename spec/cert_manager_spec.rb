require "spec_helper"
require_relative "../lib/cert_manager"

RSpec.describe CertManager do
  let(:domain) { "example" }
  let(:tld) { "com" }
  let(:site) { "dev.#{domain}.#{tld}" }
  let(:ssl_dir) { File.expand_path("~/ssl") }

  before do
    # Mock the system calls to OpenSSL to avoid actual key generation
    allow_any_instance_of(CertManager).to receive(:system).and_return(true)
    @cert_manager = CertManager.new(site)
  end

  describe "#generate_private_key" do
    it "generates a private key" do
      expect(@cert_manager).to receive(:generate_private_key)
      @cert_manager.generate_certificates
    end
  end

  describe "#generate_csr" do
    it "generates a CSR" do
      expect(@cert_manager).to receive(:generate_csr)
      @cert_manager.generate_certificates
    end
  end

  describe "#create_ext_file" do
    it "creates an ext file with the correct content" do
      @cert_manager.generate_certificates
      ext_file = File.read("#{ssl_dir}/#{site}.ext")

      expected_content = <<~EXT
        authorityKeyIdentifier=keyid,issuer
        basicConstraints=CA:FALSE
        keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
        subjectAltName = @alt_names

        [alt_names]
        DNS.1 = #{site}
      EXT

      expect(ext_file).to eq(expected_content)
    end
  end

  describe "#generate_certificate" do
    it "generates a certificate" do
      expect(@cert_manager).to receive(:generate_certificate)
      @cert_manager.generate_certificates
    end
  end
end
