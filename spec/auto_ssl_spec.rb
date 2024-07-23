require "spec_helper"
require_relative "../lib/auto_ssl"

RSpec.describe AutoSSL do
  let(:domain) { "example" }
  let(:tld) { "com" }
  let(:site) { "dev.#{domain}.#{tld}" }
  let(:ssl_dir) { File.expand_path("~/ssl") }

  describe "generate" do
    before do
      # Mock the system calls to OpenSSL to avoid actual key generation
      allow_any_instance_of(CertManager).to receive(:system).and_return(true)
    end

    it "generates a private key" do
      expect_any_instance_of(CertManager).to receive(:generate_private_key)
      AutoSSL.start(["generate", domain, tld])
    end

    it "generates a CSR" do
      expect_any_instance_of(CertManager).to receive(:generate_csr)
      AutoSSL.start(["generate", domain, tld])
    end

    it "creates an ext file with the correct content" do
      AutoSSL.start(["generate", domain, tld])
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

    it "generates a certificate" do
      expect_any_instance_of(CertManager).to receive(:generate_certificate)
      AutoSSL.start(["generate", domain, tld])
    end
  end
end
