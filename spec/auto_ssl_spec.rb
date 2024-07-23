require "spec_helper"
require_relative "../auto_ssl"
require "yaml"

RSpec.describe AutoSSL do
  let(:domain) { "example" }
  let(:tld) { "com" }
  let(:site) { "dev.#{domain}.#{tld}" }
  let(:ssl_dir) { File.expand_path("~/ssl") }
  let(:ca_file) { "/path/to/cabCA.pem" }
  let(:ca_key) { "/path/to/cabCA.key" }
  let(:config_file) { File.expand_path("../../.autosslrc", __dir__) }

  before do
    # Mock the system calls to OpenSSL to avoid actual key generation
    allow_any_instance_of(CertManager).to receive(:system).and_return(true)
  end

  after do
    File.delete(config_file) if File.exist?(config_file)
  end

  describe "generate" do
    before do
      File.write(config_file, {"ca_file" => ca_file, "ca_key" => ca_key}.to_yaml)
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

  describe "init" do
    it "creates a new configuration file" do
      allow_any_instance_of(Thor::Shell::Basic).to receive(:ask).and_return(ca_file, ca_key)

      expect { AutoSSL.start(["init"]) }.to output(/Configuration saved to .autosslrc/).to_stdout

      config = YAML.load_file(config_file)
      expect(config["ca_file"]).to eq(ca_file)
      expect(config["ca_key"]).to eq(ca_key)
    end

    it "updates an existing configuration file" do
      File.write(config_file, {"ca_file" => "old_ca.pem", "ca_key" => "old_ca.key"}.to_yaml)
      allow_any_instance_of(Thor::Shell::Basic).to receive(:ask).and_return(ca_file, ca_key)

      expect { AutoSSL.start(["init"]) }.to output(/Configuration saved to .autosslrc/).to_stdout

      config = YAML.load_file(config_file)
      expect(config["ca_file"]).to eq(ca_file)
      expect(config["ca_key"]).to eq(ca_key)
    end
  end
end
