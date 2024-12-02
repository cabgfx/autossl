require "spec_helper"
require_relative "../lib/cert_manager"
require "tmpdir"
require "pathname"

RSpec.describe CertManager do
  let(:domain) { "example.com" }
  let(:site) { "dev.#{domain}" }
  let(:temp_dir) { Pathname.new(Dir.mktmpdir).realpath.to_s }
  let(:ssl_dir) { File.join(temp_dir, "ssl") }
  let(:ca_file) { File.join(temp_dir, "ca.pem") }
  let(:ca_key) { File.join(temp_dir, "ca.key") }

  subject(:cert_manager) { described_class.new(site, ca_file, ca_key, ssl_dir) }

  before do
    # Create test CA files
    FileUtils.mkdir_p(File.dirname(ca_file))
    File.write(ca_file, "test ca content")
    File.write(ca_key, "test key content")
    File.chmod(0o600, ca_file)
    File.chmod(0o600, ca_key)

    # Create ssl directory with proper permissions
    FileUtils.mkdir_p(ssl_dir, mode: 0o700)

    # Mock OpenSSL commands
    allow(SecureCommand).to receive(:openssl) do |*args, **kwargs|
      # Create a dummy file if it's a command that generates output
      if args.include?("-out")
        out_file = args[args.index("-out") + 1]
        out_path = kwargs[:working_dir] ? File.join(kwargs[:working_dir], out_file) : out_file
        FileUtils.touch(out_path)
        File.chmod(0o600, out_path)
      end
      true
    end
  end

  after do
    # Clean up temp directory safely
    if Dir.exist?(temp_dir)
      begin
        real_temp = Pathname.new(temp_dir).realpath.to_s
        real_tmpdir = Pathname.new(Dir.tmpdir).realpath.to_s

        if real_temp.start_with?(real_tmpdir)
          FileUtils.remove_entry(temp_dir)
        else
          warn "Warning: Not removing directory that's outside tmp: #{temp_dir}"
        end
      rescue => e
        warn "Warning: Failed to clean up temp directory #{temp_dir}: #{e.message}"
      end
    end
  end

  describe "#generate_private_key" do
    it "generates a private key" do
      expect(SecureCommand).to receive(:openssl).with(
        "genrsa",
        "-out", "#{site}.key",
        "2048",
        working_dir: ssl_dir
      )
      cert_manager.send(:generate_private_key)
    end
  end

  describe "#generate_csr" do
    it "generates a CSR" do
      expect(SecureCommand).to receive(:openssl).with(
        "req",
        "-new",
        "-key", "#{site}.key",
        "-out", "#{site}.csr",
        "-subj", "/CN=#{site}/emailAddress=example@example.com",
        working_dir: ssl_dir
      )
      cert_manager.send(:generate_csr)
    end
  end

  describe "#create_ext_file" do
    it "creates an ext file with the correct content" do
      allow(SecureCommand).to receive(:openssl).and_return(true)
      cert_manager.send(:create_ext_file)
      ext_file = File.join(ssl_dir, "#{site}.ext")
      expect(File.exist?(ext_file)).to be true

      expected_content = <<~EXT
        authorityKeyIdentifier=keyid,issuer
        basicConstraints=CA:FALSE
        keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
        subjectAltName = @alt_names

        [alt_names]
        DNS.1 = #{site}
      EXT

      expect(File.read(ext_file)).to eq(expected_content)
    end
  end

  describe "#generate_certificate" do
    it "generates a certificate" do
      expect(SecureCommand).to receive(:openssl).with(
        "x509",
        "-req",
        "-in", "#{site}.csr",
        "-CA", ca_file,
        "-CAkey", ca_key,
        "-CAcreateserial",
        "-out", "#{site}.crt",
        "-days", "825",
        "-sha256",
        "-extfile", "#{site}.ext",
        working_dir: ssl_dir
      )
      cert_manager.send(:generate_certificate)
    end
  end

  describe "validation" do
    context "with invalid domain" do
      let(:domain) { "invalid..domain" }

      it "raises an error" do
        expect {
          described_class.new(site, ca_file, ca_key, ssl_dir)
        }.to raise_error(CertManager::Error, /Invalid domain name/)
      end
    end

    context "with missing CA file" do
      before { File.unlink(ca_file) }

      it "raises an error" do
        expect {
          described_class.new(site, ca_file, ca_key, ssl_dir)
        }.to raise_error(CertManager::Error, /CA file is not accessible/)
      end
    end

    context "with missing CA key" do
      before { File.unlink(ca_key) }

      it "raises an error" do
        expect {
          described_class.new(site, ca_file, ca_key, ssl_dir)
        }.to raise_error(CertManager::Error, /CA key is not accessible/)
      end
    end
  end
end
