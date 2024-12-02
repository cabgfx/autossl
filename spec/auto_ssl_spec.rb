require "spec_helper"
require_relative "../auto_ssl"
require "yaml"
require "tmpdir"
require "pathname"

RSpec.describe AutoSSL do
  let(:domain) { "example" }
  let(:tld) { "com" }
  let(:site) { "dev.#{domain}.#{tld}" }
  let(:temp_dir) { Pathname.new(Dir.mktmpdir).realpath.to_s }
  let(:ssl_dir) { File.join(temp_dir, "ssl") }
  let(:ca_file) { File.join(temp_dir, "ca.pem") }
  let(:ca_key) { File.join(temp_dir, "ca.key") }
  let(:config_file) { File.join(temp_dir, ".autosslrc") }

  before do
    # Create test CA files
    FileUtils.mkdir_p(File.dirname(ca_file))
    File.write(ca_file, "test ca content")
    File.write(ca_key, "test key content")
    File.chmod(0o600, ca_file)
    File.chmod(0o600, ca_key)

    # Create ssl directory with proper permissions
    FileUtils.mkdir_p(ssl_dir, mode: 0o700)

    # Stub CONFIG_FILE constant to use our temporary location
    stub_const("AutoSSL::CONFIG_FILE", config_file)

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

  describe "generate" do
    before do
      File.write(config_file, {"ca_file" => ca_file, "ca_key" => ca_key, "ssl_dir" => ssl_dir}.to_yaml)
    end

    it "generates a private key" do
      expect(SecureCommand).to receive(:openssl).with(
        "genrsa",
        "-out", "#{site}.key",
        "2048",
        working_dir: ssl_dir
      )
      AutoSSL.start(["generate", domain, tld])
    end

    it "generates a CSR" do
      expect(SecureCommand).to receive(:openssl).with(
        "req",
        "-new",
        "-key", "#{site}.key",
        "-out", "#{site}.csr",
        "-subj", "/CN=#{site}/emailAddress=example@example.com",
        working_dir: ssl_dir
      )
      AutoSSL.start(["generate", domain, tld])
    end

    it "creates an ext file with the correct content" do
      allow(SecureCommand).to receive(:openssl).and_return(true)
      AutoSSL.start(["generate", domain, tld])
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
      AutoSSL.start(["generate", domain, tld])
    end

    context "when config file is missing" do
      before do
        File.delete(config_file) if File.exist?(config_file)
      end

      it "fails with appropriate error message" do
        expect { AutoSSL.start(["generate", domain, tld]) }
          .to output(/CA file and CA key must be specified/).to_stdout
          .and raise_error(SystemExit)
      end
    end
  end

  describe "init" do
    it "creates a new configuration file" do
      allow_any_instance_of(Thor::Shell::Basic).to receive(:ask).and_return(ca_file, ca_key, ssl_dir)

      expect { AutoSSL.start(["init"]) }.to output(/Configuration saved to #{config_file}/).to_stdout

      config = YAML.load_file(config_file)
      expect(config["ca_file"]).to eq(ca_file)
      expect(config["ca_key"]).to eq(ca_key)
      expect(config["ssl_dir"]).to eq(ssl_dir)
    end

    it "updates an existing configuration file" do
      File.write(config_file, {"ca_file" => "old_ca.pem", "ca_key" => "old_ca.key", "ssl_dir" => "old_ssl"}.to_yaml)
      allow_any_instance_of(Thor::Shell::Basic).to receive(:ask).and_return(ca_file, ca_key, ssl_dir)

      expect { AutoSSL.start(["init"]) }.to output(/Configuration saved to #{config_file}/).to_stdout

      config = YAML.load_file(config_file)
      expect(config["ca_file"]).to eq(ca_file)
      expect(config["ca_key"]).to eq(ca_key)
      expect(config["ssl_dir"]).to eq(ssl_dir)
    end
  end
end
