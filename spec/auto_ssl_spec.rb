require "spec_helper"
require_relative "../auto_ssl"
require "yaml"
require "tmpdir"
require "pathname"

RSpec.describe AutoSSL do
  let(:domain) { "example" }
  let(:tld) { "com" }
  let(:site) { "dev.#{domain}.#{tld}" }
  let(:temp_dir) do
    path = Dir.mktmpdir
    Pathname.new(path).realpath.to_s  # Resolve any symlinks to actual path
  end
  let(:ssl_dir) { File.join(temp_dir, "ssl") }
  let(:ca_file) { "/path/to/yourCA.pem" }
  let(:ca_key) { "/path/to/yourCA.key" }
  let(:config_file) { File.join(temp_dir, ".autosslrc") }

  before do
    # Safety checks
    unless temp_dir.start_with?(Dir.tmpdir)
      raise "Safety check failed: temp_dir '#{temp_dir}' not in system temp directory '#{Dir.tmpdir}'"
    end

    # Verify all paths are within temp_dir
    [ssl_dir, config_file].each do |path|
      full_path = Pathname.new(path).cleanpath.to_s
      unless full_path.start_with?(temp_dir)
        raise "Safety check failed: path '#{full_path}' escapes temp directory '#{temp_dir}'"
      end
    end

    # Create ssl directory with explicit permissions
    FileUtils.mkdir_p(ssl_dir, mode: 0o700)

    # Stub CONFIG_FILE constant to use our temporary location
    stub_const("AutoSSL::CONFIG_FILE", config_file)

    # Mock the system calls to OpenSSL to avoid actual key generation
    allow_any_instance_of(CertManager).to receive(:system).and_return(true)
  end

  after do
    if Dir.exist?(temp_dir)
      begin
        # Ensure we're only removing files we created in our temp directory
        dir_path = Pathname.new(temp_dir).realpath
        unless dir_path.to_s.start_with?(Dir.tmpdir)
          raise "Safety check failed: attempting to remove directory outside tmp"
        end

        # Safely remove only files we own
        Dir.glob(File.join(temp_dir, "**/*")).each do |path|
          next unless File.owned?(path)
          File.unlink(path) if File.file?(path)
        end

        # Remove empty directories
        FileUtils.remove_entry(temp_dir)
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
      expect_any_instance_of(CertManager).to receive(:generate_private_key)
      AutoSSL.start(["generate", domain, tld])
    end

    it "generates a CSR" do
      expect_any_instance_of(CertManager).to receive(:generate_csr)
      AutoSSL.start(["generate", domain, tld])
    end

    it "creates an ext file with the correct content" do
      AutoSSL.start(["generate", domain, tld])
      ext_file = File.read(File.join(ssl_dir, "#{site}.ext"))

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
