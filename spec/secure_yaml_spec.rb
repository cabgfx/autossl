require 'spec_helper'
require 'secure_yaml'
require 'fileutils'
require 'securerandom'

RSpec.describe SecureYAML do
  let(:secure_tmpdir) { Dir.mktmpdir(["secureyaml_test_", SecureRandom.hex(8)]) }
  let(:test_dir) { File.join(secure_tmpdir, "test_dir") }
  let(:yaml_file) { File.join(test_dir, "config.yml") }
  let(:valid_config) do
    {
      "ssl_dir" => "/tmp/ssl",
      "ca_file" => "/tmp/ca.crt",
      "ca_key" => "/tmp/ca.key",
      "memory_limit" => 512,
      "cpu_limit" => 80,
      "operation_rate" => 100,
      "timeout" => 30
    }
  end

  before(:each) do
    FileUtils.mkdir_p(test_dir, mode: 0o700)
  end

  after(:each) do
    FileUtils.remove_entry_secure(secure_tmpdir) if File.directory?(secure_tmpdir)
  end

  describe '.load_file' do
    context 'with security constraints' do
      it 'enforces file size limits' do
        large_data = { "key" => "x" * (SecureYAML::MAX_YAML_SIZE + 1) }
        File.write(yaml_file, YAML.dump(large_data))

        expect {
          described_class.load_file(yaml_file)
        }.to raise_error(SecureYAML::SecurityError, /exceeds maximum allowed size/)
      end

      it 'enforces nesting depth limits' do
        deep_hash = {}
        current = deep_hash
        (SecureYAML::MAX_NESTING_DEPTH + 1).times do |i|
          current["level#{i}"] = {}
          current = current["level#{i}"]
        end

        File.write(yaml_file, YAML.dump(deep_hash))

        expect {
          described_class.load_file(yaml_file)
        }.to raise_error(SecureYAML::ValidationError, /maximum nesting depth/)
      end

      it 'validates file permissions' do
        File.write(yaml_file, YAML.dump(valid_config))
        FileUtils.chmod(0o777, yaml_file)

        expect {
          described_class.load_file(yaml_file)
        }.to raise_error(SecureYAML::SecurityError, /insecure permissions/)
      end

      it 'prevents symlink attacks' do
        FileUtils.ln_s("/etc/passwd", yaml_file)

        expect {
          described_class.load_file(yaml_file)
        }.to raise_error(SecureYAML::SecurityError, /symlink/)
      end
    end

    context 'with content validation' do
      it 'enforces allowed classes' do
        invalid_classes = [
          "Time.now.to_datetime",
          "IO.new(0)",
          "Kernel.exec('ls')",
          "eval('puts :hello')"
        ]

        invalid_classes.each do |expr|
          yaml_content = "key: !ruby/object:#{expr}"
          File.write(yaml_file, yaml_content)

          expect {
            described_class.load_file(yaml_file)
          }.to raise_error(SecureYAML::SecurityError, /Unsupported type/)
        end
      end

      it 'validates against schema' do
        invalid_configs = [
          { "ssl_dir" => 123 },  # wrong type
          { "memory_limit" => 99999 },  # out of range
          { "cpu_limit" => -1 },  # out of range
          { "operation_rate" => "fast" }  # wrong type
        ]

        invalid_configs.each do |config|
          File.write(yaml_file, YAML.dump(config))

          expect {
            described_class.load_file(yaml_file)
          }.to raise_error(SecureYAML::ValidationError)
        end
      end

      it 'validates key names' do
        invalid_keys = [
          { "../../etc/passwd" => "value" },
          { "key; rm -rf /" => "value" },
          { "key\x00hidden" => "value" },
          { "a" * 129 => "value" }
        ]

        invalid_keys.each do |config|
          File.write(yaml_file, YAML.dump(config))

          expect {
            described_class.load_file(yaml_file)
          }.to raise_error(SecureYAML::ValidationError, /Invalid .* key/)
        end
      end
    end
  end

  describe '.dump' do
    it 'creates files with secure permissions' do
      described_class.dump(valid_config, yaml_file)
      expect(File.stat(yaml_file).mode & 0o777).to eq(0o600)
    end

    it 'performs atomic writes' do
      original_content = "original content"
      File.write(yaml_file, original_content)

      # Simulate failure during write
      allow(File).to receive(:rename).and_raise(StandardError)

      expect {
        described_class.dump(valid_config, yaml_file)
      }.to raise_error(StandardError)

      expect(File.read(yaml_file)).to eq(original_content)
    end

    it 'validates content before saving' do
      invalid_config = valid_config.merge("dangerous" => Object.new)

      expect {
        described_class.dump(invalid_config, yaml_file)
      }.to raise_error(SecureYAML::ValidationError)

      expect(File.exist?(yaml_file)).to be false
    end
  end

  describe 'schema validation' do
    it 'enforces required fields' do
      incomplete_config = valid_config.reject { |k, _| k == "ssl_dir" }

      expect {
        described_class.validate_against_schema!(incomplete_config)
      }.to raise_error(SecureYAML::ValidationError, /Missing required key/)
    end

    it 'validates numeric ranges' do
      {
        "memory_limit" => [127, 4097],
        "cpu_limit" => [9, 91],
        "operation_rate" => [0, 1001],
        "timeout" => [0, 301]
      }.each do |key, (min, max)|
        [min, max].each do |invalid_value|
          invalid_config = valid_config.merge(key => invalid_value)
          expect {
            described_class.validate_against_schema!(invalid_config)
          }.to raise_error(SecureYAML::ValidationError, /#{key}/)
        end
      end
    end
  end

  describe 'error handling' do
    it 'provides detailed error messages' do
      error_cases = {
        "syntax" => "key: *undefined_alias",
        "circular" => "key: &ref\n  self: *ref",
        "invalid_type" => "key: !ruby/object:File {}"
      }

      error_cases.each do |case_name, yaml_content|
        File.write(yaml_file, yaml_content)

        expect {
          described_class.load_file(yaml_file)
        }.to raise_error(SecureYAML::Error, /#{case_name}/i)
      end
    end
  end
end
