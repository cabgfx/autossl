require 'spec_helper'
require 'safe_yaml'
require 'fileutils'
require 'tmpdir'

RSpec.describe SafeYAML do
  describe '.safe_load' do
    let(:temp_dir) { Dir.mktmpdir }
    let(:yaml_file) { File.join(temp_dir, 'config.yaml') }

    before do
      File.write(yaml_file, { 'key' => 'value' }.to_yaml)
      File.chmod(0o600, yaml_file)
    end

    after do
      SpecHelper.safe_remove_dir(temp_dir)
    end

    it 'loads YAML content safely' do
      data = SafeYAML.safe_load(yaml_file)
      expect(data).to eq({ 'key' => 'value' })
    end

    it 'raises an error for YAML syntax errors' do
      File.write(yaml_file, "invalid_yaml: [unclosed_sequence")
      expect {
        SafeYAML.safe_load(yaml_file)
      }.to raise_error(SafeYAML::Error, /YAML syntax error/)
    end

    it 'raises an error for unsupported data types' do
      File.write(yaml_file, { 'key' => Proc.new {} }.to_yaml)
      expect {
        SafeYAML.safe_load(yaml_file)
      }.to raise_error(SafeYAML::Error, /Unsupported type Proc/)
    end
  end

  describe '.safe_dump' do
    let(:temp_dir) { Dir.mktmpdir }
    let(:yaml_file) { File.join(temp_dir, 'config.yaml') }
    let(:data) { { 'key' => 'value' } }

    after do
      SpecHelper.safe_remove_dir(temp_dir)
    end

    it 'dumps data to a YAML file securely' do
      SafeYAML.safe_dump(yaml_file, data)
      expect(File.read(yaml_file)).to eq(data.to_yaml)
      expect(File.stat(yaml_file).mode & 0o777).to eq(0o600)
    end

    it 'raises an error for unsupported data types' do
      data_with_proc = { 'key' => Proc.new {} }
      expect {
        SafeYAML.safe_dump(yaml_file, data_with_proc)
      }.to raise_error(SafeYAML::Error, /Unsupported type Proc/)
    end
  end
end
