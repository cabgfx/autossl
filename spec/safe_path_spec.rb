require 'spec_helper'
require 'safe_path'
require 'securerandom'
require 'pathname'

RSpec.describe SafePath do
  let(:secure_tmpdir) { Dir.mktmpdir(["safepath_test_", SecureRandom.hex(8)]) }
  let(:test_dir) { File.join(secure_tmpdir, "test_dir") }
  let(:test_file) { File.join(test_dir, "test.txt") }
  let(:test_content) { SecureRandom.hex(32) }

  before(:each) do
    FileUtils.mkdir_p(test_dir, mode: 0o700)
  end

  after(:each) do
    FileUtils.remove_entry_secure(secure_tmpdir) if File.directory?(secure_tmpdir)
  end

  describe '.secure_mkdir' do
    it 'creates directory with secure permissions' do
      new_dir = File.join(test_dir, "secure_dir")
      described_class.secure_mkdir(new_dir)

      expect(File.directory?(new_dir)).to be true
      expect(File.stat(new_dir).mode & 0o777).to eq(0o700)
    end

    it 'prevents directory traversal attacks' do
      malicious_path = File.join(test_dir, "../../../etc/passwd.d")
      expect {
        described_class.secure_mkdir(malicious_path)
      }.to raise_error(SafePath::SecurityError, /path traversal/)
    end

    it 'handles race conditions safely' do
      dir_path = File.join(test_dir, "race_dir")

      # Simulate race condition
      allow(FileUtils).to receive(:mkdir_p).and_wrap_original do |original, *args|
        FileUtils.mkdir_p(dir_path, mode: 0o777)
        original.call(*args)
      end

      expect {
        described_class.secure_mkdir(dir_path)
      }.to raise_error(SafePath::SecurityError, /directory permissions/)
    end
  end

  describe '.secure_write' do
    it 'writes file with secure permissions' do
      described_class.secure_write(test_file, test_content)

      expect(File.read(test_file)).to eq(test_content)
      expect(File.stat(test_file).mode & 0o777).to eq(0o600)
    end

    it 'performs atomic writes' do
      temp_files = []
      allow(Tempfile).to receive(:new).and_wrap_original do |original, *args|
        temp_file = original.call(*args)
        temp_files << temp_file
        temp_file
      end

      described_class.secure_write(test_file, test_content)

      # Verify temp files are cleaned up
      temp_files.each do |temp_file|
        expect(File.exist?(temp_file.path)).to be false
      end
    end

    it 'validates content integrity' do
      described_class.secure_write(test_file, test_content)

      # Attempt to modify file during verification
      allow(File).to receive(:read).and_return("tampered content")

      expect {
        described_class.verify_file_integrity!(test_file, test_content)
      }.to raise_error(SafePath::SecurityError, /integrity check failed/)
    end
  end

  describe '.secure_read' do
    before(:each) do
      described_class.secure_write(test_file, test_content)
    end

    it 'reads file securely' do
      content = described_class.secure_read(test_file)
      expect(content).to eq(test_content)
    end

    it 'detects permission changes' do
      FileUtils.chmod(0o777, test_file)
      expect {
        described_class.secure_read(test_file)
      }.to raise_error(SafePath::SecurityError, /insecure permissions/)
    end

    it 'prevents symlink attacks' do
      symlink = File.join(test_dir, "symlink.txt")
      FileUtils.ln_s("/etc/passwd", symlink)

      expect {
        described_class.secure_read(symlink)
      }.to raise_error(SafePath::SecurityError, /symlink/)
    end
  end

  describe 'path validation' do
    it 'rejects paths with null bytes' do
      expect {
        described_class.validate_path!("test\0file.txt")
      }.to raise_error(SafePath::SanitizationError, /null byte/)
    end

    it 'rejects relative paths' do
      expect {
        described_class.validate_path!("../test.txt")
      }.to raise_error(SafePath::SecurityError, /relative path/)
    end

    it 'enforces path length limits' do
      long_path = File.join(test_dir, "a" * 300)
      expect {
        described_class.validate_path!(long_path)
      }.to raise_error(SafePath::SecurityError, /path length/)
    end

    it 'validates path components' do
      invalid_paths = [
        "test/file;touch malicious",
        "test/file\r\nmalicious",
        "test/file|malicious",
        "test/file>malicious"
      ]

      invalid_paths.each do |path|
        expect {
          described_class.validate_path!(path)
        }.to raise_error(SafePath::SecurityError, /invalid characters/)
      end
    end
  end

  describe 'directory traversal prevention' do
    it 'contains paths within base directory' do
      base_dir = test_dir
      traversal_attempts = [
        "../outside.txt",
        "subdir/../../outside.txt",
        "subdir/../../outside.txt",
        "/etc/passwd",
        "subdir/#{File::ALT_SEPARATOR}etc#{File::ALT_SEPARATOR}passwd"
      ]

      traversal_attempts.each do |path|
        expect {
          described_class.validate_path!(path, base_dir: base_dir)
        }.to raise_error(SafePath::SecurityError, /path traversal/)
      end
    end
  end

  describe 'symlink handling' do
    it 'limits symlink recursion' do
      link1 = File.join(test_dir, "link1")
      link2 = File.join(test_dir, "link2")
      link3 = File.join(test_dir, "link3")

      FileUtils.ln_s(link2, link1)
      FileUtils.ln_s(link3, link2)
      FileUtils.ln_s(link1, link3)

      expect {
        described_class.validate_symlink!(link1)
      }.to raise_error(SafePath::SecurityError, /symlink recursion/)
    end
  end
end
