require "rspec"
require "fileutils"
require "tmpdir"
require "yaml"
require "pathname"

module SpecHelper
  # Safely removes a directory if it's within the system's temporary directory
  #
  # @param dir [String] The directory path to remove
  def self.safe_remove_dir(dir)
    return unless dir && Dir.exist?(dir)

    begin
      real_dir = Pathname.new(dir).realpath.to_s
      real_tmpdir = Pathname.new(Dir.tmpdir).realpath.to_s

      if real_dir.start_with?(real_tmpdir)
        FileUtils.remove_entry(dir)
      else
        warn "Warning: Not removing directory that's outside tmp: #{dir}"
      end
    rescue => e
      warn "Warning: Failed to clean up directory #{dir}: #{e.message}"
    end
  end
end

RSpec.configure do |config|
  config.before(:each) do
    # Ensure we're using a clean environment for each test
    @original_env = ENV.to_h
    ENV["XDG_CONFIG_HOME"] = Dir.mktmpdir("config")
    ENV["XDG_DATA_HOME"] = Dir.mktmpdir("data")
  end

  config.after(:each) do
    [ENV["XDG_CONFIG_HOME"], ENV["XDG_DATA_HOME"]].each do |dir|
      SpecHelper.safe_remove_dir(dir)
    end

    # Restore original environment
    ENV.clear
    @original_env.each { |k, v| ENV[k] = v }
  end

  # Disable real OpenSSL operations during testing
  config.before(:each) do
    allow(SecureCommand).to receive(:openssl).and_return(true) unless RSpec.current_example.metadata[:no_mock_openssl]
    allow(File).to receive(:chmod).and_return(true) unless RSpec.current_example.metadata[:no_mock_chmod]
  end
end
