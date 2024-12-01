require "rspec"
require "fileutils"
require "tmpdir"
require "yaml"

RSpec.configure do |config|
  config.before(:each) do
    @original_autosslrc = File.exist?(".autosslrc") ? File.read(".autosslrc") : nil
    @tmp_ssl_dir = Dir.mktmpdir("build")

    # Create a temporary .autosslrc file for the test
    File.write(".autosslrc", {"ssl_dir" => @tmp_ssl_dir, "ca_file" => "/path/to/yourCA.pem", "ca_key" => "/path/to/yourCA.key"}.to_yaml)
  end

  config.after(:each) do
    FileUtils.rm_rf(@tmp_ssl_dir) if @tmp_ssl_dir

    # Restore the original .autosslrc file
    if @original_autosslrc
      File.write(".autosslrc", @original_autosslrc)
    elsif File.exist?(".autosslrc")
      File.delete(".autosslrc")
    end
  end
end
