require "rspec"
require "fileutils"

# Create a temporary directory for test outputs
RSpec.configure do |config|
  config.before(:each) do
    # FileUtils.mkdir_p(File.expand_path("~/ssl"))
  end

  config.after(:each) do
    # FileUtils.rm_rf(File.expand_path("~/ssl"))
  end
end
