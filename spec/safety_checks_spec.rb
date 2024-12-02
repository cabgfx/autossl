require "spec_helper"
require "fileutils"
require "tmpdir"
require "concurrent"

RSpec.describe SafetyChecks do
  let(:tmp_dir) { Dir.mktmpdir }
  let(:test_file) { File.join(tmp_dir, "test.txt") }
  let(:test_dir) { File.join(tmp_dir, "test_dir") }
  let(:test_content) { "test content" }

  before(:all) do
    # Stop the resource monitor thread during tests
    SafetyChecks.stop_resource_monitor
  end

  before do
    FileUtils.mkdir_p(test_dir)
    File.write(test_file, test_content)
    File.chmod(0o600, test_file)
    File.chmod(0o700, test_dir)

    # Reset circuit breaker state
    SafetyChecks.instance_variable_get(:@failure_counts).clear
    SafetyChecks.instance_variable_get(:@circuit_states).clear
  end

  after do
    FileUtils.remove_entry tmp_dir
  end

  describe "Rate Limiting" do
    it "enforces rate limits" do
      (SafetyChecks::MAX_OPERATIONS + 1).times do
        expect {
          described_class.with_rate_limit { true }
        }.to raise_error(SafetyChecks::SecurityError, /Rate limit exceeded/)
      end
    end

    it "resets rate limit after interval" do
      SafetyChecks::MAX_OPERATIONS.times do
        described_class.with_rate_limit { true }
      end

      # Wait for rate limit interval to pass
      sleep(SafetyChecks::RATE_LIMIT_INTERVAL + 0.1)

      expect {
        described_class.with_rate_limit { true }
      }.not_to raise_error
    end
  end

  describe "Timeout Handling" do
    it "enforces operation timeouts" do
      expect {
        described_class.with_timeout("test") { sleep(SafetyChecks::OPERATION_TIMEOUT + 1) }
      }.to raise_error(SafetyChecks::TimeoutError)
    end

    it "allows operations within timeout" do
      expect {
        described_class.with_timeout("test") { true }
      }.not_to raise_error
    end
  end

  describe "File Locking" do
    it "enforces exclusive access" do
      thread1 = Thread.new do
        described_class.with_file_lock(test_file) { sleep(0.5) }
      end

      # Give thread1 time to acquire lock
      sleep(0.1)

      thread2 = Thread.new do
        expect {
          described_class.with_file_lock(test_file) { true }
        }.to raise_error(SafetyChecks::ConcurrencyError)
      end

      [thread1, thread2].each(&:join)
    end

    it "releases locks after use" do
      described_class.with_file_lock(test_file) { true }
      expect {
        described_class.with_file_lock(test_file) { true }
      }.not_to raise_error
    end
  end

  describe "Integrity Checks" do
    let(:checksum) { described_class.compute_checksum(test_file) }

    it "computes consistent checksums" do
      expect(described_class.compute_checksum(test_file)).to eq(checksum)
    end

    it "detects file modifications" do
      original_checksum = checksum
      File.write(test_file, "modified content")

      expect {
        described_class.verify_integrity!(test_file, original_checksum)
      }.to raise_error(SafetyChecks::IntegrityError)
    end

    it "verifies unchanged files" do
      expect {
        described_class.verify_integrity!(test_file, checksum)
      }.not_to raise_error
    end
  end

  describe "Symlink Handling" do
    let(:symlink_chain) { [] }

    before do
      return if Process.uid == 0 # Skip if root

      # Create chain of symlinks
      current_path = test_file
      (SafetyChecks::MAX_SYMLINKS + 1).times do |i|
        link_path = File.join(tmp_dir, "link_#{i}")
        File.symlink(current_path, link_path)
        symlink_chain << link_path
        current_path = link_path
      end
    end

    after do
      symlink_chain.reverse_each do |link|
        File.unlink(link) if File.symlink?(link)
      end
    end

    it "detects symlink chains exceeding limit" do
      skip "Test requires non-root user" if Process.uid == 0
      expect {
        described_class.check_symlink!(symlink_chain.last)
      }.to raise_error(SafetyChecks::SecurityError, /Too many symbolic links/)
    end
  end

  describe ".validate_ownership!" do
    it "succeeds for owned files" do
      expect(described_class.validate_ownership!(test_file)).to be_a(Pathname)
    end

    it "raises OwnershipError for files owned by others" do
      allow(File).to receive(:owned?).and_return(false)
      expect { described_class.validate_ownership!(test_file) }
        .to raise_error(SafetyChecks::OwnershipError)
    end

    it "raises PathError for non-existent files" do
      expect { described_class.validate_ownership!("/nonexistent") }
        .to raise_error(SafetyChecks::PathError)
    end
  end

  describe ".validate_path_length!" do
    it "succeeds for normal paths" do
      expect { described_class.validate_path_length!(test_file) }.not_to raise_error
    end

    it "raises PathError for extremely long paths" do
      long_path = "/a" * (SafetyChecks::MAX_PATH_LENGTH + 1)
      expect { described_class.validate_path_length!(long_path) }
        .to raise_error(SafetyChecks::PathError)
    end
  end

  describe ".validate_available_space!" do
    it "succeeds when sufficient space is available" do
      allow_any_instance_of(File::Stat).to receive(:blocks_available).and_return(1_000_000)
      allow_any_instance_of(File::Stat).to receive(:block_size).and_return(4096)
      expect { described_class.validate_available_space!(test_dir) }.not_to raise_error
    end

    it "raises SpaceError when insufficient space is available" do
      allow_any_instance_of(File::Stat).to receive(:blocks_available).and_return(1)
      allow_any_instance_of(File::Stat).to receive(:block_size).and_return(1)
      expect { described_class.validate_available_space!(test_dir) }
        .to raise_error(SafetyChecks::SpaceError)
    end
  end

  describe ".sanitize_filename" do
    it "allows valid filenames" do
      expect(described_class.sanitize_filename("valid-file.txt")).to eq("valid-file.txt")
    end

    it "raises SecurityError for filenames with path traversal attempts" do
      expect { described_class.sanitize_filename("../etc/passwd") }
        .to raise_error(SafetyChecks::SecurityError)
    end

    it "raises SecurityError for filenames with invalid characters" do
      expect { described_class.sanitize_filename("file\0.txt") }
        .to raise_error(SafetyChecks::SecurityError)
    end
  end

  describe ".validate_in_directory!" do
    it "succeeds for files within the directory" do
      expect(described_class.validate_in_directory!(test_file, tmp_dir)).to be_a(Pathname)
    end

    it "raises SecurityError for files outside the directory" do
      expect { described_class.validate_in_directory!(test_file, "/other/dir") }
        .to raise_error(SafetyChecks::SecurityError)
    end
  end

  describe ".validate_permissions!" do
    it "succeeds for files with correct permissions" do
      expect { described_class.validate_permissions!(test_file, 0o600) }.not_to raise_error
    end

    it "raises SecurityError for files with incorrect permissions" do
      File.chmod(0o777, test_file)
      expect { described_class.validate_permissions!(test_file, 0o600) }
        .to raise_error(SafetyChecks::SecurityError)
    end
  end

  describe ".secure_directory?" do
    it "returns true for secure directories" do
      expect(described_class.secure_directory?(test_dir)).to be true
    end

    it "returns false for insecure directories" do
      File.chmod(0o777, test_dir)
      expect(described_class.secure_directory?(test_dir)).to be false
    end
  end

  describe ".secure_file?" do
    it "returns true for secure files" do
      expect(described_class.secure_file?(test_file)).to be true
    end

    it "returns false for insecure files" do
      File.chmod(0o777, test_file)
      expect(described_class.secure_file?(test_file)).to be false
    end
  end

  describe "Resource Monitoring" do
    before do
      allow(File).to receive(:read).with("/proc/meminfo").and_return("MemAvailable: 1000000 kB\n")
      allow(Etc).to receive(:nprocessors).and_return(4)
    end

    it "detects low memory conditions" do
      allow(File).to receive(:read).with("/proc/meminfo").and_return("MemAvailable: 100 kB\n")
      expect {
        SafetyChecks.check_system_resources
      }.to raise_error(SafetyChecks::ResourceError, /Insufficient memory/)
    end

    it "detects high CPU usage" do
      allow(Etc).to receive(:nprocessors).and_return(8)  # Simulate high CPU usage
      expect {
        SafetyChecks.check_system_resources
      }.to raise_error(SafetyChecks::ResourceError, /CPU usage/)
    end

    it "respects resource check interval" do
      expect(File).to receive(:read).with("/proc/meminfo").once
      2.times { SafetyChecks.check_system_resources }
    end
  end

  describe "Circuit Breaker" do
    let(:operation) { :test_operation }

    it "trips after threshold failures" do
      (SafetyChecks::CIRCUIT_BREAKER_THRESHOLD - 1).times do
        SafetyChecks.with_circuit_breaker(operation) { raise SafetyChecks::Error }
      rescue SafetyChecks::Error
        # Expected
      end

      # This should trip the circuit breaker
      expect {
        SafetyChecks.with_circuit_breaker(operation) { raise SafetyChecks::Error }
      }.to raise_error(SafetyChecks::Error)

      # Next attempt should fail due to open circuit
      expect {
        SafetyChecks.with_circuit_breaker(operation) { true }
      }.to raise_error(SafetyChecks::CircuitBreakerError)
    end

    it "resets after successful operation" do
      # Record some failures but stay under threshold
      2.times do
        SafetyChecks.with_circuit_breaker(operation) { raise SafetyChecks::Error }
      rescue SafetyChecks::Error
        # Expected
      end

      # Successful operation should reset failure count
      SafetyChecks.with_circuit_breaker(operation) { true }

      # Verify reset
      failure_count = SafetyChecks.instance_variable_get(:@failure_counts).get(operation)
      expect(failure_count).to be_nil
    end

    it "allows retry after timeout" do
      # Trip the circuit breaker
      SafetyChecks::CIRCUIT_BREAKER_THRESHOLD.times do
        SafetyChecks.with_circuit_breaker(operation) { raise SafetyChecks::Error }
      rescue SafetyChecks::Error
        # Expected
      end

      # Set last failure time to be older than timeout
      state = [Time.now - SafetyChecks::CIRCUIT_BREAKER_TIMEOUT - 1, true]
      SafetyChecks.instance_variable_get(:@circuit_states).put(operation, state)

      # Should allow retry
      expect {
        SafetyChecks.with_circuit_breaker(operation) { true }
      }.not_to raise_error
    end
  end

  describe "Method Wrapping" do
    it "applies circuit breaker to all safety check methods" do
      method = :validate_path_length!

      # Trip the circuit breaker for the method
      SafetyChecks::CIRCUIT_BREAKER_THRESHOLD.times do
        described_class.send(method, "/some/path")
      rescue SafetyChecks::Error
        # Expected
      end

      # Next call should raise CircuitBreakerError
      expect {
        described_class.send(method, "/some/path")
      }.to raise_error(SafetyChecks::CircuitBreakerError)
    end

    it "checks system resources before operations" do
      allow(described_class).to receive(:check_system_resources).and_raise(SafetyChecks::ResourceError)

      expect {
        described_class.validate_path_length!("/some/path")
      }.to raise_error(SafetyChecks::ResourceError)
    end
  end
end
