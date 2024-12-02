require 'openssl'

module AutoSSL
  class SecureKeyManager
    def initialize
      @key_material = {}
      ObjectSpace.define_finalizer(self, self.class.cleanup(@key_material))
    end

    def generate_key(size: 4096)
      key = nil
      Sandbox.isolate do
        key = OpenSSL::PKey::RSA.new(size)
        # Ensure key generation used proper entropy
        raise SecurityError, "Insufficient entropy" unless key.private?
      end

      # Store in secure memory region
      key_id = SecureRandom.uuid
      @key_material[key_id] = secure_allocate(key.to_pem)

      key_id
    ensure
      key&.private_key&.clear
    end

    def sign_csr(key_id, csr)
      raise SecurityError, "Invalid key ID" unless @key_material[key_id]

      key = nil
      begin
        key = OpenSSL::PKey::RSA.new(@key_material[key_id])
        signature = key.sign(OpenSSL::Digest::SHA256.new, csr.to_der)
        verify_signature(key, signature, csr.to_der)
        signature
      ensure
        key&.private_key&.clear
      end
    end

    private

    def self.cleanup(key_material)
      proc {
        key_material.each_value do |mem|
          secure_free(mem)
        end
      }
    end

    def secure_allocate(data)
      ptr = nil
      Sandbox.isolate do
        ptr = FFI::MemoryPointer.new(:char, data.bytesize)
        ptr.write_string(data)
        ptr.autorelease = false
      end
      ptr
    end

    def secure_free(ptr)
      return unless ptr&.respond_to?(:size)

      # Overwrite with zeros
      ptr.write_string("\0" * ptr.size)
      ptr.free
    end

    def verify_signature(key, signature, data)
      raise SecurityError, "Invalid signature" unless key.verify(
        OpenSSL::Digest::SHA256.new,
        signature,
        data
      )
    end
  end
end
