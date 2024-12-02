require 'openssl'
require 'tempfile'

module AutoSSL
  class IsolatedCertGenerator
    def self.generate(domain:, config:)
      new(domain, config).generate
    end

    def initialize(domain, config)
      @domain = domain
      @config = config
      @state_machine = StateMachine.new
      @key_manager = SecureKeyManager.new
    end

    def generate
      @state_machine.transition_to(:validating) do
        validate_prerequisites
      end

      key_id = nil
      begin
        @state_machine.transition_to(:generating_key) do
          key_id = generate_key
        end

        @state_machine.transition_to(:generating_csr) do
          csr = generate_csr(key_id)
        end

        @state_machine.transition_to(:signing_certificate) do
          cert = sign_certificate(csr)
        end

        @state_machine.transition_to(:verifying) do
          verify_certificate(cert)
        end

        @state_machine.transition_to(:completed) do
          save_artifacts(cert, key_id)
        end
      ensure
        cleanup(key_id) if key_id
      end
    end

    private

    def validate_prerequisites
      Sandbox.isolate do
        validate_openssl_version
        validate_directory_permissions
        validate_ca_integrity
      end
    end

    def generate_key
      Sandbox.isolate do
        @key_manager.generate_key(size: 4096)
      end
    end

    def generate_csr(key_id)
      Sandbox.isolate do
        csr = OpenSSL::X509::Request.new
        csr.version = 0
        csr.subject = OpenSSL::X509::Name.new([
          ['CN', @domain, OpenSSL::ASN1::UTF8STRING]
        ])

        # Add extended key usage
        extension = OpenSSL::X509::Extension.new(
          'extendedKeyUsage',
          OpenSSL::ASN1::Sequence([
            OpenSSL::ASN1::ObjectId('serverAuth'),
            OpenSSL::ASN1::ObjectId('clientAuth')
          ]).to_der
        )
        csr.add_attribute(
          OpenSSL::X509::Attribute.new(
            'extReq',
            OpenSSL::ASN1::Set([OpenSSL::ASN1::Sequence([extension])])
          )
        )

        # Sign the CSR
        csr.sign(@key_manager.get_key(key_id), OpenSSL::Digest::SHA256.new)
        csr
      end
    end

    def cleanup(key_id)
      @key_manager.destroy_key(key_id) if key_id
    end
  end
end
