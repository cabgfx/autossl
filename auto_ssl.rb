require "thor"
require_relative "lib/cert_manager"

class AutoSSL < Thor
  desc "generate DOMAIN TLD", "Generates a self-signed SSL certificate for the given DOMAIN and TLD"

  def generate(domain, tld)
    site = "dev.#{domain}.#{tld}"
    CertManager.new(site).generate_certificates
  end

  def self.exit_on_failure?
    true
  end
end

# Only start Thor if this file is run directly
AutoSSL.start(ARGV) if __FILE__ == $0
