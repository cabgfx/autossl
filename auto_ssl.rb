require "thor"

require "lib/cert_manager"

class AutoSSL < Thor
  desc "generate DOMAIN TLD", "Generates a self-signed SSL certificate for the given DOMAIN and TLD"

  def generate(domain, tld)
    site = "dev.#{domain}.#{tld}"
    CertManager.new(site).generate_certificates
  end
end

AutoSSL.start(ARGV)
