require "thor"
require "yaml"
require_relative "lib/cert_manager"

class AutoSSL < Thor
  CONFIG_FILE = ".autosslrc"

  desc "generate DOMAIN TLD", "Generates a self-signed SSL certificate for the given DOMAIN and TLD"
  option :ca_file, type: :string, desc: "Path to the CA .pem file"
  option :ca_key, type: :string, desc: "Path to the CA .key file"

  def generate(domain, tld)
    config = load_config

    ca_file = options[:ca_file] || config["ca_file"]
    ca_key = options[:ca_key] || config["ca_key"]

    if ca_file.nil? || ca_key.nil?
      puts "CA .pem file and CA .key file must be specified either in .autosslrc or as command-line options."
      exit(1)
    end

    site = "dev.#{domain}.#{tld}"
    CertManager.new(site, ca_file, ca_key).generate_certificates
  end

  desc "init", "Initialize the AutoSSL configuration"
  def init
    config = File.exist?(CONFIG_FILE) ? YAML.load_file(CONFIG_FILE) : {}

    config["ca_file"] = ask("Enter the path to the CA .pem file:", default: config["ca_file"])
    config["ca_key"] = ask("Enter the path to the CA .key file:", default: config["ca_key"])

    File.write(CONFIG_FILE, config.to_yaml)
    puts "Configuration saved to #{CONFIG_FILE}"
  end

  def self.exit_on_failure?
    true
  end

  private

  def load_config
    return {} unless File.exist?(CONFIG_FILE)
    YAML.load_file(CONFIG_FILE)
  end
end

# Only start Thor if this file is run directly
AutoSSL.start(ARGV) if __FILE__ == $0
