require "thor"
require "fileutils"

class SSLCertGenerator < Thor
  desc "generate DOMAIN TLD", "Generates a self-signed SSL certificate for the given DOMAIN and TLD"

  def generate(domain, tld)
    site = "dev.#{domain}.#{tld}"

    CertManager.new(site).generate_certificates
    CertMover.new(site).move_certificates
  end
end

class CertManager
  def initialize(site)
    @site = site
  end

  def generate_certificates
    Dir.chdir(File.expand_path("~/ssl")) do
      generate_private_key
      generate_csr
      create_ext_file
      generate_certificate
    end
  end

  private

  def generate_private_key
    system("openssl genrsa -out #{@site}.key 2048")
  end

  def generate_csr
    system("openssl req -new -key #{@site}.key -out #{@site}.csr -subj '/CN=#{@site}/emailAddress=example@example.com'")
  end

  def create_ext_file
    ext_content = <<~EXT
      authorityKeyIdentifier=keyid,issuer
      basicConstraints=CA:FALSE
      keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
      subjectAltName = @alt_names

      [alt_names]
      DNS.1 = #{@site}
    EXT

    File.write("#{@site}.ext", ext_content)
  end

  def generate_certificate
    system("openssl x509 -req -in #{@site}.csr -CA cabCA.pem -CAkey cabCA.key -CAcreateserial -out #{@site}.crt -days 825 -sha256 -extfile #{@site}.ext")
  end
end

class CertMover
  def initialize(site)
    @site = site
  end

  def move_certificates
    project_ssl_dir = File.expand_path("~/project/ssl")
    FileUtils.mkdir_p(project_ssl_dir) unless Dir.exist?(project_ssl_dir)
    FileUtils.mv("#{@site}.key", "#{project_ssl_dir}/#{@site}.key")
    FileUtils.mv("#{@site}.crt", "#{project_ssl_dir}/#{@site}.crt")

    puts "Generated and moved #{@site}.key and #{@site}.crt to #{project_ssl_dir}"
  end
end

SSLCertGenerator.start(ARGV)
