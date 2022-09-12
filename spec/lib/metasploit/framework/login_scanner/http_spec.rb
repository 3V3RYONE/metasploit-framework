
require 'spec_helper'
require 'metasploit/framework/login_scanner/http'
require 'rex'

RSpec.describe Metasploit::Framework::LoginScanner::HTTP do
  include_context 'Msf::UIDriver'
  include_context 'Msf::DBManager'
  include_context 'Msf::Simple::Framework'

  # let(:driver) do
  #   instance = double('Rex::Ui::Text::Output::Stdio', framework: framework)
  #   #require 'pry';binding.pry
  #   allow(instance).to receive(:print_line) { |arg| $stdout.puts arg }
  #   capture_logging(instance)
  #   instance
  # end

  #class Metasploit::Framework::LoginScanner::HTTP
  #  def print_line(mesg='')
  #    print(mesg+"\n")
  #  end
  #end

  #class Rex::Proto::Http::Packet
  #  def to_terminal_output(headers_only=false)
  #    output_packet(true, headers_only=headers_only)
  #  end

  #  def to_s(headers_only=false)
  #    output_packet(false, headers_only=headers_only)
  #  end
  #end

  #class Rex::Ui::Text::Output::Stdio
  #  def support_color?
  #    return false
  #  end
  #end

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: true, has_default_realm: false
  it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'
  it_behaves_like 'Metasploit::Framework::LoginScanner::HTTP'

  let(:mock_module) { instance_double Msf::Exploit }

  subject do
    capture_logging(mock_module)
    described_class.new({ 'framework' => framework, 'framework_module' => mock_module })
  end

  let(:response) { Rex::Proto::Http::Response.new(200, 'OK') }

  before(:example) do
    allow_any_instance_of(Rex::Proto::Http::Client).to receive(:request_cgi).with(any_args)
    allow_any_instance_of(Rex::Proto::Http::Client).to receive(:send_recv).with(any_args).and_return(response)
    allow_any_instance_of(Rex::Proto::Http::Client).to receive(:set_config).with(any_args)
    #allow().to receive(:print_line) { |arg| $stdout.puts arg }
    allow(subject).to receive(:print) { |arg| $stdout.puts arg }
    allow_any_instance_of(Rex::Proto::Http::Client).to receive(:close)
    allow_any_instance_of(Rex::Proto::Http::Client).to receive(:connect)
  end

  describe '#send_request' do
    context 'when a valid request is sent' do
      it 'returns a response object' do
        expect(subject.send_request({'uri'=>'/'})).to be_kind_of(Rex::Proto::Http::Response)
      end
    end
  end

  describe '#set_http_trace_proc' do
    let(:sample_request) {
      "GET / HTTP/1.1\nHost: www.google.com"
    }
    let(:sample_response) {
      res = Rex::Proto::Http::Response.new
      allow(res).to receive(:body).and_return("HTTP/1.1 302 Found\nLocation: https://www.google.com/?gws_rd=ssl")
      res
    }
    let(:expected_output) {
      [
        "####################",
        "# Request:",
        "####################",
        "%clr%bld%redGET / HTTP/1.1",
        "Host: www.google.com%clr",
        "####################",
        "# Response:",
        "####################",
        "%clr%bld%bluHTTP/1.1 200 OK\r",
        "\r",
        "HTTP/1.1 302 Found",
        "Location: https://www.google.com/?gws_rd=ssl%clr"
      ]
    }
    let(:nil_response_output) {
      [
        "####################",
        "# Request:",
        "####################",
        "%clr%bld%redGET / HTTP/1.1",
        "Host: www.google.com%clr",
        "####################",
        "# Response:",
        "####################",
        "%clr%bld%bluHTTP/1.1 200 OK\r",
        "\r",
        "HTTP/1.1 302 Found",
        "Location: https://www.google.com/?gws_rd=ssl%clr"
      ]
    }

    it 'returns a proc object when HttpTrace is set to true' do
      expect(subject.set_http_trace_proc(true, false, nil)).to be_kind_of(Proc)
    end

    it 'should execute the proc when defined' do
      subject.set_http_trace_proc(true, false, nil).call(sample_request, sample_response)
      expect(@output).to eq expected_output
    end

    it 'should give ideal message for nil response' do
      subject.set_http_trace_proc(true, false, nil).call(sample_request, sample_response)
      expect(@output).to eq nil_response_output
    end
  end

  describe '#set_http_trace_proc' do
    it 'returns nil when HttpTrace is set to false' do
      expect(subject.set_http_trace_proc(false, false, nil)).to be_nil
    end
  end

end
