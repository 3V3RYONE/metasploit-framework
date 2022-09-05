
require 'spec_helper'
require 'metasploit/framework/login_scanner/http'

RSpec.describe Metasploit::Framework::LoginScanner::HTTP do
  include_context 'Msf::UIDriver'
  include_context 'Msf::Simple::Framework'
  
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
      res = Rex::Proto::Http::Response.new(302,'Found')
      allow(res).to receive(:body).and_return("Location: https://www.google.com/?gws_rd=ssl")
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
        "%clr%bld%bluHTTP/1.1 302 Found\r",
        "\r",
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
        "No response received"
      ]
    }

    let(:nil_request_output) {
      [
        "####################",
        "# Request:",
        "####################",
        "%clr%bld%red%clr",
        "####################",
        "# Response:",
        "####################",
        "No response received"
      ]
    }


    let(:headers_only_output) {
      [
        "####################",
        "# Request:",
        "####################",
        "%clr%bld%redGET / HTTP/1.1",
        "Host: www.google.com%clr",
        "####################",
        "# Response:",
        "####################",
        "%clr%bld%bluHTTP/1.1 302 Found\r",
        "\r",
        "%clr"
      ]
    }

    let(:http_trace_colors_output) {
      [
        "####################",
        "# Request:",
        "####################",
        "%clr%bld%bluGET / HTTP/1.1",
        "Host: www.google.com%clr",
        "####################",
        "# Response:",
        "####################",
        "%clr%bld%grnHTTP/1.1 302 Found\r",
        "\r",
        "Location: https://www.google.com/?gws_rd=ssl%clr"
      ]
    }

    let(:http_trace_single_color_output) {
      [
        "####################",
        "# Request:",
        "####################",
        "%clr%bld%yelGET / HTTP/1.1",
        "Host: www.google.com%clr",
        "####################",
        "# Response:",
        "####################",
        "%clrHTTP/1.1 302 Found\r",
        "\r",
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

    it 'should give "no response received" message for nil response' do
      subject.set_http_trace_proc(true, false, nil).call(sample_request, nil)
      expect(@output).to eq nil_response_output
    end

    it 'should log empty message for nil request' do
      subject.set_http_trace_proc(true, false, nil).call(nil, nil)
      expect(@output).to eq nil_request_output
    end

    it 'should log HTTP headers only when HttpTraceHeadersOnly is set' do
      subject.set_http_trace_proc(true, true, nil).call(sample_request, sample_response)
      expect(@output).to eq headers_only_output
    end

    it 'should log HTTP requests and responses with body when HttpTraceHeadersOnly is unset' do
      subject.set_http_trace_proc(true, nil, nil).call(sample_request, sample_response)
      expect(@output).to eq expected_output
    end

    it 'should log HTTP requests and responses in the specified color' do
      subject.set_http_trace_proc(true, false, 'blu/grn').call(sample_request, sample_response)
      expect(@output).to eq http_trace_colors_output
    end

    it 'should only log HTTP request in color when only one colour is specified' do
      subject.set_http_trace_proc(true, false, 'yel/').call(sample_request, sample_response)
      expect(@output).to eq http_trace_single_color_output
    end

    it 'should only log HTTP request in color when only one color is specified without "/"' do
      subject.set_http_trace_proc(true, false, 'yel').call(sample_request, sample_response)
      expect(@output).to eq http_trace_single_color_output
    end

    it 'returns nil when HttpTrace is set to false' do
      expect(subject.set_http_trace_proc(false, false, nil)).to be_nil
    end

    it 'returns nil when HttpTrace is unset' do
      expect(subject.set_http_trace_proc(nil, false, nil)).to be_nil
    end
  end

end
