require 'spec_helper'
require 'metasploit/framework/login_scanner/http'

RSpec.describe Metasploit::Framework::LoginScanner::HTTP do
  include_context 'Msf::UIDriver'
  include_context 'Msf::Simple::Framework'

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base', has_realm_key: true, has_default_realm: false
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
        expect(subject.send_request({ 'uri' => '/' })).to be_kind_of(Rex::Proto::Http::Response)
      end
    end
  end

  describe '#set_http_trace_proc' do
    let(:sample_request) do
      req = Rex::Proto::Http::ClientRequest.new({
        'agent' => 'Met',
        'data' => 'bufaction=verifyLogin&user=admin&password=turnkey'
      })
      req
    end

    let(:sample_response) do
      res = Rex::Proto::Http::Response.new(302, 'Found')
      allow(res).to receive(:body).and_return('Location: https://www.google.com/?gws_rd=ssl')
      res
    end

    let(:normal_request_output) do
      [
        '####################',
        '# Request:',
        '####################',
        "%clr%bld%redGET / HTTP/1.1\r",
        "Host: \r",
        "User-Agent: Met\r",
        "Content-Length: 49\r",
        "\r",
        'bufaction=verifyLogin&user=admin&password=turnkey%clr',
      ]
    end
    
    let(:normal_response_output) do
      [
        '####################',
        '# Response:',
        '####################',
        "%clr%bld%bluHTTP/1.1 302 Found\r",
        "\r",
        'Location: https://www.google.com/?gws_rd=ssl%clr'
      ]
    end

    let(:normal_request_response_output) do
      [
        '####################',
        '# Request:',
        '####################',
        "%clr%bld%redGET / HTTP/1.1\r",
        "Host: \r",
        "User-Agent: Met\r",
        "Content-Length: 49\r",
        "\r",
        'bufaction=verifyLogin&user=admin&password=turnkey%clr',
        '####################',
        '# Response:',
        '####################',
        "%clr%bld%bluHTTP/1.1 302 Found\r",
        "\r",
        'Location: https://www.google.com/?gws_rd=ssl%clr'
      ]
    end

    let(:nil_response_output) do
      [
        '####################',
        '# Request:',
        '####################',
        "%clr%bld%redGET / HTTP/1.1\r",
        "Host: \r",
        "User-Agent: Met\r",
        "Content-Length: 49\r",
        "\r",
        'bufaction=verifyLogin&user=admin&password=turnkey%clr',
        '####################',
        '# Response:',
        '####################',
        'No response received'
      ]
    end

    let(:headers_only_output) do
      [
        '####################',
        '# Request:',
        '####################',
        "%clr%bld%redGET / HTTP/1.1\r",
        "Host: \r",
        "User-Agent: Met\r",
        "Content-Length: 49\r",
        '%clr',
        '####################',
        '# Response:',
        '####################',
        "%clr%bld%bluHTTP/1.1 302 Found\r",
        "\r",
        '%clr'
      ]
    end

    let(:http_trace_colors_output_request) do
      [
        '####################',
        '# Request:',
        '####################',
        "%clr%bld%bluGET / HTTP/1.1\r",
        "Host: \r",
        "User-Agent: Met\r",
        "Content-Length: 49\r",
        "\r",
        'bufaction=verifyLogin&user=admin&password=turnkey%clr',
      ]
    end
    
    let(:http_trace_colors_output_response) do
      [
        '####################',
        '# Response:',
        '####################',
        "%clr%bld%grnHTTP/1.1 302 Found\r",
        "\r",
        'Location: https://www.google.com/?gws_rd=ssl%clr'
      ]
    end

    let(:http_trace_colors_output) do
      [
        '####################',
        '# Request:',
        '####################',
        "%clr%bld%bluGET / HTTP/1.1\r",
        "Host: \r",
        "User-Agent: Met\r",
        "Content-Length: 49\r",
        "\r",
        'bufaction=verifyLogin&user=admin&password=turnkey%clr',
        '####################',
        '# Response:',
        '####################',
        "%clr%bld%grnHTTP/1.1 302 Found\r",
        "\r",
        'Location: https://www.google.com/?gws_rd=ssl%clr'
      ]
    end

    let(:http_trace_single_color_output) do
      [
        '####################',
        '# Request:',
        '####################',
        "%clr%bld%yelGET / HTTP/1.1\r",
        "Host: \r",
        "User-Agent: Met\r",
        "Content-Length: 49\r",
        "\r",
        'bufaction=verifyLogin&user=admin&password=turnkey%clr',
        '####################',
        '# Response:',
        '####################',
        "%clrHTTP/1.1 302 Found\r",
        "\r",
        'Location: https://www.google.com/?gws_rd=ssl%clr'
      ]
    end

    let(:http_trace_single_color_output_leading_slash) do
      [
        '####################',
        '# Request:',
        '####################',
        "%clrGET / HTTP/1.1\r",
        "Host: \r",
        "User-Agent: Met\r",
        "Content-Length: 49\r",
        "\r",
        'bufaction=verifyLogin&user=admin&password=turnkey%clr',
        '####################',
        '# Response:',
        '####################',
        "%clr%bld%yelHTTP/1.1 302 Found\r",
        "\r",
        'Location: https://www.google.com/?gws_rd=ssl%clr'
      ]
    end

    let(:http_trace_no_color_output) do
      [
        '####################',
        '# Request:',
        '####################',
        "%clrGET / HTTP/1.1\r",
        "Host: \r",
        "User-Agent: Met\r",
        "Content-Length: 49\r",
        "\r",
        'bufaction=verifyLogin&user=admin&password=turnkey%clr',
        '####################',
        '# Response:',
        '####################',
        "%clrHTTP/1.1 302 Found\r",
        "\r",
        'Location: https://www.google.com/?gws_rd=ssl%clr'
      ]
    end

    it 'returns a proc object to log request when HttpTrace is set to true' do
      expect(subject.set_http_trace_proc_request(true, false, nil)).to be_kind_of(Proc)
    end

    it 'returns a proc object to log response when HttpTrace is set to true' do
      expect(subject.set_http_trace_proc_response(true, false, nil)).to be_kind_of(Proc)
    end

    it 'should output the provided request with headers when HttpTrace is set' do
      subject.set_http_trace_proc_request(true, false, nil).call(sample_request)
      expect(@output).to eq normal_request_output
    end

    it 'should output the provided response with headers when HttpTrace is set' do
      subject.set_http_trace_proc_response(true, false, nil).call(sample_response)
      expect(@output).to eq normal_response_output
    end

    it 'should output the provided request and response with headers when HttpTrace is set' do
      subject.set_http_trace_proc_request(true, false, nil).call(sample_request)
      subject.set_http_trace_proc_response(true, false, nil).call(sample_response)
      expect(@output).to eq normal_request_response_output
    end
    
    it 'should give "no response received" message for nil response' do
      subject.set_http_trace_proc_request(true, false, nil).call(sample_request)
      subject.set_http_trace_proc_response(true, false, nil).call(nil)
      expect(@output).to eq nil_response_output
    end

    it 'should log HTTP headers only when HttpTraceHeadersOnly is set' do
      subject.set_http_trace_proc_request(true, true, nil).call(sample_request)
      subject.set_http_trace_proc_response(true, true, nil).call(sample_response)
      expect(@output).to eq headers_only_output
    end

    it 'should log HTTP requests and responses with body when HttpTraceHeadersOnly is unset' do
      subject.set_http_trace_proc_request(true, nil, nil).call(sample_request)
      subject.set_http_trace_proc_response(true, nil, nil).call(sample_response)
      expect(@output).to eq normal_request_response_output
    end

    it 'should log HTTP requests in the respective colors specified' do
      subject.set_http_trace_proc_request(true, false, 'blu/grn').call(sample_request)
      expect(@output).to eq http_trace_colors_output_request
    end

     it 'should log HTTP responses in the respective colors specified' do
      subject.set_http_trace_proc_response(true, false, 'blu/grn').call(sample_response)
      expect(@output).to eq http_trace_colors_output_response
    end
     
     it 'should log HTTP requests and responses in the respective colors specified' do
      subject.set_http_trace_proc_request(true, false, 'blu/grn').call(sample_request)
      subject.set_http_trace_proc_response(true, false, 'blu/grn').call(sample_response)
      expect(@output).to eq http_trace_colors_output
    end

    it 'should only log HTTP request in color when only one color is specified followed by a trailing "/"' do
      subject.set_http_trace_proc_request(true, false, 'yel/').call(sample_request)
      subject.set_http_trace_proc_response(true, false, 'yel/').call(sample_response)
      expect(@output).to eq http_trace_single_color_output
    end

    it 'should only log HTTP response in color when only one color is specified after a leading "/"' do
      subject.set_http_trace_proc_request(true, false, '/yel').call(sample_request)
      subject.set_http_trace_proc_response(true, false, '/yel').call(sample_response)
      expect(@output).to eq http_trace_single_color_output_leading_slash
    end

    it 'should not log HTTP request and response in color when HttpTraceColors is set to "/"' do
      subject.set_http_trace_proc_request(true, false, '/').call(sample_request)
      subject.set_http_trace_proc_response(true, false, '/').call(sample_response)
      expect(@output).to eq http_trace_no_color_output
    end

    it 'should only log HTTP request in color when only one color is specified without any "/"s' do
      subject.set_http_trace_proc_request(true, false, 'yel').call(sample_request)
      subject.set_http_trace_proc_response(true, false, 'yel').call(sample_response)
      expect(@output).to eq http_trace_single_color_output
    end

    it 'returns nil when HttpTrace is set to false' do
      expect(subject.set_http_trace_proc_request(false, false, nil)).to be_nil
      expect(subject.set_http_trace_proc_response(false, false, nil)).to be_nil
    end

    it 'returns nil when HttpTrace is unset' do
      expect(subject.set_http_trace_proc_request(nil, false, nil)).to be_nil
      expect(subject.set_http_trace_proc_response(nil, false, nil)).to be_nil
    end
  end
end
