
require 'spec_helper'
require 'metasploit/framework/login_scanner/http'
require 'rex'

RSpec.describe Metasploit::Framework::LoginScanner::HTTP do
  include_context 'Msf::UIDriver'
  def print_line(msg='')
    puts(msg+'\n')
  end

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: true, has_default_realm: false
  it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'
  it_behaves_like 'Metasploit::Framework::LoginScanner::HTTP'

  subject do
    described_class.new(driver)
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
      "HTTP/1.1 302 Found\nLocation: https://www.google.com/?gws_rd=ssl"
    }
    let(:expected_output) {
      "####################\n# Request:\n####################\nGET / HTTP/1.1\nHost: www.google.com\n####################\n# Response:\n####################\nHTTP/1.1 302 Found\nLocation: https://www.google.com/?gws_rd=ssl\n"
    }
    let(:nil_response_output) {
      "####################\n# Request:\n####################\nGET / HTTP/1.1\nHost: www.google.com\n####################\n# Response:\n####################\nNo response received\n"
    }

    it 'returns a proc object when HttpTrace is set to true' do
      expect(subject.set_http_trace_proc(true, false, nil)).to be_kind_of(Proc)
    end

    it 'should execute the proc when defined' do
      expect { subject.set_http_trace_proc(true, false, nil).call(sample_request, sample_response) }.to output(expected_output).to_stdout
    end

    it 'should give ideal message for nil response' do
      expect { subject.set_http_trace_proc(true, false, nil).call(sample_request, nil) }.to output(nil_response_output).to_stdout
    end
  end

  describe '#set_http_trace_proc' do
    it 'returns nil when HttpTrace is set to false' do
      expect(subject.set_http_trace_proc(false, false, nil)).to be_nil
    end
  end

end
