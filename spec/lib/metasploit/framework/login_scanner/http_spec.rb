
require 'spec_helper'
require 'metasploit/framework/login_scanner/http'

RSpec.describe Metasploit::Framework::LoginScanner::HTTP do

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: true, has_default_realm: false
  it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'
  it_behaves_like 'Metasploit::Framework::LoginScanner::HTTP'

  subject do
    described_class.new
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

  describe '#configure_http_client' do
  let(:http_client) { instance_double Rex::Proto::Http::Client, set_config: nil }
  before(:each) do
    subject.configure_http_client(http_client)
  end

  it 'configures http tracing' do
     expected_options = hash_including({
       'http_trace' => true,
       'http_trace_proc' => an_instance_of(Proc)
     })
     expect(http_client).to have_received(:set_config).with(expected_options)
  end
end

end
