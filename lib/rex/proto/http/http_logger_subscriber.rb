# -*- coding: binary -*-

require 'rex/socket'
require 'rex/text'
require 'digest'

module Rex
module Proto
module Http

class HttpLoggerSubscriber < HttpSubscriber
  def initialize(logger:)
    @logger = logger
  end

  def on_request(request)
    if http_trace
      @logger.print_line("#"*20)
      @logger.print_line("# Request:")
      @logger.print_line("#"*20)
      @logger.print_line("#{request}")
    end
  end
  
  def on_response(response)
    if http_trace
      @logger.print_line("#"*20)
      @logger.print_line("# Response:")
      @logger.print_line("#"*20)
      @logger.print_line("#{response}")
    end
  end
end
end
end
end
