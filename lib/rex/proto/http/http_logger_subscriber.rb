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
    @logger.print_line("....Request....")
    @logger.print_line("#{request}")
  end
  
  def on_response(response)
    @logger.print_line("....Response....")
    @logger.print_line("#{response}")
  end
end
end
end
end
