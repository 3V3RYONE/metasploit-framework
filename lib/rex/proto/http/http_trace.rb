
require 'rex/socket'

module Rex
module Proto
module Http

###
# 
# This class provides methods for tracing HTTP requests
# and responses for HTTP client and server.
#
###
class HttpTrace
  # TODO: configure the datastore options related to HTTP-Trace
  # with default instance variable of this class.
  def initialize()
    puts "Object Created for HTTP Trace"
  end

  def use_http_trace_request(req, colors)
    puts "HTTP Trace will track the request"
  end

  def use_http_trace_response(res, colors)
    puts "HTTP Trace will track the response"
  end
end

end
end
end
