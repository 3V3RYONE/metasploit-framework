
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

  # @param http_trace_datastore [bool] stores whether HTTP-Tracing is enabled 
  # @param http_trace_headers_only [bool] stores whether the HTTP headers only, need to be showed in HTTP-Trace
  # @param http_trace_colors_string [string] stores the HTTP request and response colors for HTTP-Trace
  def initialize(http_trace_datastore = false, http_trace_headers_only = false, http_trace_colors_string = 'red/blue')
    @http_trace = http_trace_datastore
    @http_trace_headers = http_trace_headers_only
    @http_trace_colors = http_trace_colors_string
    puts "Object Created for HTTP Trace"
  end

  def use_http_trace_request(req, method)
    if @http_trace
      puts "HTTP Trace will track the request"
      puts "Request method : #{method}"
    end
  end

  def use_http_trace_response(res, code)
    if @http_trace
      puts "HTTP Trace will track the response"
      puts "Response code : #{code}"
    end
  end
end

end
end
end
