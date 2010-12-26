-- Copyright (c) 2010 by Robert G. Jakabosky <bobby@neoawareness.com>
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in
-- all copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
-- THE SOFTWARE.

local print = print
local pairs = pairs
local format = string.format
local setmetatable = setmetatable
local assert = assert
local tconcat = table.concat

local ev = require"ev"
local nsocket = require"handler.nsocket"
local lhp = require"http.parser"

--
-- Chunked Transfer Encoding filter
--
local function chunked()
	local is_eof = false
	return function(chunk)
		if chunk == "" then
			return ""
		elseif chunk then
			local len = #chunk
			-- prepend chunk length
			return format('%x\r\n', len) .. chunk .. '\r\n'
		elseif not is_eof then
			-- nil chunk, mark stream EOF
			is_eof = true
			-- return zero-length chunk.
			return '0\r\n\r\n'
		end
		return nil
	end
end

local client_mt = {}
client_mt.__index = client_mt

function client_mt:get_name()
	return self.host .. ":" .. tostring(port)
end

function client_mt:close()
	local sock = self.sock
	if sock then
		self.sock = nil
		return sock:close()
	end
end

function client_mt:handle_error(loc, err)
	if err == 'closed' then
		self.is_closed = true
		local pool = self.pool
		if pool then
			pool:handle_disconnect(self)
		end
	else
		print('httpconnection:', loc, err)
	end
end

function client_mt:handle_connected()
end

function client_mt:handle_data(data)
	-- TODO: handle parial parsing of data.
	local bytes_parsed = self.parser:execute(data)
	assert(bytes_parsed == #data, "failed to parse all received data.")
end

local function gen_headers(data, headers)
	for k,v in pairs(headers) do
		data = data .. k .. ": " .. v .. "\r\n"
	end
	return data
end

function client_mt:queue_request(req)
	assert(self.cur_req == nil, "TODO: no pipeline support yet!")
	self.cur_req = req
	local data
	-- gen: Request-Line
	data = req.method .. " " .. req.path .. " " .. req.http_version .. "\r\n"
	-- preprocess request body
	self:preprocess_body()
	-- gen: Request-Headers
	data = gen_headers(data, req.headers) .. "\r\n"
	-- send request.
--print('--- start request headers:')
--print(data)
	self.sock:send(data)
--print('--- end request headers:')
	-- send request body
	if not self.expect_100 then
		self:send_body()
	end
end

-- this need to be called before writting headers.
function client_mt:preprocess_body()
	local req = self.cur_req
	local body = req.body
	-- if no request body, then we are finished.
	if not body then return end

	-- set "Expect: 100-continue" header
	req.headers.Expect = "100-continue"
	self.expect_100 = true

	local body_type = req.body_type
	local src
	if body_type == 'string' then
		src = ltn12.source.string(body)
	elseif body_type == 'object' then
		src = body:get_source()
	else
		-- body is the LTN12 source
		src = body
	end

	-- if no Content-Length, then use chunked transfer encoding.
	if not req.headers['Content-Length'] then
		req.headers['Transfer-Encoding'] = 'chunked'
		-- add chunked filter.
		src = ltn12.filter.chain(src, chunked())
	end

	self.body_src = src
end

function client_mt:send_body()
	local req = self.cur_req
	local body = req.body
	-- if no request body or body has already been sent, then return
	if self.sent_request_body then return end
	self.sent_request_body = true

	local data = {}
	local sink = ltn12.sink.table(data)
	ltn12.pump.all(self.body_src, sink)
	data = tconcat(data)

--print('--- start request body:')
--print(data)
--print('--- end request body:')
	self.sock:send(data)
end

local function call_callback(req, cb, ...)
	local meth_cb = req[cb]
	if meth_cb then
		meth_cb(req, ...)
	end
end

local function create_response_parser(self)
	local resp
	local headers
	local cur_header
	local parser

	function self.on_message_begin()
		-- setup response object.
		resp = {}
		headers = {}
		resp.headers = headers
	end

	function self.on_header_field(header)
		cur_header = header
	end

	function self.on_header_value(val)
		headers[cur_header] = val
	end

	function self.on_headers_complete()
		local status_code = parser:status_code()
		-- check for expect_100
		if self.expect_100 and status_code == 100 then
			-- send request body now.
			self:send_body()
			-- don't process message complete event from the "100 Continue" response.
			self.skip_complete = true
			return
		end
		-- save response status.
		resp.status_code = status_code
		-- call request's on_response callback
		call_callback(self.cur_req, 'on_response', resp)
	end

	function self.on_body(data)
		-- call request's on_data callback
		call_callback(self.cur_req, 'on_data', resp, data)
	end

	function self.on_message_complete()
		if self.skip_complete then
			self.expect_100 = false
			self.skip_complete = false
			return
		end
		-- call request's on_finished callback
		call_callback(self.cur_req, 'on_finished', resp)
		resp = nil
		headers = nil
	end

	parser = lhp.response(self)
	self.parser = parser
end

module'handler.http.connection'

function client(loop, host, port, is_https, pool)
	assert(not is_https, "HTTPS not supported yet!")
print('new http connection to:',host,port)
	local conn = setmetatable({
		is_client = is_client,
		is_https = is_https,
		is_closed = false,
		host = host,
		port = port,
		pool = pool,
		expect_100 = false,
		sent_request_body = false,
		skip_complete = false,
	}, client_mt)

	create_response_parser(conn)

	conn.sock = nsocket.new(loop, conn, host, port)

	return conn
end

function server(loop, sock, is_https)
	assert(false, "HTTP server-side connections not supported yet!")
end
