-- Copyright (c) 2010-2011 by Robert G. Jakabosky <bobby@neoawareness.com>
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

local pairs = pairs
local rawget = rawget
local rawset = rawset
local print = print
local setmetatable = setmetatable
local getmetatable = getmetatable
local assert = assert
local tostring = tostring

local common_headers = {
	"Accept",
	"Accept-Charset",
	"Accept-Encoding",
	"Accept-Language",
	"Accept-Ranges",
	"Age",
	"Allow",
	"Authorization",
	"Cache-Control",
	"Connection",
	"Content-Disposition",
	"Content-Encoding",
	"Content-Language",
	"Content-Length",
	"Content-Location",
	"Content-MD5",
	"Content-Range",
	"Content-Type",
	"Cookie",
	"Date",
	"ETag",
	"Expect",
	"Expires",
	"From",
	"Host",
	"If-Match",
	"If-Modified-Since",
	"If-None-Match",
	"If-Range",
	"If-Unmodified-Since",
	"Last-Modified",
	"Link",
	"Location",
	"Max-Forwards",
	"Pragma",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Range",
	"Referer",
	"Refresh",
	"Retry-After",
	"Server",
	"Set-Cookie",
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
	"User-Agent",
	"Vary",
	"Via",
	"WWW-Authenticate",
	"Warning",
}
-- create header normalize table.
local normalized = {}
for i=1,#common_headers do
	local name = common_headers[i]
	normalized[name] = name
	normalized[name:lower()] = name
end
local str_lower = string.lower
local has_ffi, ffi = pcall(require, 'ffi')
if jit and has_ffi and jit.version_num < 20100 then
	--
	-- NYI string.lower() replacement for LuaJIT 2.0.x
	--
	local tolower = ffi.new('char[255]')
	for i=0,255 do
		tolower[i] = (i >= 65 and i <= 90) and (i + 32) or i
	end
	local max = 1024
	local buf = ffi.new('char[?]', max)
	local byte = string.byte
	local fstr = ffi.string
	function str_lower(str)
		local len = #str
		if len >= max then
			return str:lower() -- fall back for large strings.
		end
		for i=0,len-1 do
			local c = byte(str, i+1)
			c = tolower[c]
			buf[i] = c
		end
		return fstr(buf, len)
	end
end

setmetatable(normalized, {
__index = function(names, name)
	-- search for normailized form of 'name'
	local norm = str_lower(name)
	-- if header name is already all lowercase, then just return it.
	-- otherwise check if there is a normalized version of the name.
	return (norm == name) and norm or (rawget(names, norm) or norm)
end
})

local headers_mt = {}

function headers_mt.__index(headers, name)
	-- lookup header's value using the normalized version of the name.
	return rawget(headers, normalized[name])
end

function headers_mt.__newindex(headers, name, value)
	-- normalize header name
	local norm = normalized[name]
	rawset(headers, norm, value)
	rawset(headers, #headers + 1, norm)
end

local _M = {}

local tmp = {}
function _M.new(headers)
	-- check if 'headers' has the same metatable already.
	if getmetatable(headers) == headers_mt then
		-- no need to re-convert this table.
		return headers
	end

	-- normalize existing headers
	if headers then
		-- make a list of header names.
		local idx = 0
		for name in pairs(headers) do
			idx = idx + 1
			rawset(tmp, idx, name)
		end
		-- add list of header names to headers table.
		for i=1,idx do
			local name = tmp[i]
			local val = headers[name]
			tmp[i] = nil -- clear temp. table.
			-- get normalized name
			local norm = normalized[name:lower()]
			-- if normalized name is different then current name.
			if norm and norm ~= name then
				-- then move value to normalized name.
				headers[norm] = val
				headers[name] = nil
			end
			headers[i] = name
		end
	else
		headers = {}
	end

	return setmetatable(headers, headers_mt)
end

function _M.dup(src)
	local dst = {}
	-- copy headers from src
	for i=1,#src do
		local name = src[i]
		local val = src[name]
		dst[name] = val
		dst[i] = name
	end
	return setmetatable(dst, headers_mt)
end

function _M.copy_defaults(dst, src)
	if dst == nil then
		return dup(src)
	end
	-- make sure 'dst' is a headers object
	dst = new(dst)
	-- copy headers from src
	for i=1,#src do
		local name = src[i]
		local val = src[name]
		if not dst[name] then
			dst[name] = val
		end
	end
	return dst
end

function _M.gen_headers(data, headers)
	local offset=#data
	for i=1,#headers do
		local name = headers[i]
		local val = headers[name]
		if val then
			offset = offset + 1
			data[offset] = name
			offset = offset + 1
			data[offset] = ": "
			offset = offset + 1
			data[offset] = val
			offset = offset + 1
			data[offset] = "\r\n"
		end
	end
	return offset
end

function _M.gen_headers_buf(buf, headers)
	for i=1,#headers do
		local name = headers[i]
		local val = headers[name]
		if val then
			buf:append_data(name)
			buf:append_data(": ")
			buf:append_data(tostring(val))
			buf:append_data("\r\n")
		end
	end
end

return _M