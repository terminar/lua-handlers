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

local setmetatable = setmetatable
local print = print
local assert = assert
local error = error

local d = print

local uv = require"luv"

--new --================================================================================================================
local import = require 'core.functions'.import
local async,wait,wwait,wcont = import('core.fiber',"new","wait","wwait","wcont")

--[[
local function tcp()
    local new = {
        _sock = uv.new_tcp(),
        callbacks = {}
    }


    local function currySock(fn)
        return function(self,...)
            return fn(self._sock,...);
        end
    end

    local fns = wwait(wcont{
        getaddr = uv.getaddrinfo,
        connect = uv.tcp_connect,
        write = uv.write,
        read = uv.read_start,
        close = uv.close,
        shutdown = uv.shutdown
    })

    new.connect = function(self,addr,port)
        local err,res = fns.getaddr(addr,port,{socktype="STREAM",family="inet"})
        if err then return err,nil; else
            return fns.connect(self._sock,res[1].addr,res[1].port)
        end
    end

    new.close = currySock(fns.close)
    new.write = currySock(fns.write)
    new.read = currySock(fns.read)
    new.shutdown = currySock(fns.shutdown)

    return new;
end
--]]

--new --================================================================================================================


--TODO: tls_backend
--local tls_backend = require"handler.connection.tls_backend"
--local sock_tls_wrap = tls_backend.wrap

local uri_mod = require"handler.uri"
local uri_parse = uri_mod.parse
local query_parse = uri_mod.parse_query

local function n_assert(test, errno, msg)
	return assert(test, msg)
end

-- important errors
--local EINPROGRESS = nixio.const.EINPROGRESS

local function sock_setsockopt(self, level, option, value)
--TODO: setsockopt
--	return self.sock:setsockopt(level, option, value)
end

local function sock_getsockopt(self, level, option)
--TODO: setsockopt
--	return self.sock:getsockopt(level, option)
end

local function sock_getpeername(self) --OK
--	return self.sock:getpeername()
    return uv.tcp_getpeername(self.sock)
end

local function sock_getsockname(self) --OK
--	return self.sock:getsockname()
    return uv.tcp_getsockname(self.sock);
end

local function sock_block_read(self, block)
--TODO: sock_block_read
--[[
	-- block/unblock read
	if block ~= self.read_blocked then
		self.read_blocked = block
		if block then
			self.io_read:stop(self.loop)
		else
			self.io_read:start(self.loop)
		end
	end
--]]
end

local function sock_shutdown(self, read, write)
--TODO: sock_shutdown
	local how = ''
	if read then
		how = 'rd'
		-- stop reading from socket, we don't want any more data.
		sock_block_read(self, true)
    end
    --[[
	if write then
		how = how .. 'wr'
	end
	return self.sock:shutdown(how)
	--]]
--TODO: sock_shutdown_cb async
    if write then
        --return self.sock:shutdown()
        uv.shutdown(self.sock)
    end
end

local function sock_close(self)
--TODO: sock_close
	local sock = self.sock
	if not sock then return end
	self.is_closing = true
	self.read_blocked = true
	if not self.write_buf or self.has_error then
        --[[
		local loop = self.loop
		if self.write_timer then
			self.write_timer:stop(loop)
		end
		self.io_write:stop(loop)
		self.io_read:stop(loop)
		sock:close()
		--]]
        --sock:close();
--TODO: close cb
        uv.close(sock)
		self.sock = nil
	end
end

local function sock_handle_error(self, err)

	self.has_error = true -- mark socket as bad.
	sock_close(self)
	local handler = self.handler
	if handler then
		local errFunc = handler.handle_error
		if errFunc then
			errFunc(handler, err)
		else
			print('socket error:', err)
		end
	end

end

local function sock_set_write_timeout(self, timeout)
--TODO: sock_set_write_timeout
--[[
	local timer = self.write_timer
	-- default to no write timeout.
	timeout = timeout or -1
	self.write_timeout = timeout
	-- enable/disable timeout
	local is_disable = (timeout <= 0)
	-- create the write timer if one is needed.
	if not timer then
		-- don't create a disabled timer.
		if is_disable then return end
		timer = ev.Timer.new(function()
			sock_handle_error(self, 'write timeout')
		end, timeout, timeout)
		self.write_timer = timer
		-- enable timer if socket is write blocked.
		if self.write_blocked then
			timer:start(self.loop)
		end
		return
	end
	-- if the timer should be disabled.
	if is_disable then
		-- then disable the timer
		timer:stop(self.loop)
		return
	end
	-- update timeout interval and start the timer if socket is write blocked.
	if self.write_blocked then
		timer:again(self.loop, timeout)
	end
--]]
end

local function sock_reset_write_timeout(self)
--TODO: reset_write_timeout
--[[
	local timeout = self.write_timeout
	local timer = self.write_timer
	-- write timeout is disabled.
	if timeout < 0 or timer == nil then return end
	-- update timeout interval
	timer:again(self.loop, timeout)
--]]
end

local function sock_send_data(self, buf)
    local sock = self.sock
    local is_blocked = false

    --don't send empty data
    if not buf or #buf == 0 then return; end

    --local num, errno, err = sock:send(buf,self.callbacks.write_cb)

--TODO: check write errors
--TODO: check write size
--[[
    Streams keep track of the queued bytes (stream->write_queue_size). You
    should use that to check if the client is not reading or it's too slow
    at reading and just pause the writing on your end. You can check the
    number of queued bytes in the write callbacks to decide when to resume
    sending data.
--]]
    --sync write func

    d("trying to write buf (" .. string.len(buf) .. "): " .. buf)
    local num,err = uv.try_write(sock,buf)
    d("bytes written: " .. (num or "0"))
    if not num then
        -- got timeout error block writes.
--TODO: correct error
--        err = "EAGAIN"
        --if num ~= nil and (num == false or num < 0) then
--TODO: BAD queue hack. This is used if connection is in progress and write data is queued. (httpclient)
        if not num and err:match("EPIPE") then
            -- got EAGAIN
            is_blocked = true
        else -- data == nil
        -- report error
            sock_handle_error(self, err)
            return nil, err
        end
    else
        -- trim sent data.
        if num < #buf then
            d("buf num is < #buf")
            -- remove sent bytes from buffer.
            buf = buf:sub(num+1)
            -- partial send, not enough socket buffer space, so blcok writes.
            is_blocked = true
        else
            d("buffer written, clearing write buf")
            self.write_buf = nil
            if self.is_closing then
                -- write buffer is empty, finish closing socket.
                sock_close(self)
                return num, 'closed'
            end
        end
    end
    -- block/un-block write events.
    if is_blocked ~= self.write_blocked then
        self.write_blocked = is_blocked
        if is_blocked then
            self.write_buf = buf
            --self.io_write:start(self.loop)
            -- socket is write blocked, start write timeout
            sock_reset_write_timeout(self)
            return num, 'blocked'
        else
            local loop = self.loop
            --TODO: write io timer etc
            --self.io_write:stop(loop)
            -- no data to write, so stop timer.
            --if self.write_timer then
            --    self.write_timer:stop(loop)
            --end
        end
    elseif is_blocked then
--TODO: write timeout
        -- reset write timeout, since some data was written and the socket is still write blocked.
        --sock_reset_write_timeout(self)
    end
    return num
end

local function sock_send(self, data) --OK
	-- only process send when given data to send.
	if data == nil or #data == 0 then return end
	local num, err
	local buf = self.write_buf
	if buf then
		buf = buf .. data
	else
		buf = data
	end
	if not self.write_blocked then
		num, err = sock_send_data(self, buf)
	else
		self.write_buf = buf
		-- let the caller know that the socket is blocked and data is being buffered
		err = 'blocked'
	end

	-- always return the size of the data passed in, since un-sent data will be buffered
	-- for sending later.
	return #data, err

end

local function sock_handle_connected(self) --OK
    d("sock_handle_connected")
	local handler = self.handler
	self.is_connecting = false
	if handler then
		local handle_connected = handler.handle_connected
		if handle_connected then
			handle_connected(handler)
		end
	end

end

local function sock_recv_data(self,err,data)
    d("sock_recv_data: " .. data)
    local read_len = self.read_len
    local read_max = self.read_max
    local handler = self.handler
    local sock = self.sock
    local len = 0

    if err then
        sock_handle_error(err);
        return false,err
    end

    --just callback end, end of data block
    if not data then
        return true;
    end

--TODO: fix read_cb style
--    repeat
--        local data, errno, err = sock:recv(read_len)
    --[[
        if not data then
            if data == false then
                -- no data
                return true
            else -- data == nil
            -- report error
            sock_handle_error(self, err)
            return false, err
            end
        end
     --]]
        -- check if the other side shutdown there send stream
        if #data == 0 then
            -- report socket closed
            d("sock is closed")
            sock_handle_error(self, 'closed')
            return false, 'closed'
        end
        -- pass read data to handler
        len = len + #data
        d("handle data:" .. (data or "-"))
        --err = handler:handle_data(data)
---[[
        local callstat,callerr = pcall(function()
            err = handler:handle_data(data)
        end);

        if not callstat and callerr then
                d("Call error: " .. callerr)
        end
--]]
        if err then
            -- report error
            d("error handling data")
            sock_handle_error(self, err)
            return false, err
        end
--    until len >= read_max or self.read_blocked

    d("sock_recv_data done");
    return true
end

local function sock_sethandler(self, handler)

	self.handler = handler
	if handler and not self.is_connecting then
		-- raise 'connected' event for the new handler
		sock_handle_connected(self)
	end

end

local function sock_is_closed(self)
	return self.is_closing
end

local sock_mt = {
    is_tls = false,
    send = sock_send,
    getsockopt = sock_getsockopt,
    setsockopt = sock_setsockopt,
    getsockname = sock_getsockname,
    getpeername = sock_getpeername,
    shutdown = sock_shutdown,
    close = sock_close,
    block_read = sock_block_read,
    set_write_timeout = sock_set_write_timeout,
    sethandler = sock_sethandler,
    is_closed = sock_is_closed,
}
sock_mt.__index = sock_mt

--[[
local function sock_wrap_nixio(loop, handler, sock, is_connected)
    -- create socket object
    local self = {
        loop = loop,
        handler = handler,
        sock = sock,
        is_connecting = true,
        write_blocked = false,
        write_timeout = -1,
        read_blocked = false,
        read_len = 8192,
        read_max = 65536,
        is_closing = false,
    }
    setmetatable(self, sock_mt)

    -- make nixio socket non-blocking
    sock:setblocking(false)
    -- get socket FD
    local fd = sock:fileno()
    -- create callback closure
    local write_cb = function()
        local num, err = sock_send_data(self, self.write_buf)
        if self.write_buf == nil and not self.is_closing then
            -- write buffer is empty and socket is still open,
            -- call drain callback.
            local handler = self.handler
            local drain = handler.handle_drain
            if drain then
                local err = drain(handler)
                if err then
                    -- report error
                    sock_handle_error(self, err)
                end
            end
        end
    end
    local read_cb = function()
        sock_recv_data(self)
    end

    -- create IO watchers.
    if is_connected then
        self.io_write = ev.IO.new(write_cb, fd, ev.WRITE)
        self.is_connecting = false
    else
        local connected_cb = function(loop, io, revents)
            if not self.write_blocked then
                io:stop(loop)
            end
            -- change callback to write_cb
            io:callback(write_cb)
            -- check for connect errors by tring to read from the socket.
            sock_recv_data(self)
        end
        self.io_write = ev.IO.new(connected_cb, fd, ev.WRITE)
        self.io_write:start(loop)
    end
    self.io_read = ev.IO.new(read_cb, fd, ev.READ)
    self.io_read:start(loop)

    return self
end
--]]

local function sock_wrap(loop, handler, sock, is_connected)
    d("SOCK_WRAP")
	-- create socket object
	local self = {
		loop = loop,
		handler = handler,
		sock = sock,
		is_connecting = true,
		write_blocked = false,
		write_timeout = -1,
		read_blocked = false,
		read_len = 8192,
		read_max = 65536,
		is_closing = false,
        callbacks = {}
	}
	setmetatable(self, sock_mt)

    --TODO: blocking? fd?
	-- make nixio socket non-blocking
--	sock:setblocking(false)
	-- get socket FD
--	local fd = sock:fileno()


    self.callbacks.connected_cb = function(err)
        if err then
            sock_handle_error(self,err);
            return;
        end

        sock_handle_connected(self)

        --throw write if we have queued data
        self.callbacks.write_cb()

        d("calling read_start")
        uv.read_start(self.sock,self.callbacks.read_cb)
        d("connected_cb done")
    end

    self.callbacks.read_cb = function(err,data)
        if err then
            d("read-cb called, error: " .. err)
        else
            d("read-cb called: data> " .. (data or "-"))
        end
        sock_recv_data(self,err,data)
        d("uv_read_start")
        uv.read_start(self.sock,self.callbacks.read_cb)
        d("read_cb done")
    end

    -- create callback closure
    --called if socket is available for writing!
	self.callbacks.write_cb = function()

        if self.write_buf then
            d("Write buf is set")
		    local num, err = sock_send_data(self, self.write_buf)
        end

		if self.write_buf == nil and not self.is_closing then
			-- write buffer is empty and socket is still open,
			-- call drain callback.
			local handler = self.handler
			local drain = handler.handle_drain
			if drain then
				local err = drain(handler)
				if err then
					-- report error
					sock_handle_error(self, err)
				end
			end
		end
	end

    -- create IO watchers.
    if is_connected then
--        self.io_write = ev.IO.new(write_cb, fd, ev.WRITE)
        --fire connected event
        --        self.is_connecting = false <- done in handle_connected
        sock_handle_connected(self);
        d("calling read_start")
        uv.read_start(self.sock,self.callbacks.read_cb)
        d("is_connected, read_start done")

--TODO: socket available for writing - handler io cb
--[[
    else
        local connected_cb = function(loop, io, revents)
            if not self.write_blocked then
                io:stop(loop)
            end
            -- change callback to write_cb
            io:callback(write_cb)
            -- check for connect errors by tring to read from the socket.
            sock_recv_data(self)
        end
        self.io_write = ev.IO.new(connected_cb, fd, ev.WRITE)
        self.io_write:start(loop)
--]]
    end

--  self.io_read = ev.IO.new(read_cb, fd, ev.READ)
    --set callback and start read
--    uv.read_start(self.sock,self.callbacks.read_cb)

    return self
end

local function sock_new_connect(loop, handler, domain, _type, host, port, laddr, lport)

    d("sock_new_connect")

--TODO: wrap new_socket? with commands?
-- create nixio socket
--local sock = new_socket(domain, _type)


    --_type == stream,dgram,unix
    --domain == inet,inet6
    local sock;
    if _type == "stream" then
        sock = uv.new_tcp();
    elseif _type == "dgram" then
        sock = uv.new_udp();
    elseif _type == "unix" then
        sock = uv.new_pipe(false)
    else
        return nil,"Type unknown"
    end

    -- create libuv socket
    if not sock then
        return nil,"Error creating socket"
    else

        -- wrap socket
        local self = sock_wrap(loop,handler,sock);
        self._type = _type;
        self._family = domain;


        if _type == "stream" then

            d("getaddrinfo")
            uv.getaddrinfo(host,port,{socktype=_type,family=domain},function(err,res)
                d("getaddrinfo ready")

                if not res[1] or not res[1].addr or not res[1].port then
                    err = "Error resolving host or port"
                end

                if err then
                    d("getaddrinfo handle error")
                    sock_handle_error(self,err);
                else
                    d("calling tcp_connect")

                    -- bind to local laddr/lport
                    if laddr then

                        --n_assert(sock:setsockopt('socket', 'reuseaddr', 1)) <- automatically set on tcp

--TODO: check if it is working
--TODO: getaddrinfo for local
                        --parameter4 = { ipv6only = true|false}
                        uv.tcp_bind(self.sock,laddr,tonumber(lport or 0))

                        --udp-bind: parameter4: { reuseaddr = true|false, ipv6only = true|false }
                        --[[
                        --reuseaddr:
                        * This sets the SO_REUSEPORT socket flag on the BSDs and OS X. On other
                        * UNIX platforms, it sets the SO_REUSEADDR flag. What that means is that
                        * multiple threads or processes can bind to the same address without error
                        * (provided they all set the flag) but only the last one to bind will receive
                        * any traffic, in effect "stealing" the port from the previous listener.
                        * This behavior is something of an anomaly and may be replaced by an explicit
                        * opt-in mechanism in future versions of libuv.
                        --]]
                    end

                    -- connect to host:port
                    if _type == "stream" then
                        uv.tcp_connect(self.sock,res[1].addr,res[1].port,self.callbacks.connected_cb)
                    end

                end
            end);


            d("returning self in sock_new_connect")
            return self;
        else
--TODO: implement UDP
--store gethostaddr for send socket stuff
-- udp_bind

--TODO: implement UNIX
            return nil,"NYI: " .. domain .. "/" .. _type
        end

    end

end

-- remove '[]' from IPv6 addresses
local function strip_ipv6(ip6) --OK
	if ip6 and ip6:sub(1,1) == '[' then
		return ip6:sub(2,-2)
	end
	return ip6
end

local _M = {}

--
-- TCP/UDP/Unix sockets (non-tls)
--
function _M.tcp6(loop, handler, host, port, laddr, lport) --OK
	host = strip_ipv6(host)
	laddr = strip_ipv6(laddr)
	return sock_new_connect(loop, handler, 'inet6', 'stream', host, port, laddr, lport)
end

function _M.tcp(loop, handler, host, port, laddr, lport) --OK
	if host:sub(1,1) == '[' then
		return _M.tcp6(loop, handler, host, port, laddr, lport)
	else
		return sock_new_connect(loop, handler, 'inet', 'stream', host, port, laddr, lport)
	end
    return sock_new_connect(loop, handler, 'inet', 'stream', host, port, laddr, lport)
end

function _M.udp6(loop, handler, host, port, laddr, lport) --OK
	host = strip_ipv6(host)
	laddr = strip_ipv6(laddr)
	return sock_new_connect(loop, handler, 'inet6', 'dgram', host, port, laddr, lport)
end

function _M.udp(loop, handler, host, port, laddr, lport) --OK
	if host:sub(1,1) == '[' then
		return _M.udp6(loop, handler, host, port, laddr, lport)
	else
		return sock_new_connect(loop, handler, 'inet', 'dgram', host, port, laddr, lport)
	end
end

function _M.unix(loop, handler, path) --OK
	return sock_new_connect(loop, handler, 'unix', 'stream', path)
end

function _M.wrap_connected(loop, handler, sock)
--TODO: sock connected wrap
    --[[
	-- wrap socket
	return sock_wrap(loop, handler, sock, true)
	--]]
end

--
-- TCP TLS sockets
--
function _M.tls_tcp(loop, handler, host, port, tls, is_client, laddr, lport)
--TODO: tls_tcp
    --[[
	local self = _M.tcp(loop, handler, host, port, laddr, lport)
	-- default to client-side TLS
	if is_client == nil then is_client = true end
	return sock_tls_wrap(self, tls, is_client)
	--]]
end

function _M.tls_tcp6(loop, handler, host, port, tls, is_client, laddr, lport)
--TODO: tls_tcp6
    --[[
	local self = _M.tcp6(loop, handler, host, port, laddr, lport)
	-- default to client-side TLS
	if is_client == nil then is_client = true end
	return sock_tls_wrap(self, tls, is_client)
	--]]
end

function _M.tls_wrap_connected(loop, handler, sock, tls, is_client)
--TODO: tls_wrap_connected
    --[[
	-- wrap socket
	local self = sock_wrap(loop, handler, sock, false)
	-- default to server-side TLS
	if is_client == nil then is_client = false end
	return sock_tls_wrap(self, tls, is_client)
    --]]
end

--
-- URI
--
function _M.uri(loop, handler, uri) --OK
	local orig_uri = uri
	-- parse uri
	uri = uri_parse(uri)
	local scheme = uri.scheme
	assert(scheme, "Invalid listen URI: " .. orig_uri)
	local q = query_parse(uri.query)
	-- use scheme to select socket type.
	if scheme == 'unix' then
		return _M.unix(loop, handler, uri.path)
	else
		local host, port = uri.host, uri.port or default_port
		if scheme == 'tcp' then
			return _M.tcp(loop, handler, host, port, q.laddr, q.lport)
		elseif scheme == 'tcp6' then
			return _M.tcp6(loop, handler, host, port, q.laddr, q.lport)
		elseif scheme == 'udp' then
			return _M.udp(loop, handler, host, port, q.laddr, q.lport)
		elseif scheme == 'udp6' then
			return _M.udp6(loop, handler, host, port, q.laddr, q.lport)
		else
			local mode = q.mode or 'client'
			local is_client = (mode == 'client')
			-- default to client-side
			-- create TLS context
			local tls = nixio.tls(mode)
			-- set key
			if q.key then
				tls:set_key(q.key)
			end
			-- set certificate
			if q.cert then
				tls:set_cert(q.cert)
			end
			-- set ciphers
			if q.ciphers then
				tls:set_ciphers(q.ciphers)
			end
			if scheme == 'tls' then
				return _M.tls_tcp(loop, handler, host, port, tls, is_client, q.laddr, q.lport)
			elseif scheme == 'tls6' then
				return _M.tls_tcp6(loop, handler, host, port, tls, is_client, q.laddr, q.lport)
			end
		end
	end
	error("Unknown listen URI scheme: " .. scheme)
end

-- export
_M.wrap = sock_wrap

return _M;