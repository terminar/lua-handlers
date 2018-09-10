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
local show = require 'pl.pretty'.write

local handler = require"handler"
local poll = handler.get_poller()

local uv = require"luv"

local _M = {}

function _M.getaddr(host,port, domain, type, callback)
  uv.getaddrinfo(host,port, {
      numericserv = true,
      addrconfig = true,
      socktype = type or "stream",
      family=domain or "inet"
      --[[
      canonname = true,
      all = true,
      v4mapped = true,
    --]]
  }
  , function (err, data)
    if callback then
        if err then
            return callback(nil,nil,err)
        elseif #data > 0 then
	        return callback(data[1].addr,data[1].port,nil)
        else
            return callback(nil,nil,"unknown")
        end
    end
    
  end)

end

--[=[

  -- simple callback
    -- address only
  resolver:getaddr('google.com', function(addr, port, err)
    -- return true to get the next address.
  end)
    -- address and port
  resolver:getaddr('google.com', 'http', function(addr, port, err)
  end)

  resolver:getname('127.0.0.1:80', function(name, service, err)
  end)

  -- and maybe a more complex one, see getaddrinfo(3) man page
  resolver:getaddrinfo('google.com', 'http', { --[[hints]] },
    function(addrinfo, err)
  end)
---------------------------------------------------------------------

  test("Get all local http addresses", function (print, p, expect, uv)
    assert(uv.getaddrinfo(nil, "http", nil, expect(function (err, res)
      p(res, #res)
      assert(not err, err)
      assert(res[1].port == 80)
    end)))
  end)

  test("Get all local http addresses sync", function (print, p, expect, uv)
    local res = assert(uv.getaddrinfo(nil, "http"))
    p(res, #res)
    assert(res[1].port == 80)
  end)

  test("Get only ipv4 tcp adresses for luvit.io", function (print, p, expect, uv)
    assert(uv.getaddrinfo("luvit.io", nil, {
      socktype = "stream",
      family = "inet",
    }, expect(function (err, res)
      assert(not err, err)
      p(res, #res)
      assert(#res == 1)
    end)))
  end)

  -- FIXME: this test always fails on AppVeyor for some reason
  if _G.isWindows and not os.getenv'APPVEYOR' then
    test("Get only ipv6 tcp adresses for luvit.io", function (print, p, expect, uv)
      assert(uv.getaddrinfo("luvit.io", nil, {
        socktype = "stream",
        family = "inet6",
      }, expect(function (err, res)
        assert(not err, err)
        p(res, #res)
        assert(#res == 1)
      end)))
    end)
  end

  test("Get ipv4 and ipv6 tcp adresses for luvit.io", function (print, p, expect, uv)
    assert(uv.getaddrinfo("luvit.io", nil, {
      socktype = "stream",
    }, expect(function (err, res)
      assert(not err, err)
      p(res, #res)
      assert(#res > 0)
    end)))
  end)

  test("Get all adresses for luvit.io", function (print, p, expect, uv)
    assert(uv.getaddrinfo("luvit.io", nil, nil, expect(function (err, res)
      assert(not err, err)
      p(res, #res)
      assert(#res > 0)
    end)))
  end)

  test("Lookup local ipv4 address", function (print, p, expect, uv)
    assert(uv.getnameinfo({
      family = "inet",
    }, expect(function (err, hostname, service)
      p{err=err,hostname=hostname,service=service}
      assert(not err, err)
      assert(hostname)
      assert(service)
    end)))
  end)

  test("Lookup local ipv4 address sync", function (print, p, expect, uv)
    local hostname, service = assert(uv.getnameinfo({
      family = "inet",
    }))
    p{hostname=hostname,service=service}
    assert(hostname)
    assert(service)
  end)

  test("Lookup local 127.0.0.1 ipv4 address", function (print, p, expect, uv)
    assert(uv.getnameinfo({
      ip = "127.0.0.1",
    }, expect(function (err, hostname, service)
      p{err=err,hostname=hostname,service=service}
      assert(not err, err)
      assert(hostname)
      assert(service)
    end)))
  end)

  test("Lookup local ipv6 address", function (print, p, expect, uv)
    assert(uv.getnameinfo({
      family = "inet6",
    }, expect(function (err, hostname, service)
      p{err=err,hostname=hostname,service=service}
      assert(not err, err)
      assert(hostname)
      assert(service)
    end)))
  end)

  test("Lookup local ::1 ipv6 address", function (print, p, expect, uv)
    assert(uv.getnameinfo({
      ip = "::1",
    }, expect(function (err, hostname, service)
      p{err=err,hostname=hostname,service=service}
      assert(not err, err)
      assert(hostname)
      assert(service)
    end)))
  end)

  test("Lookup local port 80 service", function (print, p, expect, uv)
    assert(uv.getnameinfo({
      port = 80,
      family = "inet6",
    }, expect(function (err, hostname, service)
      p{err=err,hostname=hostname,service=service}
      assert(not err, err)
      assert(hostname)
      assert(service == "http")
    end)))
  end)

end)

--]=]

return _M