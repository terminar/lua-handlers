
local openssl = require('openssl')
local bit = require('bit32')

local DEFAULT_CIPHERS = 'ECDHE-RSA-AES128-SHA256:AES128-GCM-SHA256:' .. -- TLS 1.2
        '!RC4:HIGH:!MD5:!aNULL:!EDH'                     -- TLS 1.0

local function readAll(file)
    local f = assert(io.open(file, "rb"))
    local content = f:read("*all")
    f:close()
    return content
end
local DEFAULT_CA_STORE
--[[
do
    local data = assert(readAll("./root_ca.dat"))
    DEFAULT_CA_STORE = openssl.x509.store:new()
    local index = 1
    local dataLength = #data
    while index < dataLength do
        local len = bit.bor(bit.lshift(data:byte(index), 8), data:byte(index + 1))
        index = index + 2
        local cert = assert(openssl.x509.read(data:sub(index, index + len)))
        index = index + len
        assert(DEFAULT_CA_STORE:add(cert))
    end
end
--]]

local function returnOne()
    return 1
end

local function getContext(options)
    local options = options or {}

    local ctx = openssl.ssl.ctx_new(
        options.protocol or 'TLSv1_2',
        options.ciphers or DEFAULT_CIPHERS)

    local key, cert, ca
    if options.key then
        key = assert(openssl.pkey.read(options.key, true, 'pem'))
    end
    if options.cert then
        cert = {}
        for chunk in options.cert:gmatch("%-+BEGIN[^-]+%-+[^-]+%-+END[^-]+%-+") do
            cert[#cert + 1] = assert(openssl.x509.read(chunk))
        end
    end
    if options.ca then
        if type(options.ca) == "string" then
            ca = { assert(openssl.x509.read(options.ca)) }
        elseif type(options.ca) == "table" then
            ca = {}
            for i = 1, #options.ca do
                ca[i] = assert(openssl.x509.read(options.ca[i]))
            end
        else
            error("options.ca must be string or table of strings")
        end
    end
    if key and cert then
        local first = table.remove(cert, 1)
        assert(ctx:use(key, first))
        if #cert > 0 then
            -- TODO: find out if there is a way to not need to duplicate the last cert here
            -- as a dummy fill for the root CA cert
            assert(ctx:add(cert[#cert], cert))
        end
    end
    if ca then
        local store = openssl.x509.store:new()
        for i = 1, #ca do
            assert(store:add(ca[i]))
        end
        ctx:cert_store(store)
    elseif DEFAULT_CA_STORE then
        ctx:cert_store(DEFAULT_CA_STORE)
    end
    if not (options.insecure or options.key) then
        ctx:verify_mode(openssl.ssl.peer, returnOne)
    end

    ctx:options(bit.bor(
        openssl.ssl.no_sslv2,
        openssl.ssl.no_sslv3,
        openssl.ssl.no_compression))

    return ctx
end

-- writeCipher is called when ssl needs something written on the socket
-- handshakeComplete is called when the handhake is complete and it's safe
-- onPlain is called when plaintext comes out.
local function bioWrap(ctx, isServer, self, handshakeComplete)

    local bin, bout = openssl.bio.mem(8192), openssl.bio.mem(8192)
    local ssl = ctx:ssl(bin, bout, isServer)

    local socket = self.sock
    local ssocket = {tls=true}
    local onPlain

    local function flush(callback)
        local chunks = {}
        local i = 0
        while bout:pending() > 0 do
            i = i + 1
            chunks[i] = bout:read()
        end
        if i == 0 then
            if callback then callback() end
            return true
        end
        return socket:write(chunks, callback)
    end

    local function handshake(callback)
        if ssl:handshake() then
            local success, result = ssl:getpeerverification()
            socket:read_stop()
            if not success and result then
                handshakeComplete("Error verifying peer: " .. result[1].error_string)
            end
            handshakeComplete(nil, ssocket)
        end
        return flush(callback)
    end

    local function onCipher(err, data)
        if not onPlain then
            if err or not data then
                return handshakeComplete(err or "Peer aborted the SSL handshake", data)
            end
            bin:write(data)
            return handshake()
        end
        if err or not data then
            return onPlain(err, data)
        end
        bin:write(data)
        while  true do
            local plain = ssl:read()
            if not plain then break end
            onPlain(nil, plain)
        end
    end

    -- When requested to start reading, start the real socket and setup
    -- onPlain handler
    function ssocket.read_start(_, onRead)
        onPlain = onRead
        return socket:read_start(onCipher)
    end

    -- When requested to write plain data, encrypt it and write to socket
    function ssocket.write(_, plain, callback)
        ssl:write(plain)
        return flush(callback)
    end

    function ssocket.shutdown(_, ...)
        return socket:shutdown(...)
    end
    function ssocket.read_stop(_, ...)
        return socket:read_stop(...)
    end
    function ssocket.is_closing(_, ...)
        return socket:is_closing(...)
    end
    function ssocket.close(_, ...)
        return socket:close(...)
    end
    function ssocket.write_queue_size()
        return socket:write_queue_size()
    end

    handshake()
    socket:read_start(onCipher)
end

local function init(self, options, is_client, callback)
  if options == true then options = {} end
  local ctx = getContext(options)

  bioWrap(ctx, (is_client ~= true), self, callback or function (err, ssocket)
  end)
end

module(...)

wrap = init
