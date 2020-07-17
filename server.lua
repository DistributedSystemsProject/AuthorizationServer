#!/usr/bin/env lua5.3

local cqueues = require "cqueues"
local http_server = require "http.server"
local http_headers = require "http.headers"
local cjson = require "cjson.safe"
local cipher = require "openssl.cipher"
local rand = require "openssl.rand"
local hmac = require "openssl.hmac"
local sslcontext = require "openssl.ssl.context"
local sslpkey = require "openssl.pkey"
local x509 = require "openssl.x509"
local x509chain = require "openssl.x509.chain"
local b64 = require "b64"
local fmt = string.format

local usetls = arg[1] ~= "dev"
local tlschainpath = "fullchain.pem"
local tlskeypath = "privkey.pem"
local port = 8888
local cq = cqueues.new()
local tlsctx = nil

local tickets = {}

local testclientid = "1234567890client"
local testclientpass = "clientpass"
local testdeviceid = "1234567890device"
local testdevicekey = {0x0c, 0xc0, 0x52, 0xf6, 0x7b, 0xbd, 0x05, 0x0e, 0x75, 0xac, 0x0d, 0x43, 0xf1, 0x0a, 0x8f, 0x35}
testdevicekey = string.pack(string.rep("B",16), table.unpack(testdevicekey))

if usetls then -- setup TLS
  tlsctx = sslcontext.new("TLS", true)
  local keyf = assert(io.open(tlskeypath))
  local key = keyf:read("a")
  keyf:close()
  local chainf = assert(io.open(tlschainpath))
  local chainstr = chainf:read("a")
  chainf:close()
  local chain = x509chain.new()
  local cert
  local i = 1
  while true do
    local ipos = chainstr:find("-----BEGIN CERTIFICATE-----", i, true)
    if not ipos then break end
    _,i = assert(chainstr:find("-----END CERTIFICATE-----", ipos, true))
    local ccert = x509.new(string.sub(chainstr, ipos, i))
    if not cert then
      cert = ccert
    else
      chain:add(ccert)
    end
  end
  assert(cert, "No certificate found in: " .. tlschainpath)
  tlsctx:setCertificate(cert)
  tlsctx:setCertificateChain(chain)
  local pkey = sslpkey.new(key, "PEM")
  tlsctx:setPrivateKey(pkey)
end

local function auth_decrypt(message, key)
  assert(#message >= 64, "load too small")
  local iv_blocks = string.sub(message, 1, -33)
  local messagehmac = string.sub(message, -32)
  assert(hmac.new(key, "sha256"):final(iv_blocks) == messagehmac, "invalid HMAC")
  local iv = string.sub(iv_blocks, 1, 16)
  local ciphertext = string.sub(iv_blocks, 17, -1)
  local aes = cipher.new("AES-128-CBC")
  aes:decrypt(key, iv, false)
  return aes:final(ciphertext)
end

local function auth_encrypt(plain, key)
  local rem = #plain % 16
  plain = plain .. string.rep(' ', rem == 0 and 0 or 16 - rem)
  local aes = cipher.new("AES-128-CBC")
  local iv = rand.bytes(16)
  aes:encrypt(key, iv, false)
  local ivaes = iv .. aes:final(plain)
  return ivaes .. hmac.new(key, "sha256"):final(ivaes)
end

local function make_confirmation(N3, key)
  local t = {
    N3 = N3
  }
  return b64.encode(auth_encrypt(cjson.encode(t), key))
end

local function make_authopmsg(operation, key, N1, N2)
  local t = {
    OP = operation,
    N1 = N1,
    N2 = N2
  }
  return b64.encode(auth_encrypt(cjson.encode(t), key))
end

local function client_error(stream, res_headers)
  res_headers:upsert(":status", "400")
  assert(stream:write_headers(res_headers, true))
end

local function safe_decode_load(dload)
  assert(#dload < 500, "device load too large")
  assert(not string.find(dload, "[^a-zA-Z0-9/%+=]"), "invalid base64 device load")
  dload = b64.decode(dload)
  local loadlen = #dload
  dload = string.sub(dload, 1, loadlen - (loadlen % 16))
  return dload
end

local function authenticate_client(clientid, clientpass)
  return clientpass == testclientpass and clientid == testclientid
end

local function authorize_client(clientid, deviceid, operation)
  return clientid == testclientid and deviceid == testdeviceid and
    (operation == "lock" or operation == "unlock")
end

local function get_device_key(deviceid)
  if deviceid == testdeviceid then
    return testdevicekey
  else
    error("deviceid not found")
  end
end

local function record_authorization(ticket, N2, clientid, deviceid, operation)
  tickets[ticket] = {
    N2 = N2, clientid = clientid, deviceid = deviceid, operation = operation, ts = os.time()
  }
end

local function get_ticketdata(ticket)
  local ticketdata = tickets[ticket]
  if ticketdata and (os.time() - ticketdata.ts) > 120 then
    return nil
  else
    return ticketdata
  end
end
local function authorize_operation_handler(stream, res_headers)
  local body = stream:get_body_as_string()
  if not body then return client_error(stream, res_headers) end
  local json = cjson.decode(body)
  if not json then return client_error(stream, res_headers) end
  local clientid = json.client_id
  local clientpass = json.client_pass
  local deviceid = json.device_id
  local operation = json.operation
  local deviceload = json.load
  if not (clientid and deviceid and operation and deviceload and clientpass) then
    return client_error(stream, res_headers)
  end
  if not authenticate_client(clientid, clientpass) then
    res_headers:upsert(":status", "403")
    assert(stream:write_headers(res_headers, true))
    return
  end
  if not authorize_client(clientid, deviceid, operation) then
    res_headers:upsert(":status", "403")
    assert(stream:write_headers(res_headers, true))
    return
  end
  local binload = safe_decode_load(deviceload)
  local key = get_device_key(deviceid)
  local devjson = assert(cjson.decode(auth_decrypt(binload, key)))
  local N1 = devjson.N1
  assert(N1)
  local ticket = string.format("%x", (string.unpack("l", rand.bytes(8))))
  local N2 = string.format("%x", (string.unpack("l", rand.bytes(8))))
  record_authorization(ticket, N2, clientid, deviceid, operation)
  local aOP = make_authopmsg(operation, key, N1, N2)
  local body = cjson.encode({ success = true, load = aOP, ticket = ticket })
  res_headers:append(":status", "200")
  res_headers:append("content-type", "application/json")
  assert(stream:write_headers(res_headers, false))
  assert(stream:write_chunk(body, true))
end

local function confirm_operation_handler(stream, res_headers)
  local body = stream:get_body_as_string()
  if not body then return client_error(stream, res_headers) end
  local json = cjson.decode(body)
  if not json then return client_error(stream, res_headers) end
  local ticket = json.ticket
  local deviceload = json.load
  if not (ticket and deviceload) then
    return client_error(stream, res_headers)
  end
  local ticketdata = get_ticketdata(ticket)
  if not ticketdata then
    res_headers:upsert(":status", "403")
    assert(stream:write_headers(res_headers, true))
    return
  end
  local binload = safe_decode_load(deviceload)
  local key = get_device_key(ticketdata.deviceid)
  local devjson = assert(cjson.decode(auth_decrypt(binload, key)))
  local N2 = devjson.N2
  local N3 = devjson.N3
  assert(N2 == ticketdata.N2, "Invalid nonce received during confirmation")
  local confirmation = make_confirmation(N3, key)
  local body = cjson.encode({ success = true, load = confirmation })
  res_headers:append(":status", "200")
  res_headers:append("content-type", "application/json")
  assert(stream:write_headers(res_headers, false))
  assert(stream:write_chunk(body, true))
end

local myserver =
  assert(http_server.listen {
           tls = usetls;
           ctx = tlsctx;
           host = "0.0.0.0";
           port = port;
           cq = cq;
           onstream = function(myserver, stream)
             local req_headers = assert(stream:get_headers())
             local req_method = req_headers:get ":method"

             local res_headers = http_headers.new()
             if req_method ~= "POST" then
               res_headers:upsert(":status", "405")
               assert(stream:write_headers(res_headers, true))
               return
             end
             if req_headers:get(":path") == "/authorize-operation" and
             req_headers:get "content-type" == "application/json" then
               return authorize_operation_handler(stream, res_headers)
             elseif req_headers:get(":path") == "/confirm-operation" and
             req_headers:get "content-type" == "application/json" then
               return confirm_operation_handler(stream, res_headers)
             else
               res_headers:append(":status", "404")
               assert(stream:write_headers(res_headers, true))
             end
           end;
           onerror = function(myserver, context, op, err, errno)
             local msg = op .. " on " .. tostring(context) .. " failed"
             if err then
               msg = msg .. ": " .. tostring(err)
             end
             assert(io.stderr:write(msg, "\n"))
           end;
  })

assert(myserver:listen())
do
  local bound_port = select(3, myserver:localname())
  assert(io.stderr:write(string.format("Now listening on port %d\n", bound_port)))
end

assert(myserver:loop())
