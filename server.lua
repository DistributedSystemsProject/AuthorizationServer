#!/usr/bin/env lua5.3

local cqueues = require "cqueues"
local lredis = require "lredis.cqueues"
local resolver = require 'cqueues.dns.resolver'
local http_server = require "http.server"
local http_headers = require "http.headers"
local cjson = require "cjson.safe"
local cipher = require "openssl.cipher"
local rand = require "openssl.rand"
local hmac = require "openssl.hmac"
local digest = require "openssl.digest"
local sslcontext = require "openssl.ssl.context"
local sslpkey = require "openssl.pkey"
local x509 = require "openssl.x509"
local x509chain = require "openssl.x509.chain"
local b64 = require "b64"
local uECC = require("uECC").secp192r1()
local fmt = string.format

local usetls = arg[1] ~= "dev"
local oplogpath = "operations.log"
local tlschainpath = "fullchain.pem"
local tlskeypath = "privkey.pem"
local port = 8888
local cq = cqueues.new()
local tlsctx = nil

local testclientid = "1234567890client"
local testclientpass = "clientpass"
local testdeviceid = "1234567890device"
function xtb(t) return string.pack(string.rep("B",#t), table.unpack(t)) end
local testdevicepk = xtb { 0xb9, 0x41, 0x5d, 0x30, 0x00, 0x30, 0x1a, 0x83, 0x62, 0x60, 0x22, 0x30, 0x65, 0xcd, 0x21, 0xd9, 0xd7, 0x3a, 0x90, 0x43, 0x2b, 0xa6, 0x54, 0xe6, 0xa1, 0x0a, 0x3e, 0xb7, 0xeb, 0x8f, 0x71, 0x76, 0xbe, 0xca, 0xa0, 0x5d, 0x89, 0xb0, 0xb9, 0x4b, 0x85, 0x2f, 0xce, 0xd2, 0x75, 0x8e, 0x7b, 0x53 }
local testserverpk = xtb { 0xdc, 0x27, 0xa5, 0x67, 0x1d, 0xcb, 0x00, 0x0d, 0xc4, 0x1b, 0x99, 0x96, 0x84, 0x0b, 0xb3, 0xc0, 0x08, 0xe2, 0x91, 0x08, 0xd1, 0x59, 0x49, 0x40, 0x1f, 0x05, 0x7a, 0x28, 0xe0, 0x46, 0x81, 0x7e, 0xfa, 0xcc, 0x67, 0x90, 0xf0, 0x5d, 0xef, 0xfd, 0x13, 0x78, 0xf5, 0xaf, 0x2d, 0xd8, 0xa9, 0x21 }
local testserversk = xtb { 0xaa, 0x2e, 0x99, 0xf6, 0xba, 0xfe, 0x95, 0xdc, 0xd5, 0x9d, 0x3c, 0x94, 0xe4, 0x9e, 0xd0, 0xb7, 0xbf, 0xb3, 0xde, 0x1b, 0xb8, 0x04, 0x7b, 0x2a }

function string.tohex(str)
    return (str:gsub('.', function (c)
        return string.format('%02X', string.byte(c))
    end))
end

local redisaddr
do
  local r = resolver.new({lookup = {"file"}})
  local packet = r:query("redisserv")
  assert(packet, "Could not find redis server address")
  local section = packet:grep({section = "ANSWER"})()
  redisaddr = section:addr()
end
local redis = lredis.connect_tcp(redisaddr)
-- load test db items
if redis:call("get", "testdbitems") ~= "v4" then
  redis:call("flushall")
  redis:call("set", "clientpass:"..testclientid, testclientpass)
  redis:call("set", "devkeys:"..testdeviceid, testdevicepk)
  redis:call("sadd", "cldevops:"..testclientid..":"..testdeviceid, "lock", "unlock")
  redis:call("set", "testdbitems", "v3")
end

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

local function make_kx(ephpk, peerpk) 
  print("kp1.pk: ", peerpk:tohex())
  local shared1 = uECC:sharedsecret(ephpk, testserversk)
  local key1 = string.sub(digest.new("sha256"):final(shared1), 1, 16)
  print("key1: ", key1:tohex())
  eph2 = uECC:keygen()
  local shared2 = uECC:sharedsecret(peerpk, eph2.sk)
  local key2 = string.sub(digest.new("sha256"):final(shared2), 1, 16)
  return key1, eph2.pk, key2
end

local function make_authopmsg(eph2pk, operation, key)
  local t = {
    PK = b64.encode(eph2pk),
    OP = operation
  }
  return auth_encrypt(cjson.encode(t), key)
end

local function client_error(stream, res_headers)
  res_headers:upsert(":status", "400")
  assert(stream:write_headers(res_headers, true))
end

local function safe_decode_load(dload)
  assert(#dload < 500, "device load too large")
  assert(not string.find(dload, "[^a-zA-Z0-9/%+=]"), "invalid base64 device load")
  dload = b64.decode(dload)
  return dload
end

local function authenticate_client(clientid, clientpass)
  return clientpass == redis:call("get", "clientpass:"..clientid)
end

local function authorize_client(clientid, deviceid, operation)
  local t = redis:call("smembers", "cldevops:"..clientid..":"..deviceid)
  for _,op in ipairs(t) do
    if op == operation then
      return true
    end
  end
  return false
end

local function get_device_pk(deviceid)
  return redis:call("get", "devkeys:"..deviceid)
end

local function record_session(ticket, seskey, clientid, deviceid, operation)
  redis:call("hmset", ticket, "seskey", seskey, "clientid", clientid, "deviceid", deviceid, "operation", operation)
  redis:call("expire", ticket, "120")
end

local function get_ticketdata(ticket)
  local t = redis:call("hgetall", ticket)
  local tt = {}
  for i=1,#t,2 do
    tt[t[i]] = t[i+1]
  end
  return tt
end

local function log_operation(td)
  local log = os.time().." cli: "..td.clientid.."; dev: "..td.deviceid.."; op: "..td.operation
  redis:call("rpush", "oplog", log)
end

local function notarize_hash(hash)
  print("Logger: Log notarization to be implemented")
end

-- thread that every 5 minutes saves a block of logs to disk and its hash on the blockchain
local function log_notarizer()
  while true do
    cqueues.sleep(300)
    local all = redis:call("lrange", "oplog", "0", "-1")
    if #all > 1 then
      local block = "###BEGIN_BLOCK\n"..table.concat(all, "\n").."\n###END_BLOCK\n"
      local f = io.open(oplogpath, "a")
      f:write(block)
      f:close()
      notarize_hash(digest.new("sha256"):final(block))
      redis:call("del", "oplog")
    end
  end
end
cq:wrap(log_notarizer)

local function authorize_operation_handler(stream, res_headers)
  local body = stream:get_body_as_string()
  if not body then return client_error(stream, res_headers) end
  local json = cjson.decode(body)
  if not json then return client_error(stream, res_headers) end
  local clientid = json.client_id
  local clientpass = json.client_pass
  local deviceid = json.device_id
  local deviceload = json.load
  local operation = json.operation
  if not (clientid and deviceid and deviceload and clientpass) then
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
  binload = string.sub(binload, 1, 48)
  local peerpk = assert(get_device_pk(deviceid))
  local key1, eph2pk, key2 = make_kx(binload, peerpk)
  local ticket = string.format("%x", (string.unpack("l", rand.bytes(8))))
  local aOP = make_authopmsg(eph2pk, operation, key1)
  record_session(ticket, key2, clientid, deviceid, operation)
  local body = cjson.encode({ success = true, load = b64.encode(aOP), ticket = ticket })
  res_headers:append(":status", "200")
  res_headers:append("content-type", "application/json")
  assert(stream:write_headers(res_headers, false))
  assert(stream:write_chunk(body, true))
end

local function result_handler(stream, res_headers)
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
  binload = string.sub(binload, 1, #binload - (#binload % 16))
  local devjson = assert(cjson.decode(auth_decrypt(binload, ticketdata.seskey)))
  local RES = devjson.RES
  if RES then
    log_operation(ticketdata)
  end
  local body = cjson.encode({ success = RES })
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
             elseif req_headers:get(":path") == "/result" and
             req_headers:get "content-type" == "application/json" then
               return result_handler(stream, res_headers)
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
