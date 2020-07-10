#!/usr/bin/env lua5.3

local port = 8888
local clientid = "1234567890client"
local clientpass = "clientpass"
local deviceid = "1234567890device"
local devicekey = {0x0c, 0xc0, 0x52, 0xf6, 0x7b, 0xbd, 0x05, 0x0e, 0x75, 0xac, 0x0d, 0x43, 0xf1, 0x0a, 0x8f, 0x35}
devicekey = string.pack(string.rep("B",16), table.unpack(devicekey))

local cqueues = require "cqueues"
local http_server = require "http.server"
local http_headers = require "http.headers"
local cjson = require "cjson.safe"
local cipher = require "openssl.cipher"
local rand = require "openssl.rand"
local hmac = require "openssl.hmac"
local b64 = require "b64"
local fmt = string.format

local cq = cqueues.new()

local function make_otp(operation, key, nonce1)
  local t = {
    OP = operation,
    N1 = nonce1,
    N2 = tostring(string.unpack("L", rand.bytes(8)))
  }
  local plain = cjson.encode(t)
  plain = plain .. string.rep(' ', 16 - (#plain % 16))
  local aes = cipher.new("AES-128-CBC")
  local iv = rand.bytes(16)
  aes:encrypt(key, iv, false)
  local ivaes = iv .. aes:final(plain)
  return b64.encode(ivaes .. hmac.new(key, "sha256"):final(ivaes))
end

local function authorize_operation_handler(stream, res_headers)
  res_headers:append(":status", "200")
  res_headers:append("content-type", "application/json")
  local body = assert(stream:get_body_as_string())
  local json = assert(cjson.decode(body))
  local reqclientid = json.client_id
  local reqoperation = json.operation
  local loadb64 = json.load
  assert(json.device_id == deviceid, "client not found")
  assert(reqclientid == clientid, "client not found")
  assert(json.client_pass == clientpass, "invalid client password")
  assert(reqoperation == "lock" or reqoperation == "unlock", "invalid operation")
  assert(not string.find(loadb64, "[^a-zA-Z0-9/%+=]"), "invalid base64 load")
  local loadraw = b64.decode(loadb64)
  loadraw = string.sub(loadraw, 1, #loadraw - (#loadraw % 16))
  assert(#loadraw >= 64, "load too small")
  local loadcbc = string.sub(loadraw, 1, -33)
  local loadhmac = string.sub(loadraw, -32)
  assert(hmac.new(devicekey, "sha256"):final(loadcbc) == loadhmac, "invalid HMAC")
  local iv = string.sub(loadcbc, 1, 16)
  local ciphertext = string.sub(loadcbc, 17, -1)
  local aes = cipher.new("AES-128-CBC")
  aes:decrypt(devicekey, iv, false)
  local message1 = aes:final(ciphertext)
  local message1 = assert(cjson.decode(message1), "invalid device message")
  local nonce1 = message1.N1
  assert(nonce1, "Nonce 1 not provided")
  local otp = make_otp(reqoperation, devicekey, nonce1)
  local t = { success = true, otp = otp }
  assert(stream:write_headers(res_headers, false))
  assert(stream:write_chunk(cjson.encode(t), true))
end

local myserver =
  assert(http_server.listen {
           host = "0.0.0.0";
           port = port;
           cq = cq;
           onstream = function(myserver, stream)
             local req_headers = assert(stream:get_headers())
             local req_method = req_headers:get ":method"

             local res_headers = http_headers.new()
             if req_method ~= "POST" and req_method ~= "HEAD" then
               res_headers:upsert(":status", "405")
               assert(stream:write_headers(res_headers, true))
               return
             end
             if req_headers:get ":path" == "/authorize-operation"
             and req_headers:get "content-type" == "application/json" then
               return authorize_operation_handler(stream, res_headers)
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
