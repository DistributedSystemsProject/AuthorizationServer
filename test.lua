#!/usr/bin/env lua

local req_timeout = 10

local request = require "http.request"
local cipher = require "openssl.cipher"
local rand = require "openssl.rand"
local hmac = require "openssl.hmac"
local b64 = require "b64"
local cjson = require "cjson"

local testdevicekey = {0x0c, 0xc0, 0x52, 0xf6, 0x7b, 0xbd, 0x05, 0x0e, 0x75, 0xac, 0x0d, 0x43, 0xf1, 0x0a, 0x8f, 0x35}
testdevicekey = string.pack(string.rep("B",16), table.unpack(testdevicekey))

local function safe_decode_load(dload)
  assert(#dload < 500, "device load too large")
  assert(not string.find(dload, "[^a-zA-Z0-9/%+=]"), "invalid base64 device load")
  dload = b64.decode(dload)
  local loadlen = #dload
  dload = string.sub(dload, 1, loadlen - (loadlen % 16))
  return dload
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
  local iv = "aaaaaaaaffffffff"
  aes:encrypt(key, iv, false)
  local ivaes = iv .. aes:final(plain)
  return ivaes .. hmac.new(key, "sha256"):final(ivaes)
end

local N1 = "2389432"
local bload = (b64.encode(auth_encrypt(cjson.encode{N1 = N1}, testdevicekey)))
local bodyt = {
    client_id= "1234567890client",
    device_id= "1234567890device",
    client_pass= "clientpass",
    operation= "unlock",
    load = bload
}

local req = request.new_from_uri("http://127.0.0.1:8888/authorize-operation")
req.headers:upsert(":method", "POST")
req.headers:append("content-type", "application/json")
req:set_body(cjson.encode(bodyt))

local headers, stream = req:go(req_timeout)
if headers == nil then
	io.stderr:write(tostring(stream), "\n")
	os.exit(1)
end
local body, err = stream:get_body_as_string()
if not body and err then
	io.stderr:write(tostring(err), "\n")
	os.exit(1)
end

local reply1 = cjson.decode(body)
local ticket = reply1.ticket
local reply1dev = cjson.decode(auth_decrypt(safe_decode_load(reply1.load), testdevicekey))
assert(reply1dev.N1 == N1)
assert(reply1dev.OP == "unlock")


local N3 = "1319131"
local bload = (b64.encode(auth_encrypt(cjson.encode{N2 = reply1dev.N2, N3 = N3}, testdevicekey)))
local bodyt = {
  ticket = ticket,
  load = bload
}

local req = request.new_from_uri("http://127.0.0.1:8888/confirm-operation")
req.headers:upsert(":method", "POST")
req.headers:append("content-type", "application/json")
req:set_body(cjson.encode(bodyt))

local headers, stream = req:go(req_timeout)
if headers == nil then
	io.stderr:write(tostring(stream), "\n")
	os.exit(1)
end
local body, err = stream:get_body_as_string()
if not body and err then
	io.stderr:write(tostring(err), "\n")
	os.exit(1)
end

local reply2 = cjson.decode(body)
local reply1dev = cjson.decode(auth_decrypt(safe_decode_load(reply2.load), testdevicekey))
assert(reply1dev.N3 == N3)
