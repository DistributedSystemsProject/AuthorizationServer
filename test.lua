#!/usr/bin/env lua
local host = arg[1]

local req_timeout = 5

local digest = require "openssl.digest"
local request = require "http.request"
local cipher = require "openssl.cipher"
local rand = require "openssl.rand"
local hmac = require "openssl.hmac"
local b64 = require "b64"
local cjson = require "cjson"
local uECC = require("uECC").secp192r1()
host = "http://127.0.0.1:8888"

function string.tohex(str)
    return (str:gsub('.', function (c)
        return string.format('%02X', string.byte(c))
    end))
end

function xtb(t) return string.pack(string.rep("B",#t), table.unpack(t)) end
local devicesk = xtb { 0x02, 0xf2, 0x82, 0x21, 0xfb, 0x3a, 0x22, 0xa4, 0x48, 0x92, 0x8c, 0x44, 0x99, 0x61, 0x20, 0xfb, 0xf7, 0xbe, 0x2d, 0xa3, 0xf6, 0xcd, 0xc2, 0xe2 }
local serverpk = xtb { 0xdc, 0x27, 0xa5, 0x67, 0x1d, 0xcb, 0x00, 0x0d, 0xc4, 0x1b, 0x99, 0x96, 0x84, 0x0b, 0xb3, 0xc0, 0x08, 0xe2, 0x91, 0x08, 0xd1, 0x59, 0x49, 0x40, 0x1f, 0x05, 0x7a, 0x28, 0xe0, 0x46, 0x81, 0x7e, 0xfa, 0xcc, 0x67, 0x90, 0xf0, 0x5d, 0xef, 0xfd, 0x13, 0x78, 0xf5, 0xaf, 0x2d, 0xd8, 0xa9, 0x21 }

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

-- KEY EXCHANGE
local eph1 = uECC:keygen()
local shared1 = uECC:sharedsecret(serverpk, eph1.sk)
local key1 = string.sub(digest.new("sha256"):final(shared1), 1, 16)

local bodyt = {
    client_id= "1234567890client",
    device_id= "1234567890device",
    client_pass= "clientpass",
    operation= "unlock",
    load = b64.encode(eph1.pk)
}

local req = request.new_from_uri(host .. "/authorize-operation")
req.headers:upsert(":method", "POST")
req.headers:append("content-type", "application/json")
print("// Authorize Operation request (/authorize-operation):") print(cjson.encode(bodyt)) print()
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

print("// Server answer:") print(body) print()
local replyex = cjson.decode(body)
local ticket = replyex.ticket
local bload = b64.decode(replyex.load)
local eph2pk = string.sub(bload, 1, 48)
local ephhmac = string.sub(bload, 49, 80)
assert(hmac.new(key1, "sha256"):final(eph2pk) == ephhmac, "exchange hmac does not correspond")
local shared2 = uECC:sharedsecret(eph2pk, devicesk)
local key2 = string.sub(digest.new("sha256"):final(shared2), 1, 16)
local aOPlen = (#bload - 80) - ((#bload - 80) % 16)
local reply1dev = cjson.decode(auth_decrypt(string.sub(bload,81,80+aOPlen), key2))
assert(reply1dev.OP == "unlock")

-- AFTER KEY EXCHANGE

local bload = (b64.encode(auth_encrypt(cjson.encode{N2 = reply1dev.N2, RES=true}, key2)))
local bodyt = {
  ticket = ticket,
  load = bload
}

local req = request.new_from_uri(host .. "/result")
req.headers:upsert(":method", "POST")
req.headers:append("content-type", "application/json")
print("// Send Result Request (/result):") print(cjson.encode(bodyt)) print()
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

print("// Server answer:") print(body) print()
local reply2 = cjson.decode(body)

assert(reply2.success == true)
