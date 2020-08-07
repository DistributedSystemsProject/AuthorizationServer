# Authorization Server (ECC Version)

The authorization server is used to authenticate the user to send operations to the Locker Device, according to this protocol.

TODO: PROTOCOL IMAGE

In the MASTER branch there is the version of the server, without the ECC key exchange: https://github.com/DistributedSystemsProject/AuthorizationServer/

# Requirements

Lua 5.3, with the following libraries:

- `lua-http`
- `lua-ossl`
- `lua-cjson`
- `lua-b64`

# Usage

1) Start the server: `./server.lua` or with Docker (see below).

2) Use the app https://github.com/DistributedSystemsProject/MobileApp or if you want to operate manually send an HTTPS POST to `SERVER_ADDRESS/authorize-operation` on port 8888, header `content-type: application/json`, and a json body as in the file `example_first_request.json`.

`client_id`, `client_pass`, and `device_id` must be as in the example, `operation` can be `lock` or `unlock`. The load has to be originated from secp192r1() ECC curve, creating a shared key from server public key and authenticated with SHA256 HMAC.
The device has to use the following keys:

```
DEVICE PRIVATE KEY = { 0x02, 0xf2, 0x82, 0x21, 0xfb, 0x3a, 0x22, 0xa4, 0x48, 0x92, 0x8c, 0x44, 
                         0x99, 0x61, 0x20, 0xfb, 0xf7, 0xbe, 0x2d, 0xa3, 0xf6, 0xcd, 0xc2, 0xe2 };
SERVER PUBLICK KEY = { 0xdc, 0x27, 0xa5, 0x67, 0x1d, 0xcb, 0x00, 0x0d, 0xc4, 0x1b, 0x99, 0x96, 
                        0x84, 0x0b, 0xb3, 0xc0, 0x08, 0xe2, 0x91, 0x08, 0xd1, 0x59, 0x49, 0x40, 
                        0x1f, 0x05, 0x7a, 0x28, 0xe0, 0x46, 0x81, 0x7e, 0xfa, 0xcc, 0x67, 0x90, 
                        0xf0, 0x5d, 0xef, 0xfd, 0x13, 0x78, 0xf5, 0xaf, 0x2d, 0xd8, 0xa9, 0x21 };
```

3) After you receive the ticket from the server plus the response from the device, send another HTTP POST, this time to `/result` like in the file `example_second_request.json`

# Testing the server

It is possible to test the server with the file `test.lua`, it will go through the entire protocol and generate a log on the server.

```
lua test.lua host
```

Where `host` is the server hostname and optional port number.

# Run on Docker

Use the command "cd" into the directory with the repository, then run:

```
docker run -d redis:alpine
docker run -d --publish 8888:8888 --link YOUR_REDIS_DOCKER_CONTAINER_ID:redisserv --mount type=bind,source="$PWD",target=/opt/server xoich/authserver
```

# Logging

The server logs operations on the file `operations.log`
Logs are divided in blocks saved every five minutes. The blocks `sha256` cryptographic hash can be used to be stored on the blockchain (for example Ethereum).
