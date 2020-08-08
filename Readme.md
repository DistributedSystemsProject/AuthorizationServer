# Authorization Server

The authorization server is used to authenticate the user to send operations to the Locker Device, according to this protocol:
![Protocol Diagram](https://raw.githubusercontent.com/DistributedSystemsProject/AuthorizationServer/master/Protocol.png)

- Device and Client are supposed to be already paired via Bluetooth
- EKd,s (AES encryption 128-bit CBC, between Device and Server, including HMAC SHA 256-bit)
- EKc,s (HTTPS connection, authorized through idClient and clientPassword)
- Aop stands for Authorized Operation
- Res is the final response from the device

In the ECC branch there is the version of the server, using Elliptic-curve cryptography (ECC):
https://github.com/DistributedSystemsProject/AuthorizationServer/tree/ECC

# Requirements

Lua 5.3, with the following libraries:

- `lua-http`
- `lua-ossl`
- `lua-cjson`
- `lua-b64`

# Usage

1) Start the server: `lua server.lua` or with Docker (see below). If you want to use HTTPS, place on the same directory the certificate files (at the moment it was tested with fullchain.pem and privkey.pem, Let's Encrypt certificate files). If you don't want to use HTTPS, simply start the server in HTTP mode, with `lua server.lua dev`.

2) Use the app https://github.com/DistributedSystemsProject/MobileApp or if you want to operate manually send an HTTPS POST to `SERVER_ADDRESS/authorize-operation` on port 8888, header `content-type: application/json`, and a json body as in the file `example_first_request.json`.

`client_id`, `client_pass`, and `device_id` must be as in the example, `operation` can be `lock` or `unlock`. The load should be encrypted and authenticated with SHA256 HMAC, key: `{0x0c, 0xc0, 0x52, 0xf6, 0x7b, 0xbd, 0x05, 0x0e, 0x75, 0xac, 0x0d, 0x43, 0xf1, 0x0a, 0x8f, 0x35}`

3) After you receive the ticket from the server plus the response from the device, send another HTTPS POST, this time to `/result` like in the file `example_second_request.json`

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
