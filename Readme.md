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

1) Start the server: `./server.lua`

REVIEW STEPS

It is safe to regenerate the key, before using it.

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
