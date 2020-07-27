# Authorization Server

The authorization server is used to authenticate the user to send operations to the Locker Device, according to this protocol:
![Protocol Diagram](https://raw.githubusercontent.com/DistributedSystemsProject/AuthorizationServer/master/protocol.png)


# Requeriments

Lua 5.3, with the following libraries:

- `lua-http`
- `lua-ossl`
- `lua-cjson`
- `lua-b64`

# Usage

Start the server: `./server.lua`

Send an http POST to `/authorize-operation` on port 8888, header `content-type: application/json`, and a json body as in the file `example_request.json`.

`client_id`, `client_pass`, and `device_id` must be as in the example, `operation` can be `lock` or `unlock`.

The load should be encrypted and authenticated with SHA256 HMAC, key: `{0x0c, 0xc0, 0x52, 0xf6, 0x7b, 0xbd, 0x05, 0x0e, 0x75, 0xac, 0x0d, 0x43, 0xf1, 0x0a, 0x8f, 0x35}`

# Run on Docker

Cd into the directory with the repository then run:

```
docker run -d --publish 8888:8888 --mount readonly,type=bind,source="$PWD",target=/opt/server xoich/authserver
```
