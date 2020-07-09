FROM alpine

WORKDIR /opt/server

# COPY server.lua .

RUN apk add lua5.3 lua-ossl lua5.3-http lua5.3-cjson lua5.3-b64 lua5.3-ossl

EXPOSE 8888

CMD [ "./server.lua" ]

