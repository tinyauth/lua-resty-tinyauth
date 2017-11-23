# lua-resty-tinyauth

Lua client for authorising actions with [tinyauth](https://github.com/tinyauth/tinyauth) on [OpenResty](http://openresty.org/)/[ngx_lua](https://github.com/openresty/lua-nginx-module).

## Status

Alpha.

## Features

 * User and group based ACLs for any service that can be proxied by nginx
 * Use URL maps to break down your API into multiple distinct actions to allow for fine grained permissions.

## Synopsis

```` lua
lua_package_path "/path/to/lua-resty-microauth/lib/?.lua;;";

server {
  location / {
    access_by_lua_block {
      local tinyauth = require('resty/tinyauth');
      local client = tinyauth.new("http://tinyauth:5000/api/v1/", "gatekeeper", "keymaster")

      client:authorize_token_for_url({
        {"/ip",         {"GET"},  "GetOriginIp"},
        {"/stream/.*",  {"GET"},  "StreamLines"},
      }, "ProxyRequest")
    }

    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header Host $http_host;
    proxy_redirect off;
    proxy_pass   http://app;
  }
}
````

## Connection

### new

`syntax: local client = tinyauth.new()`

Creates the tinyauth object.

### authorize_token_for_action

`syntax: client:authorize_token_for_action(action)`

All traffic that is subjected to this authorization will be treated as a single action type. This is useful if you either have access to an API or you do not.

### authorize_token_for_url

`syntax: client:authorize_token_for_url(uri_map)`

`syntax: client:authorize_token_for_url(uri_map, default)`

Traffic URI is looked up in a table to find out what action to use when authorizing with tinyauth.

If no matches are found and default is not set then the access attempt will be forbidden.

If no matches are found and a default is set then the access attempt will be authorized with the default action.

`uri_map` is an array of 'routes'. If a route matches then we know what action to associate it with when querying tinyauth. The routes might look like:

```
local routes = {
  {"/ip",       {"GET"},    "GetIp"},
  {"/gzip",     {"GET"},    "GetGzippedData"},
  {"/stream/.*", {"GET"},   "StreamLines"},
}
```

### authorize_login_for_action

`syntax: client:authorize_login_for_action(action)`

All traffic that is subjected to this authorization will be treated as a single action type. This is useful if you either have access to an API or you do not.

### authorize_login_for_url

`syntax: client:authorize_login_for_url(uri_map)`

`syntax: client:authorize_login_for_url(uri_map, default)`

Traffic URI is looked up in a table to find out what action to use when authorizing with tinyauth.

If no matches are found and default is not set then the access attempt will be forbidden.

If no matches are found and a default is set then the access attempt will be authorized with the default action.

`uri_map` is an array of 'routes'. If a route matches then we know what action to associate it with when querying tinyauth. The routes might look like:

```
local routes = {
  {"/ip",       {"GET"},    "GetIp"},
  {"/gzip",     {"GET"},    "GetGzippedData"},
  {"/stream/.*", {"GET"},   "StreamLines"},
}
```

With these routes when a user accesses `/stream/99` we can map that to `StreamLines` and ask tinyauth if we can authenticate that user to do the `StreamLines` action.


## Checking out the example

This repo contains an example of using tinyauth to secure a mission critical service: [httpbin](https://httpbin.org).

The docker compose config will deploy httpbin running on gunicorn with an openresty reverse proxy in front of it. `lua-resty-tinyauth` will be running in the proxy and provide authorization by talking to a simple tinyauth setup (postgres + tinyauth).

In a terminal:

```
$ docker-compose build
$ docker-compose up
```

This will run the demo in the foreground. In another terminal window

```
$ docker-compose run --rm tinyauth tinyauth db upgrade
Starting luarestytinyauth_postgres_1 ... done
Postgres is up - continuing...
INFO  [alembic.runtime.migration] Context impl PostgresqlImpl.
INFO  [alembic.runtime.migration] Will assume transactional DDL.
INFO  [alembic.runtime.migration] Running upgrade  -> 276ef161b610, empty message
INFO  [alembic.runtime.migration] Running upgrade 276ef161b610 -> 0d42398b4cdc, empty message
INFO  [alembic.runtime.migration] Running upgrade 0d42398b4cdc -> 0d0c426e7b01, empty message
INFO  [alembic.runtime.migration] Running upgrade 0d0c426e7b01 -> 7db3f3cca1a9, empty message
INFO  [alembic.runtime.migration] Running upgrade 7db3f3cca1a9 -> 9efdb5e1f6fb, empty message

$ docker-compose run --rm tinyauth tinyauth createdevuser
Starting luarestytinyauth_postgres_1 ... done
Postgres is up - continuing...
'root' account created

$ curl -u admin:admin http://localhost:80/ip
<html>
<head><title>403 Forbidden</title></head>
<body bgcolor="white">
<center><h1>403 Forbidden</h1></center>
<hr><center>openresty/1.11.2.5</center>
</body>
</html>

$ curl -u gatekeeper:keymaster http://localhost:80/ip
{
  "origin": "172.29.0.1"
}
```
