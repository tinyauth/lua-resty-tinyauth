local cjson = require "cjson"
local http = require "resty.http"

local ngx = ngx

local _M = {
    _VERSION = '0.4',
}
local mt = { __index = _M }


local login_html = [[
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <link rel="shortcut icon" href="/favicon.ico">
    <title>LOGIN</title>
  </head>
  <body style="background-color: rgb(0, 188, 212);">
    <div id="root"></div>
    <script type="text/javascript" src="/login/static/main._JS_HASH_.js"></script>
  </body>
</html>
]]


local function get_header_list()
    local headers = {}
    local i = 1
    for k, v in pairs(ngx.req.get_headers(raw)) do
        headers[i] = {k, v}
        i = i + 1
    end
    return headers
end


local function get_resource_urn()
    return "urn:::" .. ngx.var.uri
end


local function req_matches_method(methods)
  for idx, method in pairs(methods) do
    if method == ngx.req.get_method() then
      return true
    end
  end
  return false
end


local function req_matches_uri(uri)
  return ngx.re.match(ngx.var.uri, uri, "jo")
end


function _M.new(endpoint, user, pass, kwargs)
    kwargs = kwargs or {}

    local ssl_verify = true
    if kwargs.ssl_verify == false then
      ssl_verify = false
    end

    local service = "resty"
    if kwargs.service then
      service = kwargs.service
    end

    return setmetatable({
        endpoint = endpoint,
        user = user,
        pass = pass,
        ssl_verify = ssl_verify,
        service = service,
        client = http.new(),
    }, mt)
end

function _M.handle_login(self, js_hash)
  if ngx.req.get_method() == "GET" then
    ngx.header.content_type = 'text/html';
    ngx.say(string.gsub(login_html, '_JS_HASH_', js_hash))
    return
  end

  if ngx.req.get_method() ~= "POST" then
    ngx.exit(ngx.HTTP_NOT_FOUND)
    return
  end

  ngx.header.content_type = 'application/json';

  ngx.req.read_body()
  local login_attempt_raw = ngx.var.request_body
  if not login_attempt_raw then
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.say('{"message": "Request is invalid"}')
    ngx.exit(ngx.HTTP_OK)
    return
  end

  -- ngx.log(ngx.ERR, login_attempt_raw)

  local login_attempt = cjson.decode(login_attempt_raw)
  if not login_attempt["username"] or not login_attempt["password"] then
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.say('{"message": "You must specify a username and password"}')
    ngx.exit(ngx.HTTP_OK)
    return
  end

  local resp = _M.get_token_for_login(self, login_attempt["username"], login_attempt["password"])

  -- ngx.log(ngx.ERR, cjson.encode(resp))

  ngx.header["Set-Cookie"] = {
    "tinysess=" .. resp["token"] .. "; Expires=" .. ngx.cookie_time(ngx.time() + 60*60*8) .. "; Secure; HttpOnly; SameSite=strict",
    -- "tinycsrf=" .. resp["csrf"] .. "; Path=/; Expires=" .. ngx.cookie_time(ngx.time() + 60*60*8) .. "; Secure"
  }

  ngx.say("{}")
  ngx.exit(ngx.HTTP_OK)
end


function _M.get_token_for_login(self, username, password)
  local client = self.client

  local body = cjson.encode({
    username = username,
    password = password,
    ["csrf-strategy"] = "cookie",
  })

  ngx.log(ngx.DEBUG, "get_token_for_login request: " .. body)

  local res, err = client:request_uri(self.endpoint .. "services/" .. self.service .. "/get-token-for-login", {
    method = "POST",
    body = body,
    headers = {
      ["Content-Type"] = "application/json",
      Authorization = 'Basic '..ngx.encode_base64(self.user .. ':' .. self.pass)
    },
    ssl_verify = self.ssl_verify
  })

  if not res then
      ngx.log(ngx.ERR, err)
      return
  end

  ngx.log(ngx.DEBUG, "get_token_for_login response: " .. res.body)

  return cjson.decode(res.body)
end


function _M.authorize_token_for_url(self, uri_map, default_action)
  for idx, route in pairs(uri_map) do
    if req_matches_uri(route[1]) and req_matches_method(route[2]) then
      return _M.authorize_token_for_action(self, route[3])
    end
  end

  if default_action then
    return _M.authorize_token_for_action(self, default_action)
  end

  return {
    Authorized = false,
    ErrorCode = "Access to this resource is not permitted"
  }
end


function _M.authorize_token_for_action(self, action)
    local client = self.client

    local body = cjson.encode({
        action = action,
        resource = get_resource_urn(),
        headers = get_header_list(),
        context = {
            SourceIP = ngx.var.remote_addr
        }
    })

    -- ngx.log(ngx.ERR, "REQUEST: " .. body)

    local res, err = client:request_uri(self.endpoint .. "authorize", {
        method = "POST",
        body = body,
        headers = {
            ["Content-Type"] = "application/json",
            Authorization = 'Basic '..ngx.encode_base64(self.user .. ':' .. self.pass)
        },
        ssl_verify = self.ssl_verify
    })

    if not res then
      ngx.log(ngx.ERR, err)

      return {
        Authorized = false,
        ErrorCode = "Error whilst authenticating token",
      }
    end

    -- ngx.log(ngx.ERR, "RESPONSE: " .. res.body)

    local auth = cjson.decode(res.body)
    return auth
end


function _M.authorize_login_for_url(self, uri_map, default_action)
  for idx, route in pairs(uri_map) do
    if req_matches_uri(route[1]) and req_matches_method(route[2]) then
      return _M.authorize_login_for_action(self, route[3])
    end
  end

  if default_action then
    return _M.authorize_login_for_action(self, default_action)
  end

  return {
    Authorized = false,
    ErrorCode = "Access to this resource is not permitted"
  }
end


function _M.authorize_login_for_action(self, action)
    local client = self.client

    local body = cjson.encode({
        action = action,
        resource = get_resource_urn(),
        headers = get_header_list(),
        context = {
            SourceIP = ngx.var.remote_addr
        }
    })

    ngx.log(ngx.DEBUG, "REQUEST: " .. body)

    local res, err = client:request_uri(self.endpoint .. "authorize-login", {
        method = "POST",
        body = body,
        headers = {
            ["Content-Type"] = "application/json",
            Authorization = 'Basic '..ngx.encode_base64(self.user .. ':' .. self.pass)
        },
        ssl_verify = self.ssl_verify
    })

    if not res then
      ngx.log(ngx.ERR, err)

      return {
        Authorized = false,
        ErrorCode = "Error whilst authenticating login",
      }
    end

    ngx.log(ngx.DEBUG, "RESPONSE: " .. res.body)

    local auth = cjson.decode(res.body)
    return auth
end


return _M
