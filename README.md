# WeeChat Matrix.org Client


This script is considered alpha quality as only the bare minimal of functionality is in place and it is not very well tested.

## How to get weechat & lua deps up and running on OSX:

```bash
sudo port install weechat +lua
sudo port install luarocks
sudo luarocks install lua-cjson
export LUA_PATH="/opt/local/share/luarocks/share/lua/5.2/?.lua;/opt/local/share/luarocks/share/lua/5.2/?/init.lua;$LUA_PATH"
export LUA_CPATH="/opt/local/share/luarocks/lib/lua/5.2/?.so;$LUA_CPATH"
```

## How to load and use the plugin

```bash
git clone https://github.com/torhve/weechat-matrix-protocol-script.git
cd weechat-matrix-protocol-script
weechat
```

```
/lua load matrix.lua
/set plugins.var.lua.matrix.user username
/set plugins.var.lua.matrix.password secret
/matrix connect
```

# License

MIT
