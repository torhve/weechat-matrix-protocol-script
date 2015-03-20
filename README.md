# Matrix Client script for WeeChat

This script is considered beta quality as not all functionality is in place and still has known bugs, and unknown bugs to be discovered and fixed.

## What is Matrix ?

Matrix is a new open source realtime federated chat protocol. You can read more about it on [their website](http://matrix.org/blog/faq/).

## What is WeeChat ?

[WeeChat](http://weechat.org) is a super powerful CLI chat client that's extensible in many languages to allow for new protocols like Matrix.

## What does it look like?


> WeeChat in a terminal

![weechat ncurses cli screenshot](https://hveem.no/ss/weechat-matrix-ss.png)

> WeeChat in a relay client [http://github.com/glowing-bear](Glowing Bear)

![weechat glowing bear](https://hveem.no/ss/weechat-matrix-gb.png)

## How to load and use the plugin

```bash
# Clone my repo
git clone https://github.com/torhve/weechat-matrix-protocol-script.git
# Copy the script into WeeChat's Lua autoload dir
cp weechat-matrix-protocol-script/matrix.lua ~/.weechat/lua/autoload
# Start WeeChat
weechat
```

```
/lua load matrix.lua
/set plugins.var.lua.matrix.user username
/set plugins.var.lua.matrix.password secret
/matrix connect
```

When it connects it will create a WeeChat buffer called matrix that will act
like the "server" buffer. Some errors messages and status messages will appear
in there on certain events like joing/invite/connection problems/etc. It will
also create buffers for any rooms that you have already join on this or any
other client.

Most IRC commands you would expect work exists, like /join /query /part /kick
/op /voice /notice, etc. There might be slight differences from normal usage.

There's a /create room name to create a new room with a given name.

If at any point you get any errors you can always try reloading the script to
refresh the state by issuing the command

```
/lua reload matrix
```

If you get invited to a room, the script will autojoin, which is configurable
behaviour.

## Configuration

Given Matrix display names can be quite long, we recommend limiting
the size of the prefix and username lists:

```
/set weechat.look.prefix_align_max 20
/set weechat.bar.nicklist.size 20
```

## To hot-update the plugin

```bash
git pull
```

```
/lua reload matrix
```

## How to get WeeChat & Lua deps up and running on Debian/Ubuntu:

```bash
sudo apt-get install weechat lua-cjson
```

## How to get WeeChat & Lua deps up and running on OSX:

```bash
sudo port install weechat +lua
sudo port install luarocks
sudo luarocks install lua-cjson
export LUA_PATH="/opt/local/share/luarocks/share/lua/5.2/?.lua;/opt/local/share/luarocks/share/lua/5.2/?/init.lua;$LUA_PATH"
export LUA_CPATH="/opt/local/share/luarocks/lib/lua/5.2/?.so;$LUA_CPATH"
```



# License

MIT
