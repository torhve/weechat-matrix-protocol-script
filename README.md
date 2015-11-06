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

Note that the weechat in jessie (1.0.1) is quite old compared to upstream and is
missing many bugfixes. This plugin may not work with older versions. There are
unofficial packages [here](https://weechat.org/download/debian/).

## How to get WeeChat & Lua deps up and running on OSX:

### using brew:
```bash
brew install luarocks
brew install weechat --with-lua
```

### using MacPorts:
```bash
sudo port install weechat +lua
sudo port install luarocks
sudo luarocks install lua-cjson
export LUA_PATH="/opt/local/share/luarocks/share/lua/5.2/?.lua;/opt/local/share/luarocks/share/lua/5.2/?/init.lua;$LUA_PATH"
export LUA_CPATH="/opt/local/share/luarocks/lib/lua/5.2/?.so;$LUA_CPATH"
```

# Encryption

Encryption support is work in progress, but the brave souls that can handle some nonstraighfoward installation and can live with potentially crashing WeeChats and other problems can try to follow the instructions below to get end-to-end encryption working.

`matrix.lua` uses [olm](https://matrix.org/git/olm/) C library to do encryption. That library needs to be downloaded, compiled and installed in a place Lua can find it.
The Lua binding is written using FFI, which means you *either* have to compile WeeChat against LuaJIT (which is not the standard!) or you will have to install FFI for regular Lua.
[LuaFFI](https://github.com/jmckaskill/luaffi) can be found [here](https://github.com/jmckaskill/luaffi). It needs to be donwloaded, compiled and installed in a place Lua can find it.
If you decide to recompile WeeChat instead, the `cmake` incantation you need is `cmake ..  -DCMAKE_BUILD_TYPE=Debug -DLUA_INCLUDE_DIRS=/usr/include/luajit-2.0 -DLUA_LDFLAGS=/usr/lib/x86_64-linux-gnu/libluajit-5.1.so`

When this is in place, you need to place `olm.lua` binding a place where WeeChat can find it, the easiest approach is probably current working directory.

Whether encryption loads OK or not it should print a message in weechat core buffer when you load matrix script to tell you if it could be loaded OK or not.
If encryption is loaded, and your matrix homeserver supports encryption it will upload keys upon connection.

To enable encryption for otgoing messages in a room type */encrypt on* with a room as active current buffer and it will download the keys of the other users in the room and encrypt using those.

If you're having problems, you can try command `/matrix debug` or `/set plugins.var.lua.matrix.debug on` to get a lot of extra messages in your matrix buffer.

Encrypted messages will be printed in color lightgreen to tell you the user that is an encrypted message. This can be configured with option `/set plugins.var.lua.matrix.debug encrypted_message_color`

# License

MIT
