# Matrix Client script for WeeChat

This script is considered beta quality as not all functionality is in place and still has known bugs, and unknown bugs to be discovered and fixed.

## What is Matrix ?

Matrix is a new open source realtime federated chat protocol. You can read more about it on [their website](http://matrix.org/blog/faq/).

## What is WeeChat ?

[WeeChat](http://weechat.org) is a super powerful CLI chat client that's extensible in many languages to allow for new protocols like Matrix.

## What does it look like?

> WeeChat in a terminal

![weechat ncurses cli screenshot](https://hveem.no/ss/weechat-matrix-ss.png)

> WeeChat in a relay client [Glowing Bear](http://github.com/glowing-bear)

![weechat glowing bear](https://hveem.no/ss/weechat-matrix-gb.png)

## How to load and use the plugin

```bash
# Clone this repo
git clone https://github.com/torhve/weechat-matrix-protocol-script.git
# Copy the script into WeeChat's Lua dir
cp weechat-matrix-protocol-script/matrix.lua ~/.weechat/lua
# Make a symlink into the autoload dir to load script automatically when WeeChat starts
ln -s ~/.weechat/lua/matrix.lua ~/.weechat/lua/autoload
# Start WeeChat
weechat
```
Helpful commands after starting WeeChat
```
# If you didn't put matrix.lua in autoload
/lua load matrix.lua
# Set the two required settings. Look in WeeChat docs for secdata if you don't want to store passord in the clear. ( http://dev.weechat.org/post/2013/08/04/Secured-data )
/set plugins.var.lua.matrix.user username
/set plugins.var.lua.matrix.password secret
/matrix connect

# to display all the possible WeeChat Matrix settings:
/set plugins.var.lua.matrix.*
# to get a description for each option
/help plugins.var.lua.matrix.local_echo

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

To get an item on your status bar to show users currently typing in the active room buffer add the `matrix_typing_notice` item to the status bar like this:
```
/set weechat.bar.status.items [buffer_count],[buffer_plugin],buffer_number+:+buffer_name+{buffer_nicklist_count}+buffer_filter,[hotlist],completion,scroll,matrix_typing_notice
```

It's helpful to use tab-complete after typing the option name to get the current setting, and then just add it to the end

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

### using brew (recommended; it's a simpler faster install and ships newer weechat than MacPorts):
```bash
brew install lua
luarocks install lua-cjson
brew install weechat --with-lua
```

### using MacPorts:
```bash
sudo port install weechat +lua
sudo port install luarocks
sudo luarocks install lua-cjson
# You may need to substitute the version number for whatever version of lua macports installed
export LUA_PATH="/opt/local/share/luarocks/share/lua/5.3/?.lua;/opt/local/share/luarocks/share/lua/5.3/?/init.lua;$LUA_PATH"
export LUA_CPATH="/opt/local/share/luarocks/lib/lua/5.3/?.so;$LUA_CPATH"
```

# Encryption

Encryption support is work in progress, but the brave souls that can handle some nonstraighfoward installation and can live with potentially crashing WeeChats and other problems can try to follow the instructions below to get end-to-end encryption working.

`matrix.lua` uses [olm](https://matrix.org/git/olm/) C library to do encryption. That library needs to be downloaded, compiled and installed in a place Lua can find it.
The Lua binding is written using FFI, which means you *either* have to compile WeeChat against LuaJIT (which is not the standard!) or you will have to install FFI for regular Lua.
[LuaFFI](https://github.com/jmckaskill/luaffi) can be found [here](https://github.com/jmckaskill/luaffi). It needs to be downloaded, compiled and installed in a place Lua can find it.
If you decide to recompile WeeChat instead, the `cmake` incantation you need is `cmake ..  -DCMAKE_BUILD_TYPE=Debug -DLUA_INCLUDE_DIRS=/usr/include/luajit-2.0 -DLUA_LDFLAGS=/usr/lib/x86_64-linux-gnu/libluajit-5.1.so`

When this is in place, you need to place `olm.lua` binding a place where WeeChat can find it, the easiest approach is probably current working directory.

Whether encryption loads OK or not it should print a message in weechat core buffer when you load matrix script to tell you if it could be loaded OK or not.
If encryption is loaded, and your matrix homeserver supports encryption it will upload keys upon connection.

To enable encryption for outgoing messages in a room type */encrypt on* with a room as active current buffer and it will download the keys of the other users in the room and encrypt using those.

If you're having problems, you can try command `/matrix debug` or `/set plugins.var.lua.matrix.debug on` to get a lot of extra messages in your matrix buffer.

Encrypted messages will be printed in color lightgreen to tell you the user that is an encrypted message. This can be configured with option `/set plugins.var.lua.matrix.debug encrypted_message_color`

# License

MIT
