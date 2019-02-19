# Matrix Client script for WeeChat

Also known as WeeMatrix, this script is considered beta quality as not all functionality is in place and still has known bugs, and unknown bugs to be discovered and fixed.

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
cp weechat-matrix-protocol-script/matrix.lua ~/.weechat/lua/
# Make a symlink into the autoload dir to load the script automatically when WeeChat starts
ln -s ~/.weechat/lua/matrix.lua ~/.weechat/lua/autoload/
# Start WeeChat
weechat
```
Helpful commands after starting WeeChat
```
# If you didn't put matrix.lua in autoload
/script load matrix.lua
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
/script reload matrix
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
/script reload matrix
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

## How to get WeeChat & Lua deps up and running on Arch:
```bash
sudo pacman -S lua weechat
# You can grab lua-cjson from either the AUR:
pacaur -y lua-cjson
# Or through the luarocks package manager:
luarocks install lua-cjson
```

# Encryption

The current encryption implementation in weechat-matrix-protocol is incompatible with Matrix. It was written for an early proof-of-concept version of the protocol that used Olm, and does not work with the current Matrix protocol which utilises Megolm.

Help appreciated to get it working!

# License

MIT
