#!/bin/bash
# Just a simple script to push an updated copy of the matrix.lua script
# to the .weechat/lua folder after each update.
file="~/.weechat/lua/autoload/matrix.lua"
echo "Updating, please wait a moment..."
git pull
cp matrix.lua ~/.weechat/lua
ln -s ~/.weechat/lua/matrix.lua ~/.weechat/lua/autoload/matrix.lua
if [ -f "$file" ]
  then
  ln -s ~/.weechat/lua/matrix.lua ~/.weechat/lua/autoload/matrix.lua
  else
  echo "$file already exists, skipping symbolic link creation."
fi
