#!/bin/bash
# Just a simple script to push an updated copy of the matrix.lua script
# to the .weechat/lua folder after each update.
file="$HOME/.weechat/lua/matrix.lua"
link="$HOME/.weechat/lua/autoload/matrix.lua"

echo "Updating, please wait a moment..."
git pull

# copy in the updated matrix.lua
echo "Updating $file."
cp matrix.lua $HOME/.weechat/lua

# create the symlink if necessary
if [ -h $link ]
then
	echo "$link already exists, skipping symbolic link creation."
else
	echo "Creating symbolic link in autoload directory."
	ln -s $file $link
fi
echo "Done."
