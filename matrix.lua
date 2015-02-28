-- WeeChat Matrix.org Client

--[[
 Author: xt <xt@xt.gg>
 Thanks to Ryan Huber of wee_slack.py for some ideas and inspiration.

 This script is considered alpha quality as only the bare minimal of
 functionality is in place and it is not very well tested.
]]


local json = require 'cjson'
local os = require 'os'
local w = weechat

local SCRIPT_NAME = "matrix"
local SCRIPT_AUTHOR = "xt <xt@xt.gg>"
local SCRIPT_VERSION = "1"
local SCRIPT_LICENSE = "MIT"
local SCRIPT_DESC = "Matrix.org chat plugin"
local SCRIPT_COMMAND = SCRIPT_NAME

local CONF = {}
local SERVER
local STDOUT = {}
local OUT = {}
local BUFFER
local Room
local MatrixServer

local default_color = w.color('default')


local function tprint (tbl, indent, out)
    if not indent then indent = 0 end
    for k, v in pairs(tbl) do
        local formatting = string.rep("  ", indent) .. k .. ": "
        if type(v) == "table" then
            w.print('', formatting)
            tprint(v, indent+1)
        elseif type(v) == 'boolean' then
            w.print('', formatting .. tostring(v))
        else
            w.print('', formatting .. v)
        end
    end
end
local function dbg(message)
    if type(message) == 'table' then
        w.print("", 'Printing table: ' .. tostring(message))
        tprint(message)
    else
        message = ("DEBUG: %s"):format(tostring(message))
        w.print("", message)
    end
end

local function weechat_eval(text)
    local version = w.info_get('version_number', '') or 0
    if tonumber(version) >= 0x00040200 then
        return w.string_eval_expression(text,{},{},{})
    end
    return text
end

local urllib = {}
urllib.quote = function(str)
    if not str then return '' end
    if type(str) == 'number' then return str end
    return str:gsub(
    '([^%w ])',
    function (c)
        return string.format ("%%%02X", string.byte(c))
    end
    ):gsub(' ', '+')
end
urllib.urlencode = function(tbl)
    local out = {}
    for k, v in pairs(tbl) do
        table.insert(out, urllib.quote(k)..'='..urllib.quote(v))
    end
    return table.concat(out, '&')
end

local function split(str, delim)
    if not delim then delim = ' ' end
    if str == "" or str == nil then
        return { }
    end
    str = str .. delim
    local _accum_0 = { }
    local _len_0 = 1
    for m in str:gmatch("(.-)" .. delim) do
        _accum_0[_len_0] = m
        _len_0 = _len_0 + 1
    end
    return _accum_0
end

local function split_args(args)
    local splits = split(args)
    local command = splits[1]
    local remainder = {}
    for i=2,#splits do
        table.insert(remainder, splits[i])
    end
    return command, table.concat(remainder, ' ')
end

function unload()
    w.unhook(SERVER.polltimer)
    return w.WEECHAT_RC_OK
end

local function wconf(optionname)
    return w.config_string(w.config_get(optionname))
end

local function wcolor(optionname)
    return w.color(wconf(optionname))
end

local function format_nick(nick, is_self)
    -- Turns a nick name into a weechat-styled nickname. This means giving
    -- it colors, and proper prefix and suffix
    local color
    if is_self then
        color = w.color('chat_nick_self')
    else
        color = w.info_get('irc_nick_color', nick)
    end
    local prefix = wconf('weechat.look.nick_prefix')
    local prefix_c = wcolor('weechat.color.chat_nick_prefix')
    local suffix = wconf('weechat.look.nick_suffix')
    local suffix_c = wcolor('weechat.color.chat_nick_suffix')
    local nick_f = prefix_c .. prefix .. color .. nick .. suffix_c .. suffix
    return nick_f
end

function command_help(current_buffer, args)
    --help_cmds = { k[8:]: v.__doc__ for k, v in globals().items() if k.startswith("command_") }

    if args then
         local help_cmds = {args= help_cmds[args]}
         if not help_cmds then
             w.print("", "Command not found: " .. args)
             return
         end
    end

    for cmd, helptext in pairs(help_cmds) do
        w.print('', w.color("bold") .. cmd)
        w.print('', (helptext or 'No help text').strip())
        w.print('', '')
    end
end

function command_connect(current_buffer, args)
    if not SERVER.connected then
        SERVER:connect()
    end
    return w.WEECHAT_RC_OK
end

function matrix_command_cb(data, current_buffer, args)
    local function_name, arg = args:match('^(.-) (.*)$')
    if function_name == 'connect' then
        return command_connect(current_buffer, arg)
    end
    --local command = cmds[function_name](current_buffer, args)
    --if not command then
    --    w.print("", "Command not found: " .. function_name)
    --end

    return w.WEECHAT_RC_OK
end

local function http(url, post, cb, timeout)
    if not timeout then
        timeout = 30*1000
    end

    local homeserver_url = w.config_get_plugin('homeserver_url')
    homeserver_url = homeserver_url .. "_matrix/client/api/v1"
    url = homeserver_url .. url
    w.hook_process_hashtable('url:' .. url, post, timeout, cb, '')
end

function poll_cb(data, command, rc, stdout, stderr)
    if stderr ~= '' then
        w.print('', ('%s: %s'):format(SCRIPT_NAME, stderr))
        return w.WEECHAT_RC_OK
    end

    if stdout ~= '' then
        if not STDOUT[command] then
            STDOUT[command] = {}
        end
        table.insert(STDOUT[command], stdout)
    end

    if tonumber(rc) >= 0 then
        stdout = table.concat(STDOUT[command])
        STDOUT[command] = nil
        local js = json.decode(stdout)
        if false then --- pcall
            w.print('', ('%s Error: %s during json load: %s'):format(SCRIPT_NAME, e, stdout))
            js = {}
        end
        if js['errcode'] then
            w.print('', ('%s: %s'):format(SCRIPT_NAME, js['errcode']))
        else
            SERVER.end_token = js['end']
            for _, chunk in pairs(js.chunk) do
                 if chunk.room_id then
                    local room = SERVER.rooms[chunk['room_id']]
                    if room then
                        room:parseChunk(chunk)
                    end
                end
            end
        end
    end
    if tonumber(rc) == -2 or tonumber(rc) >= 0 then
        if STDOUT[command] then
            STDOUT[command] = nil
        end
        SERVER.polling = false
        SERVER:poll()
    end
    return w.WEECHAT_RC_OK
end


function http_cb(data, command, rc, stdout, stderr)

    if stderr ~= '' then
        w.print('', ('%s: %s'):format(SCRIPT_NAME, stderr))
        return w.WEECHAT_RC_OK
    end

    if stdout ~= '' then
        if not STDOUT[command] then
            STDOUT[command] = {}
        end
        table.insert(STDOUT[command], stdout)
    end

    if tonumber(rc) >= 0 then
        stdout = table.concat(STDOUT[command])
        STDOUT[command] = nil
        local js = json.decode(stdout)
        if false then --- pcall
            w.print('', ('%s Error: %s during json load: %s'):format(SCRIPT_NAME, e, stdout))
            js = {}
        end
        if js['errcode'] then
            w.print('', ('%s: %s'):format(SCRIPT_NAME, js['errcode']))
        end
        -- Get correct handler
        if command:find('login') then
            for k, v in pairs(js) do
                SERVER[k] = v
            end
            SERVER.connected = true
            SERVER:initial_sync()
        elseif command:find'initialSync' then
            for _, room in pairs(js['rooms']) do
                local myroom = SERVER:addRoom(room)
                for _, chunk in pairs(room['messages']['chunk']) do
                    myroom:parseChunk(chunk, true)
                end
            end
            SERVER:poll()
        elseif command:find'leave' then
            dbg(js)
        elseif command:find'/state/' then
            -- TODO errorcode: M_FORBIDDEN
            dbg(js)
        elseif command:find'/send/' then
            -- XXX Errorhandling 
        else
            w.print('', 'Uknown command in http cb')
            dbg(command)
            dbg(js)
        end
    end

    return w.WEECHAT_RC_OK
end

MatrixServer = {}
MatrixServer.__index = MatrixServer

MatrixServer.create = function()
     local server = {}
     setmetatable(server, MatrixServer)
     server.nick = nil
     server.connecting = false
     server.polling = false
     server.connected = false
     server.rooms = {}
     server.end_token = 'END'
     -- Timer used in cased of errors to restart the polling cycle
     -- During normal operation the polling should re-invoke itself
     server.polltimer = w.hook_timer(5*1000, 0, 0, "poll", "")
     return server
end


function MatrixServer:_getPost(post)
    local extra = {
        accept_encoding= 'application/json',
        transfer= 'application/json',
        postfields= json.encode(post)
    }
    return extra
end

function MatrixServer:findRoom(buffer_ptr)
    for id, room in pairs(self.rooms) do
        if room.channel_buffer == buffer_ptr then
            return room
        end
    end
end

function MatrixServer:connect()
    if not self.connecting then
        local user = weechat_eval(w.config_get_plugin('user'))
        local password = weechat_eval(w.config_get_plugin('password'))
        if user == '' or password == '' then
            w.print('', 'Please set your username and password using the settings system and then type /matrix connect')
            return
        end

        self.connecting = true
        w.print('', 'Connecting to homeserver.')
        local post = {
            ["type"]="m.login.password",
            ["user"]=user,
            ["password"]=password
        }
        http('/login', self:_getPost(post), 'http_cb')
    end
end

function MatrixServer:initial_sync()
    BUFFER = w.buffer_new("matrix", "", "", "closed_matrix_buffer_cb", "")
    w.buffer_set(BUFFER, "short_name", "matrix")
    w.buffer_set(BUFFER, "localvar_set_type", "server")
    w.buffer_set(BUFFER, "localvar_set_server", "matrix")
    --w.buffer_set(BUFFER, "display", "auto")
    local data = urllib.urlencode({
        access_token= self.access_token,
        limit= w.config_get_plugin('backlog_lines'),
    })
    http('/initialSync?'..data, {}, 'http_cb')
end

function MatrixServer:join(room)
    if not self.connected then
        --XXX'''
        return
    end

    room = urllib.quote(room)
    http('/join/' .. room,
        {postfields= "access_token="..self.access_token}, 'http_cb')
end

function MatrixServer:part(room)
    if not self.connected then
        --XXX'''
        return
    end

    room = urllib.quote(room.identifier)
    local data = urllib.urlencode({
        access_token= self.access_token,
    })
    -- TODO: close buffer, delete data, etc
    http(('/rooms/%s/leave?%s'):format(room,data), {postfields= "{}"}, 'http_cb')
end

function MatrixServer:poll()
    if self.connected == false or self.polling then
        return
    end
    self.polling = true
    local data = urllib.urlencode({
        access_token= self.access_token,
        timeout= 1000*30,
        from= self.end_token
    })
    http('/events?'..data, {}, 'poll_cb')
end

function MatrixServer:addRoom(room)
    local myroom = Room.create(room)
    myroom:create_buffer()
    self.rooms[room['room_id']] = myroom
    return myroom
end

function MatrixServer:msg(room_id, body, msgtype)
    if not msgtype then
        msgtype = 'm.text'
    end
    local data = {
        accept_encoding= 'application/json',
        transfer= 'application/json',
        postfields= json.encode({
            msgtype= msgtype,
            body= body,
    })}

    http(('/rooms/%s/send/m.room.message?access_token=%s')
        :format(urllib.quote(room_id), urllib.quote(self.access_token)), data, 'http_cb')
end

function MatrixServer:emote(room_id, body)
    self:msg(room_id, body, 'm.emote')
end

function MatrixServer:state(room_id, key, data)
    http(('/rooms/%s/state/%s?access_token=%s')
        :format(urllib.quote(room_id),
          urllib.quote(key),
          urllib.quote(self.access_token)),
        {customrequest = 'PUT',
         accept_encoding = 'application/json',
         transfer = 'application/json',
         postfields= json.encode(data),
        }, 'http_cb')
end


function buffer_input_cb(b, buffer, data)
    for r_id, room in pairs(SERVER.rooms) do
        if buffer == room.channel_buffer then
            SERVER:msg(r_id, data)
        end
    end
    return w.WEECHAT_RC_OK
end

Room = {}
Room.__index = Room
Room.create = function(obj)
    local room = {}
    setmetatable(room, Room)
    room.channel_buffer = nil
    room.identifier = obj['room_id']
    room.server = 'matrix'
    for _, state in pairs(obj['state']) do
        if state['type'] == 'm.room.aliases' then
            local name = state['content']['aliases'][1]
            room.name, room.server = name:match('(.+):(.+)')
        end
    end
    if not room.name then
        room.name = room.identifier
    end
    room.visibility = obj.visibility
    if not obj['visibility'] then
        room.visibility = 'public'
        dbg(obj)
    end
    -- Cache lines for dedup?
    room.lines = {}
    -- Cache users for presence/nicklist
    room.users = {}
    return room
end

function Room:topic(topic)
    SERVER:state(self.identifier, 'm.room.topic', {topic=topic})
end

function Room:msg(msg)
    SERVER:msg(self.identifier, msg)
end

function Room:emote(msg)
    SERVER:emote(self.identifier, msg)
end

function Room:create_buffer()
    local channel_buffer = w.buffer_search("", ("%s.%s"):format(self.server, self.name))
    if channel_buffer ~= '' then
        self.channel_buffer = channel_buffer
    else
        self.channel_buffer = w.buffer_new(("%s.%s")
            :format(self.server, self.name), "buffer_input_cb",
            self.name, "", "")
        -- Defined in weechat's irc-nick.h
        self.nicklist_group = w.nicklist_add_group(self.channel_buffer,
                '', "999|...", "weechat.color.nicklist_group", 1)
    end
    w.buffer_set(self.channel_buffer, "nicklist", "1")
    w.buffer_set(self.channel_buffer, "nicklist_display_groups", "0")
    --TODO
    --weechat.buffer_set(self.channel_buffer, "highlight_words", self.nick)
    -- TODO maybe use servername of homeserver?
    w.buffer_set(self.channel_buffer, "localvar_set_server", self.server)
    w.buffer_set(self.channel_buffer, "short_name", self.name)
    w.buffer_set(self.channel_buffer, "name", self.name)
    -- Doesn't work
    --w.buffer_set(self.channel_buffer, "plugin", "matrix")
    w.buffer_set(self.channel_buffer, "full_name",
        self.server.."."..self.name)
    -- TODO, needs better logic for detection of "private chat"
    if self.visibility == "private" then
        w.buffer_set(self.channel_buffer, "localvar_set_type", 'private')
    elseif self.visibility == "public" then
        w.buffer_set(self.channel_buffer, "localvar_set_type", 'channel')
    else
        dbg(self.visbility)
    end
end

function Room:addNick(obj)
    local nick = obj.user_id:match('@(.+):(.+)')
    self.users[obj['user_id']] = nick
    w.nicklist_add_nick(self.channel_buffer, self.nicklist_group, nick,
            w.info_get('irc_nick_color_name', nick), '', '', 1)
    return nick
end

function Room:parseChunk(chunk, backlog)
    -- Parses a chunk of json meant for a room 
    if not backlog then
        backlog = false
    end

    local is_self = false
    -- Check if own message
    if chunk.user_id == SERVER.user_id then
        is_self = true
    end

    if chunk['type'] == 'm.room.message' then
        local tags = "notify_message"

        if backlog then
            tags = tags .. ",notify_none,no_higlight,no_log,logger_backlog_end"
        end

        --local time_int = os.time()-chunk['age']/1000
        local time_int = chunk['origin_server_ts']/1000
        local color = default_color
        local nick
        local nick_c
        local body
        if self.users[chunk['user_id']] then
            nick = self.users[chunk['user_id']]
        else
            nick = self:addNick(chunk)
        end
        if is_self then
            w.buffer_set(self.channel_buffer, "localvar_set_nick",
                    self.users[SERVER.user_id])
            tags = tags .. ",no_highlight"
            nick_c = w.color('chat_nick_self')
        else
            nick_c = w.info_get('irc_nick_color', nick)
        end
        local content = chunk['content']
        if not content['msgtype'] then
            -- We don't support redactions 
            return
        end
        if content['msgtype'] == 'm.text' then
            body = content['body']
        elseif content['msgtype'] == 'm.image' then
            local url = content['url']:gsub('mxc://',
                w.config_get_plugin('homeserver_url')
                .. '_matrix/media/v1/download/')
            body = content['body'] .. ' ' .. url
        elseif content['msgtype'] == 'm.notice' then
            color = wcolor('irc.color.notice')
            body = content['body']

        elseif content['msgtype'] == 'm.emote' then
            tags = ",irc_action"
            local prefix = w.config_string(
                    w.config_get('weechat.look.prefix_action'))
            body = ("%s%s %s%s"):format(
                nick_c, nick, color, content['body']
            )
            nick = prefix
        else
            body = content['body']
            w.print('', 'Uknown content type')
            dbg(content)
        end
        local data = ("%s\t%s%s"):format(
                format_nick(nick, is_self),
                color,
                body)
        w.print_date_tags(self.channel_buffer, time_int, tags,
            data)
    elseif chunk['type'] == 'm.room.topic' then
        local title = chunk['content']['topic']
        w.buffer_set(self.channel_buffer, "title", title)
        local color = wcolor("irc.color.topic_new")
        local nick = self.users[chunk.user_id] or chunk.user_id
        local data = ('--\t%s%s has changed the topic to "%s%s%s"'):format(
                format_nick(nick, is_self),
                default_color,
                color,
                title,
                default_color
              )
        w.print_date_tags(self.channel_buffer, os.time(), "",
            data)
    elseif chunk['type'] == 'm.room.name' then
        local name = chunk['content']['name']
        w.buffer_set(self.channel_buffer, "short_name", name)
    elseif chunk['type'] == 'm.room.member' then
        -- TODO presence, leave, invite
        if chunk['content']['membership'] == 'join' then
            --## TODO addnick logic
            local nick = chunk['content']['displayname']
            self.users[chunk['user_id']] = nick
            w.nicklist_add_nick(self.channel_buffer, self.nicklist_group,
                nick, w.info_get('irc_nick_color_name', nick), '', '', 1)

            --local time_int = os.time()-chunk['age']/1000
            local time_int = chunk['origin_server_ts']/1000
            local data = ('%s%s\t%s%s%s joined the room.'):format(
                wcolor('weechat.color.chat_prefix_join'),
                wconf('weechat.look.prefix_join'),
                w.info_get('irc_nick_color', nick),
                nick,
                wcolor('irc.color.message_join')
            )
            w.print_date_tags(self.channel_buffer, time_int, "irc_join",
                data)
        elseif chunk['content']['membership'] == 'leave' then
            --## TODO delnick logic
            local nick = chunk['prev_content'].displayname
            if not nick then
                nick = chunk['user_id']
            if self.users[chunk['user_id']] then
                self.users[chunk['user_id']] = nil
            end
            --TODO delnick w.nicklist_add_nick(self.channel_buffer, self.nicklist_group,
            --    nick, w.info_get('irc_nick_color_name', nick), '', '', 1)
            --local time_int = os.time()-chunk['age']/1000
            local time_int = chunk['origin_server_ts']/1000
            local data = ('%s%s\t%s%s%s left the room.'):format(
                wcolor('weechat.color.chat_prefix_quit'),
                wconf('weechat.look.prefix_quit'),
                w.info_get('irc_nick_color', nick),
                nick,
                wcolor('irc.color.message_quit')
            )
            w.print_date_tags(self.channel_buffer, time_int, "irc_quit",
                data)
        end
    end
    elseif chunk['type'] == 'm.room.create' then
        -- TODO: parse create events --
    elseif chunk['type'] == 'm.room.power_levels' then
        -- TODO: parse power lvls events --
    elseif chunk['type'] == 'm.room.join_rules' then
        -- TODO: parse join_rules events --
    elseif chunk['type'] == 'm.typing' then
        -- TODO: Typing notices. --
    else
        dbg(chunk)
    end
end

function poll(a,b)
    SERVER:poll()
    return w.WEECHAT_RC_OK
end

function join_command_cb(data, current_buffer, args)
    if current_buffer == BUFFER then
        local _, args = split_args(args)
        SERVER:join(args)
        return w.WEECHAT_RC_OK_EAT
    else
        return w.WEECHAT_RC_OK
    end
end

function part_command_cb(data, current_buffer, args)
    local room = SERVER:findRoom(current_buffer)
    if room then
        SERVER:part(room)
        return w.WEECHAT_RC_OK_EAT
    else
        return w.WEECHAT_RC_OK
    end
end

function emote_command_cb(data, current_buffer, args)
    local room = SERVER:findRoom(current_buffer)
    if room then
        local _, args = split_args(args)
        room:emote(args)
        return w.WEECHAT_RC_OK_EAT
    else
        return w.WEECHAT_RC_OK
    end
end

function topic_command_cb(data, current_buffer, args)
   local  room = SERVER:findRoom(current_buffer)
    if room then
        local _, args = split_args(args)
        room:topic(args)
        return w.WEECHAT_RC_OK_EAT
    else
        return w.WEECHAT_RC_OK
    end
end


function closed_matrix_buffer_cb(data, buffer)
    BUFFER = nil
    return w.WEECHAT_RC_OK
end


if w.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE, SCRIPT_DESC, "unload", "UTF-8") then
    local settings = {
        homeserver_url= {'https://matrix.org/', 'Full URL including port to your homeserver or use default matrix.org'},
        user= {'', 'Your homeserver username'},
        password= {'', 'Your homeserver password'},
        backlog_lines= {'20', 'Number of lines to fetch from backlog upon connecting'},
    }
    -- set default settings
    local version = w.info_get('version_number', '') or 0
    for option, value in pairs(settings) do
        if w.config_is_set_plugin(option) == 1 then
            CONF[option] = w.config_get_plugin(option)
        else
            w.config_set_plugin(option, value[1])
            CONF[option] = value[1]
        end
        if tonumber(version) >= 0x00030500 then
            w.config_set_desc_plugin(option, ('%s (default: "%s")'):format(
                     value[2], value[1]))
        end
    end
    w.hook_command_run('/join', 'join_command_cb', '')
    w.hook_command_run('/part', 'part_command_cb', '')
    w.hook_command_run('/leave', 'part_command_cb', '')
    w.hook_command_run('/me', 'emote_command_cb', '')
    w.hook_command_run('/topic', 'topic_command_cb', '')
    -- Such elegance, much woe.
    --cmds = {k[8:]: v for k, v in globals().items() if k.startswith("command_")}
    local cmds = {'help', 'connect', 'join', 'part'}
    w.hook_command(SCRIPT_COMMAND, 'Plugin for matrix.org chat protocol',
        '[command] [command options]',
        'Commands:\n' ..table.concat(cmds, '\n') ..
        '\nUse /matrix help [command] to find out more\n',
        -- Completions
        table.concat(cmds, '|'),
        'matrix_command_cb', '')

    SERVER = MatrixServer.create()
    SERVER:connect()
end
