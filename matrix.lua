-- WeeChat Matrix.org Client

--[[
 Author: xt <xt@xt.gg>
 Thanks to Ryan Huber of wee_slack.py for some ideas and inspiration.

 This script is considered alpha quality as only the bare minimal of
 functionality is in place and it is not very well tested.

 It is known to be able to crash WeeChat in certain scenarioes so all
 usage of this script is at your own risk.

 If at any point there seems to be problem, make sure you update to
 the latest version of this script. You can also try reloading the
 script using /lua reload matrix to refresh all the state.

Power Levels
------------

A default Matrix room has power level between 0 to 100.
This script maps this as follows:

 ~ Room creator
 & Power level 100
 @ Power level 50
 + Power level > 0

]]


local json = require 'cjson' -- apt-get install lua-cjson
local w = weechat

local SCRIPT_NAME = "matrix"
local SCRIPT_AUTHOR = "xt <xt@xt.gg>"
local SCRIPT_VERSION = "1"
local SCRIPT_LICENSE = "MIT"
local SCRIPT_DESC = "Matrix.org chat plugin"
local SCRIPT_COMMAND = SCRIPT_NAME

local SERVER
local STDOUT = {}
local OUT = {}
local BUFFER
local Room
local MatrixServer

local default_color = w.color('default')

local function tprint(tbl, indent, out)
    if not indent then indent = 0 end
    for k, v in pairs(tbl) do
        local formatting = string.rep("  ", indent) .. k .. ": "
        if type(v) == "table" then
            w.print(BUFFER, formatting)
            tprint(v, indent+1)
        elseif type(v) == 'boolean' then
            w.print(BUFFER, formatting .. tostring(v))
        elseif type(v) == 'userdata' then
            w.print(BUFFER, formatting .. tostring(v))
        else
            w.print(BUFFER, formatting .. v)
        end
    end
end

local function mprint(message)
    -- Print message to matrix buffer
    if type(message) == 'table' then
        tprint(message)
    else
        message = tostring(message)
        w.print(BUFFER, message)
    end
end

local function dbg(message)
    mprint('________')
    if type(message) == 'table' then
        tprint(message)
    else
        message = ("DEBUG: %s"):format(tostring(message))
        mprint(BUFFER, message)
    end
end

local function perr(message)
    -- Print error message to the matrix "server" buffer using WeeChat styled
    -- error message
    mprint(
        SERVER.errprefix_c ..
        SERVER.errprefix ..
        '\t' ..
        default_color ..
        tostring(message)
        )
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

local function split_args(args)
    local function_name, arg = args:match('^(.-) (.*)$')
    return function_name, arg
end

local function byte_to_tag(s, byte, open_tag, close_tag)
    if s:match(byte) then
        local inside = false
        local open_tags = 0
        local htmlbody = s:gsub(byte, function(c)
            if inside then
                inside = false
                return close_tag
            end
            inside = true
            open_tags = open_tags + 1
            return open_tag
        end)
        local _, count = htmlbody:gsub(close_tag, '')
        -- Ensure we close tags
        if count < open_tags then
            htmlbody = htmlbody .. close_tag
        end
        return htmlbody
    end
    return s
end

local function irc_formatting_to_html(s)
    local ct = {'white','black','blue','green','red','markoon','purple',
        'orange','yellow','lightgreen','teal','cyan', 'lightblue',
        'fuchsia', 'gray', 'lightgray'}

    s = byte_to_tag(s, '\02', '<em>', '</em>')
    s = byte_to_tag(s, '\029', '<i>', '</i>')
    s = byte_to_tag(s, '\031', '<u>', '</u>')
    for i, c in pairs(ct) do
        s = byte_to_tag(s, '\003'..tostring(i-1),
            '<font color="'..c..'">', '</font>')
    end
    return s
end

local function strip_irc_formatting(s)
    if not s then return '' end
    return (s
        :gsub("\02", "")
        :gsub("\03%d%d?,%d%d?", "")
        :gsub("\03%d%d?", "")
        :gsub("\03", "")
        :gsub("\15", "")
        :gsub("\17", "")
        :gsub("\18", "")
        :gsub("\22", "")
        :gsub("\29", "")
        :gsub("\31", ""))
end

function unload()
    return w.WEECHAT_RC_OK
end

local function wconf(optionname)
    return w.config_string(w.config_get(optionname))
end

local function wcolor(optionname)
    return w.color(wconf(optionname))
end

function command_help(current_buffer, args)
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
    if args == 'connect' then
        return command_connect(current_buffer, arg)
    end
    --local command = cmds[function_name](current_buffer, args)
    --if not command then
    --    w.print("", "Command not found: " .. function_name)
    --end

    return w.WEECHAT_RC_OK
end

local function http(url, post, cb, timeout, extra)
    if not post then
        post = {}
    end
    if not cb then
        cb = 'http_cb'
    end
    if not timeout then
        timeout = 60*1000
    end
    if not extra then
        extra = ''
    end

    -- Add accept encoding by default if it's not already there
    if not post.accept_encoding then
        post.accept_encoding = 'application/json'
    end

    local homeserver_url = w.config_get_plugin('homeserver_url')
    homeserver_url = homeserver_url .. "_matrix/client/api/v1"
    url = homeserver_url .. url
    w.hook_process_hashtable('url:' .. url, post, timeout, cb, extra)
end

function poll_cb(data, command, rc, stdout, stderr)
    if stderr ~= '' then
        perr(('%s'):format(stderr))
        SERVER.polling = false
    end

    if stdout ~= '' then
        if not STDOUT[command] then
            STDOUT[command] = {}
        end
        table.insert(STDOUT[command], stdout)
    end

    if tonumber(rc) >= 0 and STDOUT[command]  then
        stdout = table.concat(STDOUT[command])
        STDOUT[command] = nil
        -- Protected call in case of JSON errors
        local success, js = pcall(json.decode, stdout)
        if not success then
            perr(('%s during json load: %s'):format(js, stdout))
            js = {}
            -- Return here so we don't go spinning into a crazy loop in
            -- case of errors. This will make the polltimer kick in in 30
            -- seconds or so
            return w.WEECHAT_RC_OK
        end
        if js['errcode'] then
            perr(js.errcode)
            perr(js['error'])
        else
            if js['end'] then
                SERVER.end_token = js['end']
            end
            for _, chunk in pairs(js.chunk or {}) do
                 if chunk.room_id then
                    local room = SERVER.rooms[chunk['room_id']]
                    if room then
                        room:parseChunk(chunk, false, 'messages')
                else
                    -- Chunk for non-existing room, maybe we just got
                        -- invited, so lets create a room
                        if (chunk.content and chunk.content.membership and
                              chunk.content.membership == 'invite') -- or maybe we just created a new room ourselves
                              or chunk['type'] == 'm.room.create'
                              then
                            local newroom = SERVER:addRoom(chunk)
                            newroom:parseChunk(chunk, false, 'messages')
                        elseif chunk.content and chunk.content.membership and
                              chunk.content.membership == 'leave' then
                              -- Ignore leave events
                        else

                            dbg{err='Event for unknown room',event=chunk}
                        end
                    end
                elseif chunk.type == 'm.presence' then
                    SERVER:UpdatePresence(chunk.content)
                else
                    dbg{err='unknown polling event',chunk=chunk}
                end
            end
        end
        SERVER.polling = false
        SERVER:poll()
    end
    -- Empty cache in case of errors
    if tonumber(rc) ~= 0 then
        if STDOUT[command] then
            STDOUT[command] = nil
            SERVER.polling = false
        end
    end

    return w.WEECHAT_RC_OK
end


function http_cb(data, command, rc, stdout, stderr)
    if stderr ~= '' then
        mprint(('error: %s'):format(stderr))
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
        -- Protected call in case of JSON errors
        local success, js = pcall(json.decode, stdout)
        if not success then
            mprint(('error\t%s during json load: %s'):format(js, stdout))
            js = {}
            return w.WEECHAT_RC_OK
        end
        if js['errcode'] then
            if command:find'login' then
                w.print('', ('matrix: Error code during login: %s'):format(
                    js['errcode']))
            else
                perr(js.errcode)
                perr(js['error'])
            end
            return w.WEECHAT_RC_OK
        end
        -- Get correct handler
        if command:find('login') then
            for k, v in pairs(js) do
                SERVER[k] = v
            end
            SERVER.connected = true
            SERVER:initial_sync()
        elseif command:find'/rooms/.*/initialSync' then
            local myroom = SERVER:addRoom(js)
            for _, chunk in pairs(js['presence']) do
                myroom:parseChunk(chunk, true, 'presence')
            end
            for _, chunk in pairs(js['messages']['chunk']) do
                myroom:parseChunk(chunk, true, 'messages')
            end
        elseif command:find'v1/initialSync' then
            -- Start with setting the global presence variable on the server
            -- so when the nicks get added to the room they can get added to
            -- the correct nicklist group according to if they have presence
            -- or not
            for _, chunk in pairs(js.presence) do
                SERVER:UpdatePresence(chunk.content)
            end
            for _, room in pairs(js['rooms']) do
                local myroom = SERVER:addRoom(room)

                -- Parse states before messages so we can add nicks and stuff
                -- before messages start appearing
                local states = room.state
                if states then
                    local chunks = room.state or {}
                    for _, chunk in pairs(chunks) do
                        myroom:parseChunk(chunk, true, 'states')
                    end
                end

                local messages = room.messages
                if messages then
                    local chunks = messages.chunk or {}
                    for _, chunk in pairs(chunks) do
                        myroom:parseChunk(chunk, true, 'messages')
                    end
                end
            end
            -- Now we have created rooms and can go over the rooms and update
            -- the presence for each nick
            for _, chunk in pairs(js.presence) do
                SERVER:UpdatePresence(chunk.content)
            end
            SERVER.end_token = js['end']
            -- We have our backlog, lets start listening for new events
            SERVER:poll()
            -- Timer used in cased of errors to restart the polling cycle
            -- During normal operation the polling should re-invoke itself
            SERVER.polltimer = w.hook_timer(30*1000, 0, 0, "polltimer_cb", "")
        elseif command:find'messages' then
            dbg('command msgs returned, '.. command)
        elseif command:find'/join/' then
            -- We came from a join command, fecth some messages
            local found = false
            for id, _ in pairs(SERVER.rooms) do
                if id == js.room_id then
                    found = true
                    -- this is a false positive for example when getting
                    -- invited. need to investigate more
                    --mprint('error\tJoined room, but already in it.')
                    break
                end
            end
            if not found then
                local data = urllib.urlencode({
                    access_token= SERVER.access_token,
                    --limit= w.config_get_plugin('backlog_lines'),
                    limit = 10,
                })
                http(('/rooms/%s/initialSync?%s'):format(
                    urllib.quote(js.room_id), data))
            end
        elseif command:find'leave' then
            -- We store room_id in data
            local room_id = data
            SERVER:delRoom(room_id)
        elseif command:find'upload' then
            -- We store room_id in data
            local room_id = data
            if js.content_uri then
                SERVER:msg(room_id, js.content_uri)
            end
        elseif command:find'/typing/' then
            -- either it errs or it is empty
        elseif command:find'/state/' then
            -- TODO errorcode: M_FORBIDDEN
            -- either it errs or it is empty
            --dbg({state= js})
        elseif command:find'/send/' then
            -- XXX Errorhandling
        elseif command:find'createRoom' then
            local room_id = js.room_id
            -- We get join events, so we don't have to do anything
        elseif command:find'/publicRooms' then
            mprint 'Public rooms:'
            mprint '\tName\tUsers\tTopic\tAliases'
            for _, r in pairs(js.chunk) do
                local name = ''
                if r.name ~= json.null then
                    name = r.name
                end
                mprint(('%s %s %s %s')
                    :format(
                        name,
                        r.num_joined_members,
                        r.topic,
                        table.concat(r.aliases, ', ')))
            end
        elseif command:find'/invite' then
            local room_id = js.room_id
        else
            dbg{['error'] = 'Unknown command in http cb', command=command,
                js=js}
        end
    end
    if tonumber(rc) == -2 then
        perr(('Call to API errored in command %s, maybe timeout?'):format(
            command))
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
     -- Store user presences here since they are not local to the rooms
     server.presence = {}
     server.end_token = 'END'
     server.typing_time = os.time()
     server.typingtimer = w.hook_timer(10*1000, 0, 0, "cleartyping", "")

     -- Cache error variables so we don't have to look them up for every error
     -- message, a normal user will not change these ever anyway.
     server.errprefix = wconf'weechat.look.prefix_error'
     server.errprefix_c = wcolor'weechat.color.chat_prefix_error'
     return server
end

function MatrixServer:UpdatePresence(c)
    self.presence[c.user_id] = c.presence
    for id, room in pairs(self.rooms) do
        room:UpdatePresence(c.user_id, c.presence)
    end
end

function MatrixServer:findRoom(buffer_ptr)
    for id, room in pairs(self.rooms) do
        if room.buffer == buffer_ptr then
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
        w.print('', 'matrix: Connecting to homeserver URL: '..
            w.config_get_plugin('homeserver_url'))
        local post = {
            ["type"]="m.login.password",
            ["user"]=user,
            ["password"]=password
        }
        -- Set a short timeout so user can get more immidiate feedback
        http('/login', {
                postfields = json.encode(post)
            }, 'http_cb', 5*1000)
    end
end

function MatrixServer:initial_sync()
    BUFFER = w.buffer_new("matrix", "", "", "closed_matrix_buffer_cb", "")
    w.buffer_set(BUFFER, "short_name", "matrix")
    w.buffer_set(BUFFER, "name", "matrix")
    w.buffer_set(BUFFER, "localvar_set_type", "server")
    w.buffer_set(BUFFER, "localvar_set_server", "matrix")
    w.buffer_set(BUFFER, "title", ("Matrix: %s"):format(
        w.config_get_plugin'homeserver_url'))
    w.buffer_set(BUFFER, "display", "auto")
    local data = urllib.urlencode({
        access_token = self.access_token,
        limit = w.config_get_plugin('backlog_lines'),
    })
    http('/initialSync?'..data)
end

function MatrixServer:getMessages(room_id)
    local data = urllib.urlencode({
        access_token= self.access_token,
        dir = 'b',
        from = 'END',
        limit = w.config_get_plugin('backlog_lines'),
    })
    http(('/rooms/%s/messages?%s')
        :format(urllib.quote(room_id), data))
end

function MatrixServer:join(room)
    if not self.connected then
        --XXX'''
        return
    end

    mprint('\tJoining room '..room)
    room = urllib.quote(room)
    http('/join/' .. room,
        {postfields = "access_token="..self.access_token})
end

function MatrixServer:part(room)
    if not self.connected then
        --XXX'''
        return
    end

    local id = urllib.quote(room.identifier)
    local data = urllib.urlencode({
        access_token= self.access_token,
    })
    -- TODO: close buffer, delete data, etc
    http(('/rooms/%s/leave?%s'):format(id, data), {postfields = "{}"},
        'http_cb', 10000, room.identifier)
end

function MatrixServer:poll()
    if self.connected == false or self.polling then
        return
    end
    self.polltime = os.time()
    self.polling = true
    local data = urllib.urlencode({
        access_token = self.access_token,
        timeout = 1000*30,
        from = self.end_token
    })
    http('/events?'..data, nil, 'poll_cb')
end

function MatrixServer:addRoom(room)
    local myroom = Room.create(room)
    myroom:create_buffer()
    self.rooms[room['room_id']] = myroom
    if room.membership == 'invite' and room.inviter then
        myroom:addNick(room.inviter)
    end
    return myroom
end

function MatrixServer:delRoom(room_id)
    for id, room in pairs(self.rooms) do
        if id == room_id then
            mprint('\tLeft room '..room.name)
            room:destroy()
            self.rooms[id] = nil
            break
        end
    end
end

function MatrixServer:msg(room_id, body, msgtype)
    -- check if there's an outgoing message timer already
    self:ClearSendTimer()

    if not msgtype then
        msgtype = 'm.text'
    end

    if not OUT[room_id] then
        OUT[room_id] = {}
    end
    -- Add message to outgoing queue of messages for this room
    table.insert(OUT[room_id], {msgtype, body})

    self:StartSendTimer()
end

function MatrixServer:StartSendTimer()
    local send_delay = 200
    self.sendtimer = w.hook_timer(send_delay, 0, 1, "send", "")
end

function MatrixServer:ClearSendTimer()
    -- Clear timer if it exists
    if self.sendtimer then
        w.unhook(self.sendtimer)
    end
    self.sendtimer = nil
end

function send(data, calls)
    -- Schedule a poll so that sending a message will try to poll messages
    -- if we came back from a server error, which has a wait time becaue of
    -- the polltimer.
    SERVER:poll()
    SERVER:ClearSendTimer()
    -- Iterate rooms
    for id, msgs in pairs(OUT) do
        -- Clear message
        OUT[id] = nil
        local body = {}
        local htmlbody = {}
        local msgtype

        local ishtml = false


        for _, msg in pairs(msgs) do
            -- last msgtype will override any other for simplicity's sake
            msgtype = msg[1]
            local html = irc_formatting_to_html(msg[2])
            if html ~= msg[2] then
                ishtml = true
            end
            table.insert(htmlbody, html )
            table.insert(body, msg[2] )
        end
        body = table.concat(body, '\n')

        local data = {
            postfields = {
                msgtype = msgtype,
                body = body,
        }}

        if ishtml then
            htmlbody = table.concat(htmlbody, '\n')
            data.postfields.body = strip_irc_formatting(body)
            data.postfields.format = 'org.matrix.custom.html'
            data.postfields.formatted_body = htmlbody
        end

        data.postfields = json.encode(data.postfields)


        http(('/rooms/%s/send/m.room.message?access_token=%s')
            :format(
              urllib.quote(id),
              urllib.quote(SERVER.access_token)
            ),
              data
            )
    end
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
         postfields = json.encode(data),
        })
end

function MatrixServer:set_membership(room_id, userid, data)
    http(('/rooms/%s/state/m.room.member/%s?access_token=%s')
        :format(urllib.quote(room_id),
          urllib.quote(userid),
          urllib.quote(self.access_token)),
        {customrequest = 'PUT',
         postfields = json.encode(data),
        })
end

function MatrixServer:SendTypingNotice(room_id)
    local data = {
        typing = true,
        timeout = 4*1000
    }
    http(('/rooms/%s/typing/%s?access_token=%s')
        :format(urllib.quote(room_id),
          urllib.quote(self.user_id),
          urllib.quote(self.access_token)),
        {customrequest = 'PUT',
         postfields = json.encode(data),
        })
end

function upload_cb(data, command, rc, stdout, stderr)
    if stderr ~= '' then
        perr(('error: %s'):format(stderr))
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
        --- TODO improve content type detection, maybe let curl do it?
    end
end

function MatrixServer:upload(room_id, filename)
    local content_type = 'image/jpeg'
    if command:find'png' then
        content_type = 'image/png'
    end
    -- TODO:
    --local url = w.config_get_plugin('homeserver_url') ..
    --    ('_matrix/media/v1/upload?access_token=%s')
    --    :format( urllib.quote(SERVER.access_token) )
    --w.hook_process_hashtable('curl',
    --    {arg1 = '-F',
    --    arg2 = 'filedata=@'..filename
    --    }, 30*1000, 'upload_cb', room_id)
end

function MatrixServer:CreateRoom(public, alias, invites)
    local data = {}
    if alias then
        data.room_alias_name = alias
    end
    if public then
        data.visibility = 'public'
    else
        data.visibility = 'private'
    end
    if invites then
        data.invite = invites
    end
    http(('/createRoom?access_token=%s')
        :format(urllib.quote(self.access_token)),
        {customrequest = 'POST',
         postfields = json.encode(data),
        })
end

function MatrixServer:ListRooms()
    http(('/publicRooms?access_token=%s')
        :format(urllib.quote(self.access_token)))
end

function MatrixServer:invite(room_id, user_id)
    local data = {
        user_id = user_id
    }
    http(('/rooms/%s/invite?access_token=%s')
        :format(urllib.quote(room_id),
          urllib.quote(self.access_token)),
        {customrequest = 'POST',
         postfields = json.encode(data),
        })
end

function MatrixServer:Nick(displayname)
    local data = {
        displayname = displayname,
    }
    http(('/profile/%s/displayname?access_token=%s')
        :format(
          urllib.quote(self.user_id),
          urllib.quote(self.access_token)),
        {customrequest = 'PUT',
         postfields = json.encode(data),
        })
end

function buffer_input_cb(b, buffer, data)
    for r_id, room in pairs(SERVER.rooms) do
        if buffer == room.buffer then
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
    room.buffer = nil
    room.identifier = obj['room_id']
    room.server = 'matrix'
    room.member_count = 0
    -- Cache lines for dedup?
    room.lines = {}
    -- Cache users for presence/nicklist
    room.users = {}
    -- Cache the rooms power levels state
    room.power_levels = {users={}}
    -- We might not be a member yet
    local state_events = obj.state or {}
    for _, state in pairs(state_events) do
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
    end

    if obj.membership == 'invite' then
        if w.config_get_plugin('autojoin_on_invite') == 'on' then
            SERVER:join(room.identifier)
        else
            mprint(('You have been invited to join room %s by %s. Type /join %s to join.'):format(room.identifier, obj.inviter, room.identifier))
        end
    end

    return room
end

function Room:setName(name)
    if not name or name == '' or name == json.null then
        return
    end
    w.buffer_set(self.buffer, "short_name", name)
    w.buffer_set(self.buffer, "name", name)
    -- Doesn't work
    w.buffer_set(self.buffer, "plugin", "matrix")
    w.buffer_set(self.buffer, "full_name",
        self.server.."."..name)
    w.buffer_set(self.buffer, "localvar_set_channel", name)
end

function Room:topic(topic)
    SERVER:state(self.identifier, 'm.room.topic', {topic=topic})
end

function Room:upload(filename)
    SERVER:upload(self.identifier, filename)
end

function Room:msg(msg)
    SERVER:msg(self.identifier, msg)
end

function Room:emote(msg)
    SERVER:emote(self.identifier, msg)
end

function Room:SendTypingNotice()
    SERVER:SendTypingNotice(self.identifier)
end

function Room:create_buffer()
    local buffer = w.buffer_search("", ("%s.%s"):format(self.server, self.name))
    if buffer ~= '' then
        self.buffer = buffer
    else
        self.buffer = w.buffer_new(("%s.%s")
            :format(self.server, self.name), "buffer_input_cb",
            self.name, "closed_matrix_room_cb", "")
        self.nicklist_groups = {
            -- Emulate OPs
            w.nicklist_add_group(self.buffer,
                '', "000|o", "weechat.color.nicklist_group", 1),
            -- Emulate half-op
            w.nicklist_add_group(self.buffer,
                '', "001|v", "weechat.color.nicklist_group", 1),
            -- Defined in weechat's irc-nick.h
            w.nicklist_add_group(self.buffer,
                '', "998|...", "weechat.color.nicklist_group", 1),
            w.nicklist_add_group(self.buffer,
                '', "999|...", "weechat.color.nicklist_group", 1),
        }
    end
    w.buffer_set(self.buffer, "nicklist", "1")
    w.buffer_set(self.buffer, "nicklist_display_groups", "0")
    w.buffer_set(self.buffer, "localvar_set_server", self.server)
    w.buffer_set(self.buffer, "localvar_set_roomid", self.identifier)
    self:setName(self.name)
end

function Room:destroy()
    w.buffer_close(self.buffer)
end

function Room:_nickListChanged()
    -- Check the user count, if it's 2 or less then we decide this buffer
    -- is a "private" one like IRC's query type
    if self.member_count == 3 then -- don't run code for every add > 2
        w.buffer_set(self.buffer, "localvar_set_type", 'channel')
    elseif self.member_count == 2 then
        -- At the point where we reach two nicks, set the buffer name to be
        -- the display name of the other guy that is not our self since it's
        -- in effect a query, but the matrix protocol doesn't have such
        -- a concept
        w.buffer_set(self.buffer, "localvar_set_type", 'private')
        w.buffer_set(self.buffer, "localvar_set_server", self.server)
        -- Check if the room name is identifier meaning we don't have a
        -- name set yet, and should try and set one
        local buffer_name = w.buffer_get_string(self.buffer, 'name')
        if not self.roomname and not self.aliases then
            for id, name in pairs(self.users) do
                -- Set the name to the other party
                if id ~= SERVER.user_id then
                    self:setName(name)
                    break
                end
            end
        end
    elseif self.member_count == 1 then
        if not self.roomname and not self.aliases then
            -- Set the name to ourselves
            self:setName(self.users[SERVER.user_id])
        end
    end
end

function Room:addNick(user_id, displayname)
    if not displayname or displayname == json.null or displayname == '' then
        displayname = user_id:match('@(.*):.+')
    end
    if not self.users[user_id] then
        self.member_count = self.member_count + 1
    end
    if self.users[user_id] ~= displayname then
        self.users[user_id] = displayname
        local nick_c = ''
        -- Check if this is ourselves
        if user_id == SERVER.user_id then
            w.buffer_set(self.buffer, "highlight_words", displayname)
            w.buffer_set(self.buffer, "localvar_set_nick", displayname)
            nick_c = 'chat_nick_self'
        end
        local ngroup, nprefix, nprefix_color = self:GetNickGroup(user_id)
        -- Check if nick already exists
        --local nick_ptr = w.nicklist_search_nick(self.buffer, '', displayname)
        --if nick_ptr == '' then
        nick_ptr = w.nicklist_add_nick(self.buffer,
            self.nicklist_groups[ngroup],
            displayname,
            nick_c, nprefix, nprefix_color, 1)
        --else
        --    -- TODO CHANGE nickname here
        --end
        if nick_ptr  == '' then
            -- Duplicate nick names :(
            -- We just add the full id to the nicklist so atleast it will show
            -- but we should probably assign something new and track the state
            -- so we can print msgs with non-conflicting nicks too
            w.nicklist_add_nick(self.buffer,
                self.nicklist_groups[ngroup],
                user_id,
                nick_c, nprefix, nprefix_color, 1)
            -- Since we can't allow duplicate displaynames, we just use the
            -- user_id straight up. Maybe we could invent some clever
            -- scheme here, like user(homeserver), user (2) or something
            self.users[user_id] = user_id
        end
        self:_nickListChanged()
    end

    return displayname
end

function Room:GetNickGroup(user_id)
    -- TODO, cache
    local ngroup = 4
    local nprefix = ' '
    local nprefix_color = ''
    if self:GetPowerLevel(user_id) >= 100 then
        ngroup = 1
        nprefix = '&'
        nprefix_color = 'lightgreen'
        if user_id == self.creator then
            nprefix = '~'
            nprefix_color = 'lightred'
        end
    elseif self:GetPowerLevel(user_id) >= 50 then
        ngroup = 2
        nprefix = '@'
        nprefix_color = 'lightgreen'
    elseif self:GetPowerLevel(user_id) > 0 then
        ngroup = 2
        nprefix = '+'
        nprefix_color = 'yellow'
    elseif SERVER.presence[user_id] then
        -- User has a presence, put him in group3
        ngroup = 3
    end
    return ngroup, nprefix, nprefix_color
end

function Room:GetPowerLevel(user_id)
    return self.power_levels.users[user_id] or 0
end

function Room:ClearTyping()
    for user_id, nick in pairs(self.users) do
        local _, nprefix, nprefix_color = self:GetNickGroup(user_id)
        self:UpdateNick(user_id, 'prefix', nprefix)
        self:UpdateNick(user_id, 'prefix_color', nprefix_color)
    end
end

function Room:UpdatePresence(user_id, presence)
    local nick_c = 'bar_fg'
    local nick = self.users[user_id]
    if presence == 'typing' then
        self:UpdateNick(user_id, 'prefix', '!')
        self:UpdateNick(user_id, 'prefix_color', 'magenta')
        return
    end
    if user_id ~= SERVER.user_id then
        if presence == 'online' then
            nick_c =  w.info_get('irc_nick_color_name', nick)
        elseif presence == 'unavailable' then
            nick_c = 'weechat.color.nicklist_away'
        elseif presence == 'offline' then
            nick_c = 'red'
        else
            dbg{err='unknown presence type',presence=presence}
        end
        self:UpdateNick(user_id, 'color', nick_c)
    end
end

function Room:UpdateNick(user_id, key, val)
    local nick = self.users[user_id]
    if not nick then return end
    local nick_ptr = w.nicklist_search_nick(self.buffer, '', nick)

    if nick_ptr ~= '' and key and val then
        -- Check if we need to move the nick into another group
        local group_ptr = w.nicklist_nick_get_pointer(self.buffer, nick_ptr,
            'group')
        local ngroup, nprefix, nprefix_color = self:GetNickGroup(user_id)
        if group_ptr ~= self.nicklist_groups[ngroup] then
            local nick_c = w.nicklist_nick_get_string(self.buffer, nick_ptr,
                'color')
            -- No WeeChat API for changing a nick's group so we will have to
            -- delete the nick from the old nicklist and add it to the correct
            -- nicklist group
            local d_nick_ptr = w.nicklist_remove_nick(self.buffer, nick_ptr)
            -- TODO please check if this call fails, if it does it means the
            -- WeeChat version is old and has a bug so it can't remove nicks
            -- and so it needs some workaround
            nick_ptr = w.nicklist_add_nick(self.buffer,
                self.nicklist_groups[ngroup],
                nick,
                nick_c, nprefix, nprefix_color, 1)
        end
        -- Check if we are clearing a typing notice, and don't issue updates
        -- if we are, because it spams the API so much, including potential
        -- relay clients
        if key == 'prefix' and val == ' ' then
            -- TODO check existing values like + and @ too
            local prefix = w.nicklist_nick_get_string(self.buffer, nick_ptr,
                key)
            if prefix == '!' then
                w.nicklist_nick_set(self.buffer, nick_ptr, key, val)
            end
        elseif key == 'prefix_color' then
            local prefix_color = w.nicklist_nick_get_string(self.buffer,
                nick_ptr, key)
            if prefix_color ~= val then
                w.nicklist_nick_set(self.buffer, nick_ptr, key, val)
            end
        else
            w.nicklist_nick_set(self.buffer, nick_ptr, key, val)
        end
    end
end

function Room:delNick(id)
    if self.users[id] then
        local nick = self.users[id]
        local nick_ptr = w.nicklist_search_nick(self.buffer, '', nick)
        if nick_ptr ~= '' then
            w.nicklist_remove_nick(self.buffer, nick_ptr)
            self.users[id] = nil
            self.member_count = self.member_count - 1
        end
        self:_nickListChanged()
        return true
    end
end

function Room:formatNick(user_id)
    -- Turns a nick name into a weechat-styled nickname. This means giving
    -- it colors, and proper prefix and suffix
    local nick = self.users[user_id]
    if not nick then
        return user_id
    end
    local color
    if user_id == SERVER.user_id then
        color = w.color('chat_nick_self')
    else
        color = w.info_get('irc_nick_color', nick)
    end
    local _, nprefix, nprefix_c = self:GetNickGroup(user_id)
    local prefix = wconf('weechat.look.nick_prefix')
    local prefix_c = wcolor('weechat.color.chat_nick_prefix')
    local suffix = wconf('weechat.look.nick_suffix')
    local suffix_c = wcolor('weechat.color.chat_nick_suffix')
    local nick_f = prefix_c
        .. prefix
        .. wcolor(nprefix_c)
        .. nprefix
        .. color
        .. nick
        .. suffix_c
        .. suffix
    return nick_f
end

-- Parses a chunk of json meant for a room
function Room:parseChunk(chunk, backlog, chunktype)
    local taglist = {}
    local tag = function(tag)
        -- Helper function to add tags
        if type(tag) == 'table' then
            for _, t in pairs(tag) do
                taglist[t] = true
            end
        else
            taglist[tag] = true
        end
    end
    local tags = function()
        -- Helper for returning taglist for this message
        local out = {}
        for k, v in pairs(taglist) do
            table.insert(out, k)
        end
        return table.concat(out, ',')
    end
    if not backlog then
        backlog = false
    end

    if backlog then
        tag{'no_highlight','notify_none','no_log'}
    end

    local is_self = false
    -- Check if own message
    if chunk.user_id == SERVER.user_id then
        is_self = true
        tag{'no_highlight','notify_none'}
    end

    if chunk['type'] == 'm.room.message' then
        if not backlog and not is_self then
            tag'notify_message'
        end

        local time_int = chunk['origin_server_ts']/1000
        local color = default_color
        local body
        local content = chunk['content']
        if not content['msgtype'] then
            -- We don't support redactions
            return
        end
        if content['msgtype'] == 'm.text' then
            body = content['body']
            -- TODO
            -- Parse HTML here:
            -- content.format = 'org.matrix.custom.html'
            -- fontent.formatted_body...
        elseif content['msgtype'] == 'm.image' then
            local url = content['url']:gsub('mxc://',
                w.config_get_plugin('homeserver_url')
                .. '_matrix/media/v1/download/')
            body = content['body'] .. ' ' .. url
        elseif content['msgtype'] == 'm.notice' then
            color = wcolor('irc.color.notice')
            body = content['body']
        elseif content['msgtype'] == 'm.emote' then
            local nick_c
            local nick = self.users[chunk.user_id] or chunk.user_id
            if is_self then
                nick_c = w.color('chat_nick_self')
            else
                nick_c = w.info_get('irc_nick_color', nick)
            end
            tag"irc_action"
            local prefix_c = wcolor'weechat.color.chat_prefix_action'
            local prefix = wconf'weechat.look.prefix_action'
            body = ("%s%s %s%s"):format(
                nick_c, nick, color, content['body']
            )
            local data = ("%s%s\t%s"):format(
                prefix_c,
                prefix,
                body)
            return w.print_date_tags(self.buffer, time_int, tags(),data)
        else
            body = content['body']
            perr 'Uknown content type'
            dbg(content)
        end
        local data = ("%s\t%s%s"):format(
                self:formatNick(chunk.user_id),
                color,
                body)
        w.print_date_tags(self.buffer, time_int, tags(), data)
    elseif chunk['type'] == 'm.room.topic' then
        local title = chunk['content']['topic']
        if not title then
            title = ''
        end
        w.buffer_set(self.buffer, "title", title)
        local color = wcolor("irc.color.topic_new")
        local nick = self.users[chunk.user_id] or chunk.user_id
        local data = ('--\t%s%s has changed the topic to "%s%s%s"'):format(
                nick,
                default_color,
                color,
                title,
                default_color
              )
        w.print_date_tags(self.buffer, chunk.origin_server_ts, tags(),
            data)
    elseif chunk['type'] == 'm.room.name' then
        local name = chunk['content']['name']
        self.roomname = name
        if name ~= '' or name ~= json.null then
            self:setName(name)
        end
    elseif chunk['type'] == 'm.room.member' then
        if chunk['content']['membership'] == 'join' then
            tag"irc_join"
            --- FIXME shouldn't be neccessary adding all the time
            local nick = self.users[chunk.user_id] or self:addNick(chunk.user_id, chunk.content.displayname)
            local name = chunk.content.displayname
            if not name or name == json.null or name == '' then
                name = chunk.user_id
            end
            local time_int = chunk['origin_server_ts']/1000
            -- Check if the chunk has prev_content or not
            -- if there is prev_content there wasn't a join but a nick change
            if chunk.prev_content
                    and chunk.prev_content.membership == 'join'
                    and chunktype == 'messages' then
                local oldnick = chunk.prev_content.displayname
                if oldnick == json.null then
                    oldnick = chunk.user_id
                else
                    if oldnick == name then
                        -- Maybe they changed their avatar or something else
                        -- that we don't care about
                        return
                    end
                    self:delNick(chunk.user_id)
                    nick = self:addNick(chunk.user_id, chunk.content.displayname)
                end
                local pcolor = wcolor'weechat.color.chat_prefix_network'
                local data = ('%s--\t%s%s%s is now known as %s%s'):format(
                    pcolor,
                    w.info_get('irc_nick_color', oldnick),
                    oldnick,
                    default_color,
                    w.info_get('irc_nick_color', name),
                    name)
                w.print_date_tags(self.buffer, time_int, tags(), data)
            elseif chunktype == 'messages' then
                local data = ('%s%s\t%s%s%s (%s%s%s) joined the room.'):format(
                    wcolor('weechat.color.chat_prefix_join'),
                    wconf('weechat.look.prefix_join'),
                    w.info_get('irc_nick_color', name),
                    name,
                    wcolor('irc.color.message_join'),
                    wcolor'weechat.color.chat_host',
                    chunk.user_id,
                    wcolor('irc.color.message_join')
                )
                w.print_date_tags(self.buffer, time_int, tags(), data)
            end
        elseif chunk['content']['membership'] == 'leave' then
            if chunktype == 'states' then
                self:delNick(chunk.user_id)
            end
            if chunktype == 'messages' then
                local nick = chunk.user_id
                local prev = chunk['prev_content']
                if (prev and
                        prev.displayname and
                        prev.displayname ~= json.null) then
                    nick = prev.displayname
                end
                tag"irc_quit"
                local time_int = chunk['origin_server_ts']/1000
                local data = ('%s%s\t%s%s%s left the room.'):format(
                    wcolor('weechat.color.chat_prefix_quit'),
                    wconf('weechat.look.prefix_quit'),
                    w.info_get('irc_nick_color', nick),
                    nick,
                    wcolor('irc.color.message_quit')
                )
                w.print_date_tags(self.buffer, time_int, tags(), data)
            end
        elseif chunk['content']['membership'] == 'invite' then
            -- Check if we were the one being invited
            if chunk.state_key == SERVER.user_id and
                  (not backlog and chunktype=='messages') then
                if w.config_get_plugin('autojoin_on_invite') == 'on' then
                    SERVER:join(self.identifier)
                    self:addNick(chunk.user_id)
                    mprint(('%s invited you'):format(
                        chunk.user_id))
                else
                    mprint(('You have been invited to join room %s by %s. Type /join %s to join.')
                        :format(
                          self.identifier,
                          chunk.user_id,
                          self.identifier))
                end
            end
            if chunktype == 'messages' then
                tag"irc_invite"
                local time_int = chunk['origin_server_ts']/1000
                local prefix_c = wcolor'weechat.color.chat_prefix_action'
                local prefix = wconf'weechat.look.prefix_action'
                local data = ("%s%s\t%s invited %s to join"):format(
                    prefix_c,
                    prefix,
                    self.users[chunk.user_id] or chunk.user_id,
                    self.users[chunk.state_key] or chunk.state_key
                )
                w.print_date_tags(self.buffer, time_int, tags(), data)
            end
        else
            dbg{err= 'unknown membership type in parseChunk', chunk= chunk}
        end
    elseif chunk['type'] == 'm.room.create' then
        self.creator = chunk.content.creator
    elseif chunk['type'] == 'm.room.power_levels' then
        for user_id, lvl in pairs(chunk.content.users) do
            -- TODO
            -- calculate changes here and generate message lines
            -- describing the change
        end
        self.power_levels = chunk.content
        for user_id, lvl in pairs(self.power_levels.users) do
            local _, nprefix, nprefix_color = self:GetNickGroup(user_id)
            self:UpdateNick(user_id, 'prefix', nprefix)
            self:UpdateNick(user_id, 'prefix_color', nprefix_color)
        end
    elseif chunk['type'] == 'm.room.join_rules' then
        -- TODO: parse join_rules events --
        self.join_rules = chunk.content
    elseif chunk['type'] == 'm.typing' then
        for _, id in pairs(chunk.content.user_ids) do
            self:UpdatePresence(id, 'typing')
        end
    elseif chunk['type'] == 'm.presence' then
        SERVER:UpdatePresence(chunk)
    elseif chunk['type'] == 'm.room.aliases' then
        -- Use first alias, weechat doesn't really support multiple  aliases
        self.aliases = chunk.content.aliases
        self:setName(chunk.content.aliases[1])
    else
        perr(('Unknown chunk type %s%s%s in room %s%s%s'):format(
            w.color'bold',
            chunk.type,
            default_color,
            w.color'bold',
            self.name,
            default_color))
    end
end

function Room:Op(nick)
    for id, name in pairs(self.users) do
        if name == nick then
            -- patch the locally cached power levels
            self.power_levels.users[id] = 100
            SERVER:state(self.identifier, 'm.room.power_levels',
                self.power_levels)
            break
        end
    end
end

function Room:Voice(nick)
    for id, name in pairs(self.users) do
        if name == nick then
            -- patch the locally cached power levels
            self.power_levels.users[id] = 50
            SERVER:state(self.identifier, 'm.room.power_levels',
                self.power_levels)
            break
        end
    end
end

function Room:Devoice(nick)
    for id, name in pairs(self.users) do
        if name == nick then
            -- patch the locally cached power levels
            self.power_levels.users[id] = 0
            SERVER:state(self.identifier, 'm.room.power_levels',
                self.power_levels)
            break
        end
    end
end

function Room:Deop(nick)
    for id, name in pairs(self.users) do
        if name == nick then
            -- patch the locally cached power levels
            self.power_levels.users[id] = 0
            SERVER:state(self.identifier, 'm.room.power_levels',
                self.power_levels)
            break
        end
    end
end

function Room:Kick(nick, reason)
    for id, name in pairs(self.users) do
        if name == nick then
            local data = {
                membership = 'leave',
                reason = 'Kicked by '..SERVER.user_id
            }
            SERVER:set_membership(self.identifier, id, data)
            break
        end
    end
end

function Room:Whois(nick)
    for id, name in pairs(self.users) do
        if name == nick then
            local pcolor = wcolor'weechat.color.chat_prefix_network'
            local data = ('%s--\t%s%s%s has user id %s%s'):format(
                pcolor,
                w.info_get('irc_nick_color', nick),
                nick,
                default_color,
                w.info_get('irc_nick_color', id),
                id)
            w.print_date_tags(self.buffer, nil, 'notify_message', data)
            break
        end
    end
end

function Room:invite(id)
    SERVER:invite(self.identifier, id)
end

function poll(a,b)
    SERVER:poll()
    return w.WEECHAT_RC_OK
end

function polltimer_cb(a,b)
    local now = os.time()
    if (now - SERVER.polltime) > 65 then
        SERVER.polling = false
        SERVER:poll()
    end
    return w.WEECHAT_RC_OK
end

function cleartyping(a, b)
    for id, room in pairs(SERVER.rooms) do
        room:ClearTyping()
    end
    return w.WEECHAT_RC_OK
end

function join_command_cb(data, current_buffer, args)
    local room = SERVER:findRoom(current_buffer)
    if current_buffer == BUFFER or room then
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
    local room = SERVER:findRoom(current_buffer)
    if room then
        local _, args = split_args(args)
        room:topic(args)
        return w.WEECHAT_RC_OK_EAT
    else
        return w.WEECHAT_RC_OK
    end
end

function upload_command_cb(data, current_buffer, args)
    local room = SERVER:findRoom(current_buffer)
    if room then
        local _, args = split_args(args)
        room:upload(args)
        return w.WEECHAT_RC_OK_EAT
    else
        return w.WEECHAT_RC_OK
    end
end

function query_command_cb(data, current_buffer, args)
    local room = SERVER:findRoom(current_buffer)
    if room then
        local _, args = split_args(args)
        for id, displayname in pairs(room.users) do
            if displayname == args then
                -- Create a new room and invite the guy
                SERVER:CreateRoom(false, nil, {id})
                return w.WEECHAT_RC_OK_EAT
            end
        end
    else
        return w.WEECHAT_RC_OK
    end
end

function create_command_cb(data, current_buffer, args)
    local room = SERVER:findRoom(current_buffer)
    if room or current_buffer == BUFFER then
        local _, args = split_args(args)
        -- Room names are supposed to be without # and homeserver, so
        -- we try to help the user out here
        local alias = args:match'#?(.*):?'
        -- Create a non-public room with argument as alias
        SERVER:CreateRoom(false, alias, nil)
        return w.WEECHAT_RC_OK_EAT
    else
        return w.WEECHAT_RC_OK
    end
end

function invite_command_cb(data, current_buffer, args)
    local room = SERVER:findRoom(current_buffer)
    if room then
        local _, args = split_args(args)
        room:invite(args)
        return w.WEECHAT_RC_OK_EAT
    else
        return w.WEECHAT_RC_OK
    end
end

function list_command_cb(data, current_buffer, args)
    local room = SERVER:findRoom(current_buffer)
    if room or current_buffer == BUFFER then
        SERVER:ListRooms()
        return w.WEECHAT_RC_OK_EAT
    else
        return w.WEECHAT_RC_OK
    end
end

function op_command_cb(data, current_buffer, args)
    local room = SERVER:findRoom(current_buffer)
    if room then
        local _, args = split_args(args)
        room:Op(args)
        return w.WEECHAT_RC_OK_EAT
    else
        return w.WEECHAT_RC_OK
    end
end

function voice_command_cb(data, current_buffer, args)
    local room = SERVER:findRoom(current_buffer)
    if room then
        local _, args = split_args(args)
        room:Voice(args)
        return w.WEECHAT_RC_OK_EAT
    else
        return w.WEECHAT_RC_OK
    end
end

function devoice_command_cb(data, current_buffer, args)
    local room = SERVER:findRoom(current_buffer)
    if room then
        local _, args = split_args(args)
        room:Devoice(args)
        return w.WEECHAT_RC_OK_EAT
    else
        return w.WEECHAT_RC_OK
    end
end
function deop_command_cb(data, current_buffer, args)
    local room = SERVER:findRoom(current_buffer)
    if room then
        local _, args = split_args(args)
        room:Deop(args)
        return w.WEECHAT_RC_OK_EAT
    else
        return w.WEECHAT_RC_OK
    end
end

function kick_command_cb(data, current_buffer, args)
    local room = SERVER:findRoom(current_buffer)
    if room then
        local _, args = split_args(args)
        room:Kick(args)
        return w.WEECHAT_RC_OK_EAT
    else
        return w.WEECHAT_RC_OK
    end
end

function nick_command_cb(data, current_buffer, args)
    local room = SERVER:findRoom(current_buffer)
    if room or current_buffer == BUFFER then
        local _, nick = split_args(args)
        SERVER:Nick(nick)
        return w.WEECHAT_RC_OK_EAT
    else
        return w.WEECHAT_RC_OK
    end
end

function whois_command_cb(data, current_buffer, args)
    local room = SERVER:findRoom(current_buffer)
    if room then
        local _, nick = split_args(args)
        room:Whois(nick)
        return w.WEECHAT_RC_OK_EAT
    else
        return w.WEECHAT_RC_OK
    end
end

function closed_matrix_buffer_cb(data, buffer)
    BUFFER = nil
    return w.WEECHAT_RC_OK
end

function closed_matrix_room_cb(data, buffer)
    return w.WEECHAT_RC_ERR
end

function typing_notification_cb(signal, sig_type, data)
    -- Ignore commands
    if data:match'^/' then
        return w.WEECHAT_RC_OK
    end
    -- Is this signal coming from a matrix buffer?
    local room = SERVER:findRoom(data)
    if room then
        -- Start sending when it reaches > 4
        if #w.buffer_get_string(data, "input") > 4 then
            local now = os.time()
            -- Generate typing events every 4th second
            if SERVER.typing_time + 4 < now then
                SERVER.typing_time = now
                room:SendTypingNotice()
            end
        end
    end

    return w.WEECHAT_RC_OK
end

if w.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE, SCRIPT_DESC, "unload", "UTF-8") then
    local settings = {
        homeserver_url= {'https://matrix.org/', 'Full URL including port to your homeserver or use default matrix.org'},
        user= {'', 'Your homeserver username'},
        password= {'', 'Your homeserver password'},
        backlog_lines= {'120', 'Number of lines to fetch from backlog upon connecting'},
        autojoin_on_invite = {'on', 'Automatically join rooms you are invited to'},
        typing_notices = {'on', 'Send typing notices when you type'},
    }
    -- set default settings
    local version = w.info_get('version_number', '') or 0
    for option, value in pairs(settings) do
        if w.config_is_set_plugin(option) ~= 1 then
            w.config_set_plugin(option, value[1])
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
    w.hook_command_run('/upload', 'upload_command_cb', '')
    w.hook_command_run('/query', 'query_command_cb', '')
    w.hook_command_run('/list', 'list_command_cb', '')
    w.hook_command_run('/op', 'op_command_cb', '')
    w.hook_command_run('/voice', 'voice_command_cb', '')
    w.hook_command_run('/deop', 'deop_command_cb', '')
    w.hook_command_run('/devoice', 'devoice_command_cb', '')
    w.hook_command_run('/kick', 'kick_command_cb', '')
    w.hook_command_run('/create', 'create_command_cb', '')
    w.hook_command_run('/invite', 'invite_command_cb', '')
    w.hook_command_run('/nick', 'nick_command_cb', '')
    w.hook_command_run('/whois', 'whois_command_cb', '')
    -- TODO
    -- /ban
    -- /names
    -- /upload
    -- Giving people arbitrary power levels
    -- Lazyload messages instead of HUGE initialSync
    if w.config_get_plugin('typing_notices') == 'on' then
        w.hook_signal('input_text_changed', "typing_notification_cb", '')
    end
    local cmds = {'help', 'connect'}
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
