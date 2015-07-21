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

 TODO
 ----
 /ban
 /names
 /upload
 Giving people arbitrary power levels
 Lazyload messages instead of HUGE initialSync
 Dynamically fetch more messages in backlog when user reaches the
 oldest message using pgup
 Need a way to change room join rule
 Fix broken state after failed initial connect
 Fix parsing of kick messages
 Fix parsing of multiple join messages
]]

local json = require 'cjson' -- apt-get install lua-cjson
local olmstatus, olm = pcall(require, 'olm') -- LuaJIT olm FFI binding ln -s ~/olm/olm.lua /usr/local/share/lua/5.1
local w = weechat

local SCRIPT_NAME = "matrix"
local SCRIPT_AUTHOR = "xt <xt@xt.gg>"
local SCRIPT_VERSION = "2"
local SCRIPT_LICENSE = "MIT"
local SCRIPT_DESC = "Matrix.org chat plugin"
local SCRIPT_COMMAND = SCRIPT_NAME

local SERVER
local STDOUT = {}
local OUT = {}
local BUFFER
local Room
local MatrixServer
local DEBUG = false
local POLL_INTERVAL = 360

local default_color = w.color('default')
-- Cache error variables so we don't have to look them up for every error
-- message, a normal user will not change these ever anyway.
local errprefix
local errprefix_c

local homedir
local ALGO = 'm.olm.v1.curve25519-aes-sha2'
local OLM_KEY = 'secr3t' -- TODO configurable using weechat sec data
local v2_api_ns = '_matrix/client/v2_alpha'

local dtraceback = debug.traceback
debug.traceback = function (...)
    if select('#', ...) >= 1 then
        local err, lvl = ...
        local trace = dtraceback(err, (lvl or 2)+1)
        perr(trace)
    end
    -- direct call to debug.traceback: return the original.
    -- debug.traceback(nil, level) doesn't work in Lua 5.1
    -- (http://lua-users.org/lists/lua-l/2011-06/msg00574.html), so
    -- simply remove first frame from the stack trace
    return (dtraceback(...):gsub("(stack traceback:\n)[^\n]*\n", "%1"))
end
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

local function werr(message)
    --write error message to core buffer
    if message == nil then return end
end
local function perr(message)
    if message == nil then return end
    -- Print error message to the matrix "server" buffer using WeeChat styled
    -- error message
    mprint(
        errprefix_c ..
        errprefix ..
        '\t' ..
        default_color ..
        tostring(message)
        )
end

local function dbg(message)
    perr('- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -')
    if type(message) == 'table' then
        tprint(message)
    else
        message = ("DEBUG: %s"):format(tostring(message))
        mprint(BUFFER, message)
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

local function sign_json(json_object, signing_key, signing_name)
    -- See: https://github.com/matrix-org/matrix-doc/blob/master/specification/31_event_signing.rst
    -- Maybe use:http://regex.info/code/JSON.lua which sorts keys
    local signatures = json_object.signatures or {}
    json_object.signatures = nil

    local unsigned = json_object.unsigned or nil
    json_object.unsigned = nil

    -- TODO ensure canonical json
    local signed = signing_key:sign(json.encode(json_object))
    local signature_base64 = encode_base64(signed.signature)

    local key_id = ("%s:%s"):format(signing_key.agl, signing_key.version)
    signatures[signing_name] = {[key_id] = signature_base64}

    json_object.signatures = signatures
    if unsigned then
        json_object.unsigned = unsigned
    end

    return json_object
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

function matrix_unload()
    w.print('', 'matrix: Unloading')
    -- Clear/free olm memory if loaded
    if olmstatus then
        w.print('', 'matrix: Saving olm state')
        SERVER.olm.save()
        w.print('', 'matrix: Clearing olm state from memory')
        SERVER.olm.account:clear()
        --SERVER.olm = nil
    end
    w.print('', 'matrix: done cleaning up!')
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
    elseif args == 'debug' then
        if DEBUG then
            DEBUG = false
            w.print('', SCRIPT_NAME..': debugging messages disabled')
        else
            DEBUG = true
            w.print('', SCRIPT_NAME..': debugging messages enabled')
        end
    else
        perr("Command not found: " .. args)
    end

    return w.WEECHAT_RC_OK
end

function configuration_changed_cb(data, option, value)
    if value == 'on' then
        DEBUG = true
        w.print('', SCRIPT_NAME..': debugging messages enabled')
    else
        DEBUG = false
        w.print('', SCRIPT_NAME..': debugging messages disabled')
    end
end

local function http(url, post, cb, timeout, extra, api_ns)
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
        extra = nil
    end
    if not api_ns then
        api_ns = "_matrix/client/api/v1"
    end

    -- Add accept encoding by default if it's not already there
    if not post.accept_encoding then
        post.accept_encoding = 'application/json'
    end

    local homeserver_url = w.config_get_plugin('homeserver_url')
    homeserver_url = homeserver_url .. api_ns
    url = homeserver_url .. url
    if DEBUG then
        dbg{request={url=url,post=post,extra=extra}}
    end
    w.hook_process_hashtable('url:' .. url, post, timeout, cb, extra)
end

function poll_cb(data, command, rc, stdout, stderr)
    -- Because of a bug in WeeChat sometimes the stdout gets prepended by
    -- any number of BEL chars (hex 07). Let's have a nasty workaround and
    -- just replace them away.
    stdout = (stdout:gsub('^\007*', ''))

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
        if DEBUG then
            dbg{reply={command=command,js=js}}
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
                        elseif chunk.type and chunk.type == 'm.typing' then
                            -- Ignore typing events for unknown rooms
                        else
                            -- Maybe user closed the buffer? Recreate.
                            local newroom = SERVER:addRoom(chunk)
                            newroom:parseChunk(chunk, false, 'messages')

                            perr('Event for unknown room... Recreating buffer. Try /lua reload matrix to refresh all state')
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

function real_http_cb(data, command, rc, stdout, stderr)
    if stderr ~= '' then
        mprint(('error: %s'):format(stderr))
        return w.WEECHAT_RC_OK
    end

    -- Because of a bug in WeeChat sometimes the stdout gets prepended by
    -- any number of BEL chars (hex 07). Let's have a nasty workaround and
    -- just replace them away.
    stdout = (stdout:gsub('^\007*', ''))

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
        if DEBUG then
            dbg{reply={command=command,js=js}}
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
            SERVER.polltimer = w.hook_timer(POLL_INTERVAL*1000, 0, 0, "polltimer_cb", "")
            if olmstatus then
                -- timer that checks number of otks available on the server
                SERVER.otktimer = w.hook_timer(POLL_INTERVAL*1000, 0, 0, "otktimer_cb", "")
                SERVER.olm.query{SERVER.user_id}
                --SERVER.olm.upload_keys()
                SERVER.olm.check_server_keycount()
            end
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
        elseif command:find'/keys/claim' then
            local count = 0
            for user_id, v in pairs(js.one_time_keys or {}) do
                for device_id, keys in pairs(v or {}) do
                    for key_id, key in pairs(keys or {}) do
                        SERVER.olm.otks[user_id] = {[device_id]=key}  -- TODO support more than one
                        perr(('olm: Recieved OTK for user %s for device id %s'):format(user_id, device_id))
                        count = count + 1
                        SERVER.olm.create_session(user_id)
                    end
                end
            end
        elseif command:find'/keys/query' then
            for k, v in pairs(js.device_keys or {}) do
                SERVER.olm.device_keys[k] = v
                -- Claim keys for all only if missing session
                for device_id, device_data in pairs(v) do
                    -- First try to create session from saved data
                    -- if that doesn't success we will download otk
                    SERVER.olm.create_session(k)
                    local pickle = SERVER.olm.sessions[k..':'..device_id]
                    if not pickle then
                        perr('olm: Downloading otk for user '..k..', and device_id: '..device_id)
                        SERVER.olm.claim(k)
                    else
                        perr('olm: Reusing existing session for user '..k)
                    end
                end
            end
        elseif command:find'/keys/upload' then
            local key_count = 0
            local valid_response = false
            local sensible_number_of_keys = 20
            for algo, count in pairs(js.one_time_key_counts) do
                valid_response = true
                key_count = count
                SERVER.olm.key_count = key_count
            end
            perr('olm: Number of own OTKs uploaded to server: '..key_count)
            -- Check for valid response so we don't create endless loop here
            if valid_response and key_count < sensible_number_of_keys then
                SERVER.olm.upload_keys()
            end
        elseif command:find'upload' then
            -- We store room_id in data
            local room_id = data
            if js.content_uri then
                SERVER:Msg(room_id, js.content_uri)
            end
        elseif command:find'/typing/' then
            -- either it errs or it is empty
        elseif command:find'/state/' then
            -- TODO errorcode: M_FORBIDDEN
            -- either it errs or it is empty
            --dbg({state= js})
        elseif command:find'/send/' then
            -- XXX Errorhandling
            -- TODO save event id to use for localecho
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
            dbg{['error'] = {msg='Unknown command in http cb', command=command,
                js=js}}
        end
    end
    if tonumber(rc) == -2 then
        perr(('Call to API errored in command %s, maybe timeout?'):format(
            command))
    end

    return w.WEECHAT_RC_OK
end
function http_cb(data, command, rc, stdout, stderr)
    local status, result = xpcall(real_http_cb, debug.traceback, data, command, rc, stdout, stderr)
    return result
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

     if olmstatus then -- check if encryption is available
         local account = olm.Account.new()
         local olmdata = {
             account=account,
             sessions={},
             device_keys={},
             otks={}
         }
         olmdata.save = function()
             local pickle, err = account:pickle(OLM_KEY)
             perr(err)
             local fd = io.open(homedir..'account.olm', 'wb')
             fd:write(pickle)
             fd:close()
         end
         olmdata.query = function(user_ids) -- Query keys from other user_id
             if DEBUG then
                 perr('olm: querying user_ids')
                 tprint(user_ids)
             end
             local auth = urllib.urlencode{access_token=SERVER.access_token}
             local data = {
                 device_keys = {}
             }
             for _,uid in pairs(user_ids) do
                 data.device_keys[uid] = {false}
             end
             http('/keys/query/?'..auth,
                {postfields=json.encode(data)},
                'http_cb',
                5*1000, nil,
                v2_api_ns )
         end
         olmdata.check_server_keycount = function()
             local data = urllib.urlencode{access_token=SERVER.access_token}
             http('/keys/upload/'..olmdata.device_id..'?'..data,
                {},
                'http_cb', 5*1000, nil, v2_api_ns)
         end
         olmdata.upload_keys = function()
             if DEBUG then
                 perr('olm: Uploading keys')
             end
             local id_keys = json.decode(account:identity_keys())
             local user_id = SERVER.user_id
             local one_time_keys = {}
             local otks = json.decode(account:one_time_keys())
             local keyCount = 0
             for id, k in pairs(otks.curve25519) do
                 keyCount = keyCount + 1
             end
             perr('olm: keycount: '..tostring(keyCount))
             if keyCount < 5 then -- try to always have 5 keys
                 perr('olm: newly generated keys: '..tostring(tonumber(
                     account:generate_one_time_keys(5 - keyCount))))
                 otks = json.decode(account:one_time_keys())
             end
             for id, key in pairs(otks.curve25519) do
                 one_time_keys['curve25519:'..id] = key
                 keyCount = keyCount + 1
             end


             local msg = {
                 device_keys = {
                     algorithms= { ALGO },
                     device_id = olmdata.device_id,
                     keys = {
                         ["ed25519:"..olmdata.device_id] = id_keys.ed25519,
                         ["curve25519:"..olmdata.device_id] = id_keys.curve25519
                     },
                     user_id = user_id,
                     --valid_after_ts = 1234567890123,-- FIXME,
                     --valid_until_ts = 2345678901234,--FIXME,
                 },
                 one_time_keys = one_time_keys
             }
             -- FIXME proper signing
             msg.device_keys.signatures = {
                 [user_id] = {
                     ["ed25519:"..olmdata.device_id] = account:sign(json.encode(msg.device_keys))
                 }
             }
             local data = urllib.urlencode{
                 access_token = SERVER.access_token
             }
             http('/keys/upload/'..olmdata.device_id..'?'..data, {
                 postfields = json.encode(msg)
             }, 'http_cb', 5*1000, nil, v2_api_ns)

             account:mark_keys_as_published()

         end
         olmdata.claim = function(user_id) -- Fetch one time keys
             if DEBUG then
                 perr('olm: Claiming '..tostring(user_id))
             end
             -- TODO take a list of ids for batch downloading
             local auth = urllib.urlencode{ access_token = SERVER.access_token }
             local device_ids = olmdata.device_keys[user_id]
             local data = {
                 one_time_keys = {}
             }
             for device_id, kd in pairs(device_ids) do
                 data.one_time_keys[user_id] = {
                     [device_id] = 'curve25519'
                }
             end
             http('/keys/claim?'..auth, {postfields=json.encode(data)}, 'http_cb', 30*1000, nil, v2_api_ns)
         end
         olmdata.create_session = function(user_id)
             perr('olm: creating session for user: '..user_id)
             for device_id, device_data in pairs(olmdata.device_keys[user_id] or {}) do
                 -- Frist try to unpickle session from filesystem
                 local session_filename = homedir..user_id..'.'..device_id..'.session.olm'
                 local fd, err = io.open(session_filename, 'rb')
                 if fd then
                     perr('olm: found saved session for user: '..user_id)
                     local pickled = fd:read'*all'
                     olmdata.sessions[user_id..':'..device_id] = pickled
                     fd:close()
                 else
                     perr('olm: saved new session for user: '..user_id)
                     local session = olm.Session.new()
                     local otk = olmdata.otks[user_id]
                     if not otk then
                         perr("olm: Missing OTK for user: "..user_id.." and device: "..device_id.."")
                     else
                         otk = otk[device_id]
                     end
                     local id_key = device_data.keys['curve25519:'..device_id]
                     if not id_key then
                         perr("olm: Missing key for user: "..user_id.." and device: "..device_id.."")
                     end
                     if id_key and otk then
                         session:create_outbound(olmdata.account, id_key, otk)
                         local session_id = session:session_id()
                         perr('Session ID:'..tostring(session_id))
                         local pickled = session:pickle(OLM_KEY)
                         olmdata.sessions[user_id..':'..device_id] = pickled
                         local fd, err = io.open(session_filename, 'wb')
                         if fd then
                             fd:write(pickled)
                             fd:close()
                         else
                             perr('olm: error saving session: '..tostring(err))
                         end
                     end
                     session:clear()
                 end
             end
         end
         server.olm = olmdata
         local fd = io.open(homedir..'account.olm', 'rb')
         local pickled = ''
         if fd then
             pickled = fd:read'*all'
             fd:close()
         end
         if pickled == '' then
             account:create()
             local ret, err = account:generate_one_time_keys(5)
             perr(err)
             olmdata.save()
         else
             local unpickle, err = account:unpickle(OLM_KEY, pickled)
             --account:create()
             --account:generate_one_time_keys(10)
             perr(err)
         end
         local identity = json.decode(account:identity_keys())
         -- TODO figure out what device id is supposed to be
         olmdata.device_id = identity.ed25519:match'%w*' -- problems with nonalfanum
         olmdata.device_key = identity.curve25519
         w.print('', 'matrix: Encryption loaded. To send encrypted messages in a room, use command /encrypt with a room as active current buffer')
         if DEBUG then
             dbg{olm={
                 'Loaded identity:',
                 json.decode(account:identity_keys())
             }}
         end

     else
        w.print('', SCRIPT_NAME .. ': Unable to load olm encryption library. Not enabling encryption. Please see documenation for how to enable.')
     end


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
        http('/login', {
            postfields = json.encode(post)
        }, 'http_cb', 5*1000) -- Set a short timeout so user can get more immidiate feedback
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
        timeout = 1000*POLL_INTERVAL,
        from = self.end_token
    })
    http('/events?'..data, nil, 'poll_cb', (POLL_INTERVAL+10)*1000)
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

function MatrixServer:Msg(room_id, body, msgtype)
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

        -- Run IRC modifiers (XXX: maybe run out1 also?
        body = w.hook_modifier_exec('irc_out1_PRIVMSG', '', body)

        if w.config_get_plugin('local_echo') == 'on'
                and not olmstatus then -- don't use local_echo when encrypting
            -- Generate local echo
            for _, r in pairs(SERVER.rooms) do
                if r.identifier == id then
                    if msgtype == 'm.text' then
                        w.print_date_tags(r.buffer, nil,
                            'notify_none,localecho,no_highlight', ("%s\t%s%s"):format(
                                r:formatNick(SERVER.user_id),
                                default_color,
                                body
                                )
                            )
                    elseif msgtype == 'm.emote' then
                        local prefix_c = wcolor'weechat.color.chat_prefix_action'
                        local prefix = wconf'weechat.look.prefix_action'
                        w.print_date_tags(r.buffer, nil,
                            'notify_none,localecho,irc_action,no_highlight', ("%s%s\t%s%s%s %s"):format(
                                prefix_c,
                                prefix,
                                w.color('chat_nick_self'),
                                r.users[SERVER.user_id],
                                default_color,
                                body
                                )
                            )
                    end
                end
            end
        end

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

        local api_event_function = 'm.room.message'

        -- Find the room
        local room
        for _, r in pairs(SERVER.rooms) do
            if r.identifier == id then
                room = r
                break
            end
        end
        if olmstatus and room.encrypted then
            api_event_function = 'm.room.encrypted'
            local olmd = SERVER.olm

            data.postfields.algorithm = ALGO
            data.postfields.sender_key = olmd.device_key
            data.postfields.ciphertexts = {}

            -- Count number of devices we are sending to
            local recipient_count = 0

            local room = SERVER.rooms[id]
            for user_id, _ in pairs(room.users) do
                local ciphertexts = {}
                local found_session = false
                for device_id, device_data in pairs(olmd.device_keys[user_id] or {}) do -- FIXME check for missing keys?
                    local pickled = olmd.sessions[user_id..':'..device_id]
                    if pickled then
                        found_session = true
                        local session = olm.Session.new()
                        session:unpickle(OLM_KEY, pickled)
                        local session_id = session:session_id()
                        perr('Session ID:'..tostring(session_id))
                        local message = data.postfields.body or ''
                        local message_type, encrypted_body = session:encrypt(message)
                        session:clear()
                        -- encrypt body
                        local ciphertext = {
                            [device_id] = {
                                ["type"] = tonumber(message_type),
                                body = encrypted_body
                            }
                        }
                        table.insert(ciphertexts, ciphertext)
                        recipient_count = recipient_count + 1
                    end
                end
                if found_session then
                    data.postfields.ciphertexts[user_id] = ciphertexts
                end
            end
            -- remove cleartext from original msg
            data.postfields.body = nil
            data.postfields.formatted_body = nil

            if recipient_count == 0 then
                perr('Aborted sending of encrypted message: could not find any valid recipients')
                return
            end
        end

        data.postfields = json.encode(data.postfields)

        http(('/rooms/%s/send/'..api_event_function..'?access_token=%s')
            :format(
              urllib.quote(id),
              urllib.quote(SERVER.access_token)
            ),
              data
            )
    end
end

function MatrixServer:emote(room_id, body)
    self:Msg(room_id, body, 'm.emote')
end

function MatrixServer:notice(room_id, body)
    self:Msg(room_id, body, 'm.notice')
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

function MatrixServer:Invite(room_id, user_id)
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
            SERVER:Msg(r_id, data)
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
    -- Encryption status of room
    room.encrypted = false
    -- We might not be a member yet
    local state_events = obj.state or {}
    for _, state in pairs(state_events) do
        if state['type'] == 'm.room.aliases' then
            local name = state['content']['aliases'][1] or ''
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

function Room:Msg(msg)
    SERVER:Msg(self.identifier, msg)
end

function Room:emote(msg)
    SERVER:emote(self.identifier, msg)
end

function Room:Notice(msg)
    SERVER:notice(self.identifier, msg)
end

function Room:SendTypingNotice()
    SERVER:SendTypingNotice(self.identifier)
end

function Room:create_buffer()
    --local buffer = w.buffer_search("", ("%s.%s"):format(self.server, self.name))
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

function Room:UpdateLine(id, message)
    local lines = w.hdata_pointer(w.hdata_get('buffer'), self.buffer, 'own_lines')
    if lines == '' then return end
    local line = w.hdata_pointer(w.hdata_get('lines'), lines, 'last_line')
    if line == '' then return end
    local hdata_line = w.hdata_get('line')
    local hdata_line_data = w.hdata_get('line_data')
    while #line > 0 do
        local needsupdate = false
        local data = w.hdata_pointer(hdata_line, line, 'data')
        local tags = {}
        local tag_count = w.hdata_integer(hdata_line_data, data, "tags_count")
        if tag_count > 0 then
            for i = 0, tag_count-1 do
                local tag = w.hdata_string(hdata_line_data, data, i .. "|tags_array")
                tags[#tags+1] = tag
                if tag:match(id) then
                    needsupdate = true
                end
            end
            if needsupdate then
                w.hdata_update(hdata_line_data, data, {
                    prefix = prefix,
                    message = message,
                    tags_array = table.concat(tags, ','),
                    })
                return true
            end
        end
        line = w.hdata_move(hdata_line, line, -1)
    end
    return false
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

    -- Add Event ID to each line so can use it later to match on for things
    -- like redactions and localecho, etc
    tag{chunk.event_id}

    if chunk['type'] == 'm.room.message' or chunk['type'] == 'm.room.encrypted' then
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

        if chunk['type'] == 'm.room.encrypted' then
            content.body = 'encrypted message, unable to decrypt'
            if olmstatus then
                -- Find our id
                local ciphertexts = content.ciphertexts or {}
                local ciphertext = ciphertexts[SERVER.user_id]
                if not ciphertext then
                    content.body = 'encrypted message, no ciphertext for our ID'
                else
                    -- Use first device
                    local devices = ciphertext
                    for _, devices in pairs(devices) do
                        for device, data in pairs(devices) do
                            if device == SERVER.olm.device_id then
                                local session = olm.Session.new()
                                session:create_inbound(SERVER.olm.account, data.body)
                                local decrypted, err = session:decrypt(0, data.body)
                                if err then
                                    content.body = "Decryption error: "..err
                                else
                                    content.body = decrypted
                                end
                                session:clear()
                                break
                            end
                        end
                    end
                end
            end
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
            local prefix = prefix_c .. prefix
            local data = ("%s\t%s"):format(prefix, body)
            if not backlog and is_self
                -- TODO better check, to work for multiple weechat clients
              and w.config_get_plugin('local_echo') == 'on'
              and not olmstatus then -- disable local echo for encryption
                -- We have already locally echoed this line
                return
            else
                return w.print_date_tags(self.buffer, time_int, tags(), data)
            end
        else
            -- Unknown content type, but if it contains an URL we will print
            -- URL and body
            local url = content['url']
            if url ~= nil then
                url = url:gsub('mxc://',
                    w.config_get_plugin('homeserver_url')
                    .. '_matrix/media/v1/download/')
                body = content['body'] .. ' ' .. url
            end
            dbg {
                warning='Warning: unknown/unhandled content type',
                event=content
            }
        end
        if not backlog and is_self
          -- TODO better check, to work for multiple weechat clients
          and w.config_get_plugin('local_echo') == 'on'
          and not olmstatus then -- disable local echo for encrypted messages
            -- We have already locally echoed this line
            return
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
                if not oldnick or oldnick == json.null then
                    oldnick = chunk.user_id
                else
                    if oldnick == name then
                        -- Maybe they changed their avatar or something else
                        -- that we don't care about (or multiple joins)
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
        elseif chunk['content']['membership'] == 'ban' then
            if chunktype == 'messages' then
                tag"irc_ban"
                local time_int = chunk['origin_server_ts']/1000
                local prefix_c = wcolor'weechat.color.chat_prefix_action'
                local prefix = wconf'weechat.look.prefix_action'
                local data = ("%s%s\t%s banned %s"):format(
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
    elseif chunk['type'] == 'm.room.redaction' then
        local redact_id = chunk.redacts
        perr('Redacting message ' .. redact_id)
        local result = self:UpdateLine(redact_id, w.color'darkgray'..'(redacted)')
        if not result then
            perr 'Could not find message to redact :('
        end
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

function Room:Invite(id)
    SERVER:Invite(self.identifier, id)
end

function Room:Encrypt()
    self.encrypted = true
    -- Download keys for all members
    self:Download_keys()
    -- Create sessions
    -- Pickle.
    -- Save
end
function Room:Download_keys()
    for id, name in pairs(self.users) do
        -- TODO enable batch downloading of keys here when synapse can handle it
        SERVER.olm.query({id})
    end
end

function poll(a,b)
    SERVER:poll()
    return w.WEECHAT_RC_OK
end

function polltimer_cb(a,b)
    local now = os.time()
    if (now - SERVER.polltime) > POLL_INTERVAL+10 then
        SERVER.polling = false
        SERVER:poll()
    end
    return w.WEECHAT_RC_OK
end

function otktimer_cb(a,b)
    SERVER.olm.check_server_keycount()
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

function leave_command_cb(data, current_buffer, args)
    return part_command_cb(data, current_buffer, args)
end

function me_command_cb(data, current_buffer, args)
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
        room:Invite(args)
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

function notice_command_cb(data, current_buffer, args)
    -- TODO sending from matrix buffer given a room name
    local room = SERVER:findRoom(current_buffer)
    if room then
        local _, msg = split_args(args)
        room:Notice(msg)
        return w.WEECHAT_RC_OK_EAT
    else
        return w.WEECHAT_RC_OK
    end
end

function msg_command_cb(data, current_buffer, args)
    local _, args = split_args(args)
    local mask, msg = split_args(args)
    local room
    -- WeeChat uses * as a mask for current buffer
    if mask == '*' then
        room = SERVER:findRoom(current_buffer)
    else
        for id, r in pairs(SERVER.rooms) do
            -- Send /msg to a ID
            if id == mask then
                room = r
                break
            elseif mask == r.name then
                room = r
                break
            end
        end
    end

    if room then
        room:Msg(msg)
        return w.WEECHAT_RC_OK_EAT
    else
        return w.WEECHAT_RC_OK
    end
end

function encrypt_command_cb(data, current_buffer, args)
    local room = SERVER:findRoom(current_buffer)
    if room then
        mprint('Enabling encryption for outgoing messages in room ' .. tostring(room.name))
        room:Encrypt()
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
    -- WeeChat closed our room
    local room = SERVER:findRoom(buffer)
    if room then
        room.buffer = nil
        perr('Room got closed: '..room.name)
        SERVER.rooms[room.identifier] = nil
        return w.WEECHAT_RC_OK
    end
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

if w.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE, SCRIPT_DESC, "matrix_unload", "UTF-8") then
    local settings = {
        homeserver_url= {'https://matrix.org/', 'Full URL including port to your homeserver or use default matrix.org'},
        user= {'', 'Your homeserver username'},
        password= {'', 'Your homeserver password'},
        backlog_lines= {'120', 'Number of lines to fetch from backlog upon connecting'},
        autojoin_on_invite = {'on', 'Automatically join rooms you are invited to'},
        typing_notices = {'on', 'Send typing notices when you type'},
        local_echo = {'on', 'Print lines locally instead of waiting for resturn from server'},
        debug = {'off', 'Print a lot of extra information to help with finding bugs and other problems.'}
        --olm_secret = {'', 'Password used to secure olm stores'},
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
    errprefix = wconf'weechat.look.prefix_error'
    errprefix_c = wcolor'weechat.color.chat_prefix_error'
    homedir = w.info_get('weechat_dir', '') .. '/'
    local commands = {
        'join', 'part', 'leave', 'me', 'topic', 'upload', 'query', 'list',
        'op', 'voice', 'deop', 'devoice', 'kick', 'create', 'invite', 'nick',
        'whois', 'notice', 'msg', 'encrypt'
    }
    for _, c in pairs(commands) do
        w.hook_command_run('/'..c, c..'_command_cb', '')
    end

    if w.config_get_plugin('typing_notices') == 'on' then
        w.hook_signal('input_text_changed', "typing_notification_cb", '')
    end

    if w.config_get_plugin('debug') == 'on' then
        DEBUG = true
    end

    weechat.hook_config('plugins.var.lua.matrix.debug', 'configuration_changed_cb', '')

    local cmds = {'help', 'connect', 'debug'}
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
