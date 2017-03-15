-- WeeChat Matrix.org Client
-- vim: expandtab:ts=4:sw=4:sts=4
-- luacheck: globals weechat command_help command_connect matrix_command_cb matrix_away_command_run_cb configuration_changed_cb real_http_cb matrix_unload http_cb upload_cb send buffer_input_cb poll polltimer_cb cleartyping otktimer_cb join_command_cb part_command_cb leave_command_cb me_command_cb topic_command_cb upload_command_cb query_command_cb create_command_cb createalias_command_cb invite_command_cb list_command_cb op_command_cb voice_command_cb devoice_command_cb kick_command_cb deop_command_cb nick_command_cb whois_command_cb notice_command_cb msg_command_cb encrypt_command_cb public_command_cb names_command_cb more_command_cb roominfo_command_cb name_command_cb closed_matrix_buffer_cb closed_matrix_room_cb typing_notification_cb buffer_switch_cb typing_bar_item_cb

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
 Giving people arbitrary power levels
 Lazyload messages instead of HUGE initialSync
 Dynamically fetch more messages in backlog when user reaches the
 oldest message using pgup
 Need a way to change room join rule
 Fix broken state after failed initial connect
 Fix parsing of multiple join messages
 Friendlier error message on bad user/password
 Parse some HTML and turn into color/bold/etc
 Support weechat.look.prefix_same_nick

]]

local json = require 'cjson' -- apt-get install lua-cjson
local olmstatus, olm = pcall(require, 'olm') -- LuaJIT olm FFI binding ln -s ~/olm/olm.lua /usr/local/share/lua/5.1
local w = weechat

local SCRIPT_NAME = "matrix"
local SCRIPT_AUTHOR = "xt <xt@xt.gg>"
local SCRIPT_VERSION = "3"
local SCRIPT_LICENSE = "MIT"
local SCRIPT_DESC = "Matrix.org chat plugin"
local SCRIPT_COMMAND = SCRIPT_NAME

local WEECHAT_VERSION

local SERVER
local STDOUT = {}
local OUT = {}
local BUFFER
local Room
local MatrixServer
local Olm
local DEBUG = false
-- How many seconds to timeout if nothing happened on the server. If something
-- happens before it will return sooner.
-- default Nginx proxy timeout is 60s, so we go slightly lower
local POLL_INTERVAL = 55

local default_color = w.color('default')
-- Cache error variables so we don't have to look them up for every error
-- message, a normal user will not change these ever anyway.
local errprefix
local errprefix_c

local HOMEDIR
local OLM_ALGORITHM = 'm.olm.v1.curve25519-aes-sha2'
local OLM_KEY = 'secr3t' -- TODO configurable using weechat sec data
local v2_api_ns = '_matrix/client/v2_alpha'

local function tprint(tbl, indent, out)
    if not indent then indent = 0 end
    if not out then out = BUFFER end
    for k, v in pairs(tbl) do
        local formatting = string.rep("  ", indent) .. k .. ": "
        if type(v) == "table" then
            w.print(out, formatting)
            tprint(v, indent+1, out)
        elseif type(v) == 'boolean' then
            w.print(out, formatting .. tostring(v))
        elseif type(v) == 'userdata' then
            w.print(out, formatting .. tostring(v))
        else
            w.print(out, formatting .. v)
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
        message = ("DEBUG\t%s"):format(tostring(message))
        mprint(BUFFER, message)
    end
end

local dtraceback = debug.traceback
-- luacheck: ignore debug
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

local function weechat_eval(text)
    if WEECHAT_VERSION >= 0x00040200 then
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

local function accesstoken_redact(str)
    return (str:gsub('access.*token=[0-9a-zA-Z%%]*', 'access_token=[redacted]'))
end

local transaction_id_counter = 0
local function get_next_transaction_id()
    transaction_id_counter = transaction_id_counter + 1
    return transaction_id_counter
end

--[[
-- Function for signing json, unused for now, we hand craft the required
-- signed json in the encryption function. But I think this function will be
-- needed in the future so leaving it here in a commented version
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
--]]

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
    -- TODO, support foreground and background?
    local ct = {'white','black','blue','green','red','maroon','purple',
        'orange','yellow','lightgreen','teal','cyan', 'lightblue',
        'fuchsia', 'gray', 'lightgray'}

    s = byte_to_tag(s, '\02', '<em>', '</em>')
    s = byte_to_tag(s, '\029', '<i>', '</i>')
    s = byte_to_tag(s, '\031', '<u>', '</u>')
    -- First do full color strings with reset.
    -- Iterate backwards to catch long colors before short
    for i=#ct,1,-1 do
        s = s:gsub(
            '\003'..tostring(i-1)..'(.-)\003',
            '<font color="'..ct[i]..'">%1</font>')
    end

    -- Then replace unmatch colors
    -- Iterate backwards to catch long colors before short
    for i=#ct,1,-1 do
        local c = ct[i]
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

local function irc_formatting_to_weechat_color(s)
    -- TODO, support foreground and background?
    -- - is atribute to remove formatting
    -- | is to keep formatting during color changes
    s = byte_to_tag(s, '\02', w.color'bold', w.color'-bold')
    s = byte_to_tag(s, '\029', w.color'italic', w.color'-italic')
    s = byte_to_tag(s, '\031', w.color'underline', w.color'-underline')
    -- backwards to catch long numbers before short
    for i=16,1,-1 do
        i = tostring(i)
        s = byte_to_tag(s, '\003'..i,
            w.color("|"..i), w.color("-"..i))
    end
    return s
end

function matrix_unload()
    w.print('', 'matrix: Unloading')
    -- Clear/free olm memory if loaded
    if olmstatus then
        w.print('', 'matrix: Saving olm state')
        SERVER.olm:save()
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
         local help_cmds = {args=args}
         if not help_cmds then
             w.print("", "Command not found: " .. args)
             return
         end
         for cmd, helptext in pairs(help_cmds) do
             w.print('', w.color("bold") .. cmd)
             w.print('', (helptext or 'No help text').strip())
             w.print('', '')
        end
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
        return command_connect(current_buffer)
    elseif args == 'debug' then
        if DEBUG then
            DEBUG = false
            w.print('', SCRIPT_NAME..': debugging messages disabled')
        else
            DEBUG = true
            w.print('', SCRIPT_NAME..': debugging messages enabled')
        end
    elseif args:match('^msg ') then
        local _
        _, args = split_args(args) -- remove cmd
        local roomarg, msg = split_args(args)
        local room
        for id, r in pairs(SERVER.rooms) do
            -- Send /msg to a ID
            if id == roomarg then
                room = r
                break
            elseif roomarg == r.name then
                room = r
                break
            elseif roomarg == r.roomname then
                room = r
                break
            end
        end

        if room then
            room:Msg(msg)
            return w.WEECHAT_RC_OK_EAT
        end
    else
        perr("Command not found: " .. args)
    end

    return w.WEECHAT_RC_OK
end

function matrix_away_command_run_cb(data, buffer, args)
    -- Callback for command /away -all
    local _
    _, args = split_args(args) -- remove cmd
    local msg
    _, msg = split_args(args)
    w.buffer_set(BUFFER, "localvar_set_away", msg)
    for id, room in pairs(SERVER.rooms) do
        if msg and msg ~= '' then
            w.buffer_set(room.buffer, "localvar_set_away", msg)
        else
            -- Delete takes empty string, and not nil
            w.buffer_set(room.buffer, "localvar_del_away", '')
        end
    end
    if msg and msg ~= '' then
        SERVER:SendPresence('unavailable', msg)
        mprint 'You have been marked as unavailable'
    else
        SERVER:SendPresence('online', nil)
        mprint 'You have been marked as online'
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
        api_ns = "_matrix/client/r0"
    end

    -- Add accept encoding by default if it's not already there
    if not post.accept_encoding then
        post.accept_encoding = 'application/json'
    end
    if not post.header then
        post.header = 1 -- Request http headers in the response
    end

    if not url:match'https?://' then
        local homeserver_url = w.config_get_plugin('homeserver_url')
        homeserver_url = homeserver_url .. api_ns
        url = homeserver_url .. url
    end

    if DEBUG then
        dbg{request={
            url=accesstoken_redact(url),
            post=post,extra=extra}
        }
    end
    w.hook_process_hashtable('url:' .. url, post, timeout, cb, extra)
end

local function parse_http_statusline(line)
    local httpversion, status_code, reason_phrase = line:match("^HTTP/(1%.[01]) (%d%d%d) (.-)\r?\n")
    if not httpversion then
        return
    end
    return httpversion, tonumber(status_code), reason_phrase
end

function real_http_cb(extra, command, rc, stdout, stderr)
    if DEBUG then
        dbg{reply={
            command=accesstoken_redact(command),
            extra=extra,rc=rc,stdout=stdout,stderr=stderr}
        }
    end

    if stderr and stderr ~= '' then
        mprint(('error: %s'):format(stderr))
        return w.WEECHAT_RC_OK
    end

    -- Because of a bug in WeeChat sometimes the stdout gets prepended by
    -- any number of BEL chars (hex 07). Let's have a nasty workaround and
    -- just replace them away.
    if WEECHAT_VERSION < 0x01030000 then -- fixed in 1.3
        stdout = (stdout:gsub('^\007*', ''))
    end

    if stdout ~= '' then
        if not STDOUT[command] then
            STDOUT[command] = {}
        end
        table.insert(STDOUT[command], stdout)
    end

    if tonumber(rc) >= 0 then
        stdout = table.concat(STDOUT[command] or {})
        STDOUT[command] = nil
        local httpversion, status_code, reason_phrase = parse_http_statusline(stdout)
        if not httpversion then
            perr(('Invalid http request: %s'):format(stdout))
            return w.WEECHAT_RC_OK
        end
        if status_code >= 500 then
            perr(('HTTP API returned error. Code: %s, reason: %s'):format(status_code, reason_phrase))
            return w.WEECHAT_RC_OK
        end
        -- Skip to data
        stdout = (stdout:match('.-\r?\n\r?\n(.*)'))
        -- Protected call in case of JSON errors
        local success, js = pcall(json.decode, stdout)
        if not success then
            mprint(('error\t%s during json load: %s'):format(js, stdout))
            return w.WEECHAT_RC_OK
        end
        if js['errcode'] or js['error'] then
            if command:find'login' then
                w.print('', ('matrix: Error code during login: %s, code: %s'):format(
                    js['error'], js['errcode']))
                w.print('', 'matrix: Please verify your username and password')
            else
                perr('API call returned error: '..js['error'] .. '('..tostring(js.errcode)..')')
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
            for _, chunk in ipairs(js['presence']) do
                myroom:ParseChunk(chunk, true, 'presence')
            end
            for _, chunk in ipairs(js['messages']['chunk']) do
                myroom:ParseChunk(chunk, true, 'messages')
            end
        elseif command:find'/sync' then
            SERVER.end_token = js.next_batch

            -- We have a new end token, which means we safely can release the
            -- poll lock
            SERVER.poll_lock = false

            local backlog = false
            local initial = false
            if extra == 'initial' then
                initial = true
                backlog = true
            end

            -- Start with setting the global presence variable on the server
            -- so when the nicks get added to the room they can get added to
            -- the correct nicklist group according to if they have presence
            -- or not
            for _, e in ipairs(js.presence.events) do
                SERVER:UpdatePresence(e)
            end
            for membership, rooms in pairs(js['rooms']) do
                -- If we left the room, simply ignore it
                if membership ~= 'leave' or (membership == 'leave' and (not backlog)) then
                    for identifier, room in pairs(rooms) do
                        -- Monkey patch it to look like v1 object
                        room.room_id = identifier
                        local myroom
                        if initial then
                            myroom = SERVER:addRoom(room)
                        else
                            myroom = SERVER.rooms[identifier]
                            -- Chunk for non-existing room
                            if not myroom then
                                myroom = SERVER:addRoom(room)
                                if not membership == 'invite' then
                                    perr('Event for unknown room')
                                end
                            end
                        end
                        -- First of all parse invite states.
                        local inv_states = room.invite_state
                        if inv_states then
                            local chunks = room.invite_state.events or {}
                            for _, chunk in ipairs(chunks) do
                                myroom:ParseChunk(chunk, backlog, 'states')
                            end
                        end
                        -- Parse states before messages so we can add nicks and stuff
                        -- before messages start appearing
                        local states = room.state
                        if states then
                            local chunks = room.state.events or {}
                            for _, chunk in ipairs(chunks) do
                                myroom:ParseChunk(chunk, backlog, 'states')
                            end
                        end
                        local timeline = room.timeline
                        if timeline then
                            -- Save the prev_batch on the initial message so we
                            -- know for later when we picked up the sync
                            if initial then
                                myroom.prev_batch = timeline.prev_batch
                            end
                            local chunks = timeline.events or {}
                            for _, chunk in ipairs(chunks) do
                                myroom:ParseChunk(chunk, backlog, 'messages')
                            end
                        end
                        local ephemeral = room.ephemeral
                        -- Ignore Ephemeral Events during initial sync
                        if (extra and extra ~= 'initial') and ephemeral then
                            local chunks = ephemeral.events or {}
                            for _, chunk in ipairs(chunks) do
                                myroom:ParseChunk(chunk, backlog, 'states')
                            end
                        end
                        if backlog then
                            -- All the state should be done. Try to get a good name for the room now.
                            myroom:SetName(myroom.identifier)
                        end
                    end
                end
            end
            -- Now we have created rooms and can go over the rooms and update
            -- the presence for each nick
            for _, e in pairs(js.presence.events) do
                SERVER:UpdatePresence(e)
            end
            if initial then
                SERVER:post_initial_sync()
            end
            SERVER:poll()
        elseif command:find'messages' then
            local identifier = extra
            local myroom = SERVER.rooms[identifier]
            myroom.prev_batch = js['end']
            -- Freeze buffer
            myroom:Freeze()
            -- Clear buffer
            myroom:Clear()
            -- We request backwards direction, so iterate backwards
            for i=#js.chunk,1,-1 do
                local chunk = js.chunk[i]
                myroom:ParseChunk(chunk, true, 'messages')
            end
            -- Thaw!
            myroom:Thaw()
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
            -- We store room_id in extra
            local room_id = extra
            SERVER:delRoom(room_id)
        elseif command:find'/keys/claim' then
            local count = 0
            for user_id, v in pairs(js.one_time_keys or {}) do
                for device_id, keys in pairs(v or {}) do
                    for key_id, key in pairs(keys or {}) do
                        SERVER.olm.otks[user_id..':'..device_id] = {[device_id]=key}
                        perr(('olm: Recieved OTK for user %s for device id %s'):format(user_id, device_id))
                        count = count + 1
                        SERVER.olm:create_session(user_id, device_id)
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
                    local device_key = device_data.keys['curve25519:'..device_id]
                    local sessions = SERVER.olm:get_sessions(device_key)
                    if #sessions == 0 then
                        perr('olm: Downloading otk for user '..k..', and device_id: '..device_id)
                        SERVER.olm:claim(k, device_id)
                    else
                        perr('olm: Reusing existing session for user '..k)
                    end
                end
            end
        elseif command:find'/keys/upload' then
            local key_count = 0
            local sensible_number_of_keys = 20
            for algo, count in pairs(js.one_time_key_counts) do
                key_count = count
                SERVER.olm.key_count = key_count
            end
            if DEBUG then
                perr('olm: Number of own OTKs uploaded to server: '..key_count)
            end
            -- TODO make endless loop prevention in case of server error
            if key_count < sensible_number_of_keys then
                SERVER.olm:upload_keys()
            end
        elseif command:find'upload' then
            -- We store room_id in extra
            local room_id = extra
            if js.content_uri then
                SERVER:Msg(room_id, js.content_uri)
            end
        -- luacheck: ignore 542
        elseif command:find'/typing/' then
            -- either it errs or it is empty
        elseif command:find'/state/' then
            -- TODO errorcode: M_FORBIDDEN
            -- either it errs or it is empty
            --dbg({state= js})
        elseif command:find'/send/' then
            -- XXX Errorhandling
            -- TODO save event id to use for localecho
            local event_id = js.event_id
            local room_id = extra
            -- When using relay client, WeeChat doesn't get any buffer_switch
            -- signals, and thus cannot know when the relay client reads any
            -- messages. https://github.com/weechat/weechat/issues/180
            -- As a better than nothing approach we send read receipt when
            -- user sends a message, since most likely the user has read
            -- messages in that room if sending messages to it.
            SERVER:SendReadReceipt(room_id, event_id)
        elseif command:find'createRoom' then
            -- We get join events, so we don't have to do anything
        elseif command:find'/publicRooms' then
            mprint 'Public rooms:'
            mprint '\tUsers\tName\tTopic\tAliases'
            table.sort(js.chunk, function(a, b)
                return a.num_joined_members > b.num_joined_members
            end)
            for _, r in ipairs(js.chunk) do
                local name = ''
                if r.name and r.name ~= json.null then
                    name = r.name:gsub('\n', '')
                end
                local topic = ''
                if r.topic and r.topic ~= json.null then
                    topic = r.topic:gsub('\n', '')
                end
                mprint(('%s %s %s %s')
                    :format(
                        r.num_joined_members or '',
                        name or '',
                        topic or '',
                        table.concat(r.aliases or {}, ', ')))
            end
        -- luacheck: ignore 542
        elseif command:find'/invite' then
        elseif command:find'receipt' then
            -- we don't care about receipts for now
        elseif command:find'directory/room' then
            --- XXX: parse result
            mprint 'Created new alias for room'
        elseif command:match'presence/.*/status' then
            -- Return of SendPresence which we don't have to handle because
            -- it will be sent back to us as an event
        else
            dbg{['error'] = {msg='Unknown command in http cb', command=command,
                js=js}}
        end
    end

    if tonumber(rc) == -2 then -- -2 == WEECHAT_HOOK_PROCESS_ERROR
        perr(('Call to API errored in command %s, maybe timeout?'):format(
            accesstoken_redact(command)))
        -- Empty cache in case of errors
        if STDOUT[command] then
            STDOUT[command] = nil
        end
        -- Release poll lock in case of errors
        SERVER.poll_lock = false
    end

    return w.WEECHAT_RC_OK
end

function http_cb(data, command, rc, stdout, stderr)
    local status, result = pcall(real_http_cb, data, command, rc, stdout, stderr)
    if not status then
        perr('Error in http_cb: ' .. tostring(result))
        perr(debug.traceback())
    end
    return result
end

function upload_cb(data, command, rc, stdout, stderr)
    local success, js = pcall(json.decode, stdout)
    if not success then
        mprint(('error\t%s when getting uploaded URI: %s'):format(js, stdout))
        return w.WEECHAT_RC_OK
    end

    local uri = js.content_uri
    if not uri then
        mprint(('error\tNo content_uri after upload. Stdout: %s, stderr: %s'):format(stdout, stderr))
        return w.WEECHAT_RC_OK
    end

    local room_id = data
    local body = 'Image'
    local msgtype = 'm.image'
    SERVER:Msg(room_id, body, msgtype, uri)

    return w.WEECHAT_RC_OK
end

Olm = {}
Olm.__index = Olm
Olm.create = function()
    local olmdata = {}
    setmetatable(olmdata, Olm)
    if not olmstatus then
        w.print('', SCRIPT_NAME .. ': Unable to load olm encryption library. Not enabling encryption. Please see documentation (README.md) for information on how to enable.')
        return
    end

    local account = olm.Account.new()
    olmdata.account = account
    olmdata.sessions = {}
    olmdata.device_keys = {}
    olmdata.otks = {}
    -- Try to read account from filesystem, if not generate a new account
    local fd = io.open(HOMEDIR..'account.olm', 'rb')
    local pickled = ''
    if fd then
        pickled = fd:read'*all'
        fd:close()
    end
    if pickled == '' then
        account:create()
        local _, err = account:generate_one_time_keys(5)
        perr(err)
    else
        local _, err = account:unpickle(OLM_KEY, pickled)
        perr(err)
    end
    local identity = json.decode(account:identity_keys())
    -- TODO figure out what device id is supposed to be
    olmdata.device_id = identity.ed25519:match'%w*' -- problems with nonalfanum
    olmdata.device_key = identity.curve25519
    w.print('', 'matrix: Encryption loaded. To send encrypted messages in a room, use command /encrypt on with a room as active current buffer')
    if DEBUG then
        dbg{olm={
            'Loaded identity:',
            json.decode(account:identity_keys())
        }}
    end
    return olmdata
end

function Olm:save()
    -- Save account and every pickled session
    local pickle, err = self.account:pickle(OLM_KEY)
    perr(err)
    local fd = io.open(HOMEDIR..'account.olm', 'wb')
    fd:write(pickle)
    fd:close()
    --for key, pickled in pairs(self.sessions) do
    --    local user_id, device_id = key:match('(.*):(.+)')
    --    self.write_session_to_file(pickled, user_id, device_id)
    --end
end

function Olm:query(user_ids) -- Query keys from other user_id
    if DEBUG then
        perr('olm: querying user_ids')
        tprint(user_ids)
    end
    local auth = urllib.urlencode{access_token=SERVER.access_token}
    local data = {
        device_keys = {}
    }
    for _, uid in pairs(user_ids) do
        data.device_keys[uid] = {false}
    end
    http('/keys/query/?'..auth,
        {postfields=json.encode(data)},
        'http_cb',
        5*1000, nil,
        v2_api_ns
    )
end

function Olm:check_server_keycount()
    local data = urllib.urlencode{access_token=SERVER.access_token}
    http('/keys/upload/'..self.device_id..'?'..data,
        {},
        'http_cb', 5*1000, nil, v2_api_ns
    )
end

function Olm:upload_keys()
    if DEBUG then
        perr('olm: Uploading keys')
    end
    local id_keys = json.decode(self.account:identity_keys())
    local user_id = SERVER.user_id
    local one_time_keys = {}
    local otks = json.decode(self.account:one_time_keys())
    local keyCount = 0
    for id, k in pairs(otks.curve25519) do
        keyCount = keyCount + 1
    end
    perr('olm: keycount: '..tostring(keyCount))
    if keyCount < 5 then -- try to always have 5 keys
        perr('olm: newly generated keys: '..tostring(tonumber(
        self.account:generate_one_time_keys(5 - keyCount))))
        otks = json.decode(self.account:one_time_keys())
    end

    for id, key in pairs(otks.curve25519) do
        one_time_keys['curve25519:'..id] = key
        keyCount = keyCount + 1
    end

    -- Construct JSON manually so it's ready for signing
    local keys_json = '{"algorithms":["' .. OLM_ALGORITHM .. '"]'
    .. ',"device_id":"' .. self.device_id .. '"'
    .. ',"keys":'
    .. '{"ed25519:' .. self.device_id .. '":"'
    .. id_keys.ed25519
    .. '","curve25519:' .. self.device_id .. '":"'
    .. id_keys.curve25519
    .. '"}'
    .. ',"user_id":"' .. user_id
    .. '"}'

    local success, key_data = pcall(json.decode, keys_json)
    -- TODO save key data to device_keys so we don't have to download
    -- our own keys from the servers?
    if not success then
        perr(('olm: upload_keys: %s when converting to json: %s')
        :format(key_data, keys_json))
    end

    local msg = {
        device_keys = key_data,
        one_time_keys = one_time_keys
    }
    msg.device_keys.signatures = {
        [user_id] = {
            ["ed25519:"..self.device_id] = self.account:sign(keys_json)
        }
    }
    local data = urllib.urlencode{
        access_token = SERVER.access_token
    }
    http('/keys/upload/'..self.device_id..'?'..data, {
        postfields = json.encode(msg)
    }, 'http_cb', 5*1000, nil, v2_api_ns)

    self.account:mark_keys_as_published()

end

function Olm:claim(user_id, device_id) -- Fetch one time keys
    if DEBUG then
        perr(('olm: Claiming OTK for user: %s and device: %s'):format(user_id, device_id))
    end
    -- TODO take a list of ids for batch downloading
    local auth = urllib.urlencode{ access_token = SERVER.access_token }
    local data = {
        one_time_keys = {
            [user_id] = {
                [device_id] = 'curve25519'
            }
        }
    }
    http('/keys/claim?'..auth,
        {postfields=json.encode(data)},
        'http_cb', 30*1000, nil, v2_api_ns
    )
end

function Olm:create_session(user_id, device_id)
    perr(('olm: creating session for user: %s, and device: %s'):format(user_id, device_id))
    local device_data = self.device_keys[user_id][device_id]
    if not device_data then
        perr(('olm: missing device data for user: %s, and device: %s'):format(user_id, device_id))
        return
    end
    local device_key = device_data.keys['curve25519:'..device_id]
    if not device_key then
        perr("olm: Missing key for user: "..user_id.." and device: "..device_id.."")
        return
    end
    local sessions = self:get_sessions(device_key)
    if not sessions[device_key] then
        perr(('olm: creating NEW session for: %s, and device: %s'):format(user_id, device_id))
        local session = olm.Session.new()
        local otk = self.otks[user_id..':'..device_id]
        if not otk then
            perr("olm: Missing OTK for user: "..user_id.." and device: "..device_id.."")
        else
            otk = otk[device_id]
        end
        if otk then
            session:create_outbound(self.account, device_key, otk)
            local session_id = session:session_id()
            perr('olm: Session ID:'..tostring(session_id))
            self:store_session(device_key, session)
        end
        session:clear()
    end
end

function Olm:get_sessions(device_key)
    if DEBUG then
        perr("olm: get_sessions: device: "..device_key.."")
    end
    local sessions = self.sessions[device_key]
    if not sessions then
        sessions = self:read_session(device_key)
    end
    return sessions
end

function Olm:read_session(device_key)
    local session_filename = HOMEDIR..device_key..'.session.olm'
    local fd, err = io.open(session_filename, 'rb')
    if fd then
        perr(('olm: reading saved session device: %s'):format(device_key))
        local sessions = fd:read'*all'
        sessions = json.decode(sessions)
        self.sessions[device_key] = sessions
        fd:close()
        return sessions
    else
        perr(('olm: Error: %s, reading saved session device: %s'):format(err, device_key))
    end
    return {}
end

function Olm:store_session(device_key, session)
    local session_id = session:session_id()
    if DEBUG then
        perr("olm: store_session: device: "..device_key..", Session ID: "..session_id)
    end
    local sessions = self.sessions[device_key] or {}
    local pickled = session:pickle(OLM_KEY)
    sessions[session_id] = pickled
    self.sessions[device_key] = sessions
    self:write_session_to_file(sessions, device_key)
end

function Olm:write_session_to_file(sessions, device_key)
    local session_filename = HOMEDIR..device_key..'.session.olm'
    local fd, err = io.open(session_filename, 'wb')
    if fd then
        fd:write(json.encode(sessions))
        fd:close()
    else
        perr('olm: error saving session: '..tostring(err))
    end
end

MatrixServer = {}
MatrixServer.__index = MatrixServer

MatrixServer.create = function()
     local server = {}
     setmetatable(server, MatrixServer)
     server.nick = nil
     server.connecting = false
     server.connected = false
     server.rooms = {}
     -- Store user presences here since they are not local to the rooms
     server.presence = {}
     server.end_token = 'END'
     server.typing_time = os.time()
     if w.config_get_plugin('presence_filter') ~= 'on' then
         server.typingtimer = w.hook_timer(10*1000, 0, 0, "cleartyping", "")
     end

     -- Use a lock to prevent multiple simul poll with same end token, which
     -- could lead to duplicate messages
     server.poll_lock = false
     server.olm = Olm.create()
     if server.olm then -- might not be available
         -- Run save so we do not lose state. Create might create new account,
         -- new keys, etc.
         server.olm:save()
     end
     return server
end

function MatrixServer:UpdatePresence(c)
    local user_id = c.sender or c.content.user_id
    self.presence[user_id] = c.content.presence
    for id, room in pairs(self.rooms) do
        room:UpdatePresence(c.sender, c.content.presence)
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
    BUFFER = w.buffer_new(SCRIPT_NAME, "", "", "closed_matrix_buffer_cb", "")
    w.buffer_set(BUFFER, "short_name", SCRIPT_NAME)
    w.buffer_set(BUFFER, "name", SCRIPT_NAME)
    w.buffer_set(BUFFER, "localvar_set_type", "server")
    w.buffer_set(BUFFER, "localvar_set_server", SCRIPT_NAME)
    w.buffer_set(BUFFER, "title", ("Matrix: %s"):format(
        w.config_get_plugin'homeserver_url'))
    if w.config_string(w.config_get('irc.look.server_buffer')) == 'merge_with_core' then
        w.buffer_merge(BUFFER, w.buffer_search_main())
    end
    w.buffer_set(BUFFER, "display", "auto")
    local data = urllib.urlencode({
        access_token = self.access_token,
        timeout = 1000*POLL_INTERVAL,
        full_state = 'true',
        filter = json.encode({ -- timeline filter
            room = {
                timeline = {
                    limit = tonumber(w.config_get_plugin('backlog_lines'))
                }
            },
            presence = {
                not_types = {'*'}, -- dont want presence
            }
        })
    })
    local extra = 'initial'
    -- New v2 sync API is slow. Until we can easily ignore archived rooms
    -- let's increase the timer for the initial login
    local login_timer = 60*5*1000
    http('/sync?'..data, nil, 'http_cb', login_timer, extra)
end

function MatrixServer:post_initial_sync()
    -- Timer used in cased of errors to restart the polling cycle
    -- During normal operation the polling should re-invoke itself
    SERVER.polltimer = w.hook_timer(POLL_INTERVAL*1000, 0, 0, "polltimer_cb", "")
    if olmstatus then
        -- timer that checks number of otks available on the server
        SERVER.otktimer = w.hook_timer(5*60*1000, 0, 0, "otktimer_cb", "")
        SERVER.olm:query{SERVER.user_id}
        --SERVER.olm.upload_keys()
        SERVER.olm:check_server_keycount()
    end
end

function MatrixServer:getMessages(room_id, dir, from, limit)
    if not dir then dir = 'b' end
    if not from then from = 'END' end
    if not limit then limit = w.config_get_plugin('backlog_lines') end
    local data = urllib.urlencode({
        access_token = self.access_token,
        dir = dir,
        from = from,
        limit = limit,
    })
    http(('/rooms/%s/messages?%s')
        :format(urllib.quote(room_id), data), nil, nil, nil, room_id)
end

function MatrixServer:Join(room)
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
    http(('/rooms/%s/leave?%s'):format(id, data), {postfields = "{}"},
        'http_cb', 10000, room.identifier)
end

function MatrixServer:poll()
    if self.connected == false then
        return
    end
    if self.poll_lock then
        return
    end
    self.poll_lock = true
    self.polltime = os.time()
    local filter = {}
    if w.config_get_plugin('presence_filter') == 'on' then
        filter = { -- timeline filter
            presence = {
                not_types = {'*'}, -- dont want presence
            },
            room = {
                ephemeral = {
                    not_types = {'*'}, -- dont want read receipt and typing notices
                }
            }
        }
    end
    local data = urllib.urlencode({
        access_token = self.access_token,
        timeout = 1000*POLL_INTERVAL,
        full_state = 'false',
        filter = json.encode(filter),
        since = self.end_token
    })
    http('/sync?'..data, nil, 'http_cb', (POLL_INTERVAL+10)*1000)
end

function MatrixServer:addRoom(room)
    -- Just in case, we check for duplicates here
    if self.rooms[room['room_id']] then
        return self.rooms[room['room_id']]
    end
    local myroom = Room.create(room)
    myroom:create_buffer()
    self.rooms[room['room_id']] = myroom
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

function MatrixServer:SendReadReceipt(room_id, event_id)
    -- TODO: prevent sending multiple identical read receipts
    local r_type = 'm.read'
    local auth = urllib.urlencode{access_token=self.access_token}
    room_id = urllib.quote(room_id)
    event_id = urllib.quote(event_id)
    local url = '/rooms/'..room_id..'/receipt/'..r_type..'/'..event_id..'?'..auth
    http(url,
      {customrequest = 'POST'},
      'http_cb',
      5*1000
    )
end

function MatrixServer:Msg(room_id, body, msgtype, url)
    -- check if there's an outgoing message timer already
    self:ClearSendTimer()

    if not msgtype then
        msgtype = 'm.text'
    end

    if not OUT[room_id] then
        OUT[room_id] = {}
    end
    -- Add message to outgoing queue of messages for this room
    table.insert(OUT[room_id], {msgtype, body, url})

    self:StartSendTimer()
end

function MatrixServer:StartSendTimer()
    local send_delay = 50 -- Wait this long for paste detection
    self.sendtimer = w.hook_timer(send_delay, 0, 1, "send", "")
end

function MatrixServer:ClearSendTimer()
    -- Clear timer if it exists
    if self.sendtimer then
        w.unhook(self.sendtimer)
    end
    self.sendtimer = nil
end

function send(cbdata, calls)
    SERVER:ClearSendTimer()
    -- Find the room
    local room

    for id, msgs in pairs(OUT) do
        -- Clear message
        OUT[id] = nil
        local body = {}
        local htmlbody = {}
        local msgtype
        local url

        local ishtml = false

        for _, r in pairs(SERVER.rooms) do
            if r.identifier == id then
                room = r
                break
            end
        end

        for _, msg in pairs(msgs) do
            -- last msgtype will override any other for simplicity's sake
            msgtype = msg[1]
            local html = irc_formatting_to_html(msg[2])
            if html ~= msg[2] then
                ishtml = true
            end
            table.insert(htmlbody, html )
            table.insert(body, msg[2] )
            if msg[3] then -- Primarily image upload
                url = msg[3]
            end
        end
        body = table.concat(body, '\n')

        -- Run IRC modifiers (XXX: maybe run out1 also?
        body = w.hook_modifier_exec('irc_out1_PRIVMSG', '', body)

        if w.config_get_plugin('local_echo') == 'on' or
            room.encrypted then
            -- Generate local echo
            local color = default_color
            if msgtype == 'm.text' then
                --- XXX: no localecho for encrypted messages?
                local tags = 'notify_none,localecho,no_highlight'
                if room.encrypted then
                    tags = tags .. ',no_log'
                    color = w.color(w.config_get_plugin(
                        'encrypted_message_color'))
                end
                w.print_date_tags(room.buffer, nil,
                    tags, ("%s\t%s%s"):format(
                        room:formatNick(SERVER.user_id),
                        color,
                        irc_formatting_to_weechat_color(body)
                        )
                    )
            elseif msgtype == 'm.emote' then
                local prefix_c = wcolor'weechat.color.chat_prefix_action'
                local prefix = wconf'weechat.look.prefix_action'
                local tags = 'notify_none,localecho,irc_action,no_highlight'
                if room.encrypted then
                    tags = tags .. ',no_log'
                    color = w.color(w.config_get_plugin(
                        'encrypted_message_color'))
                end
                w.print_date_tags(room.buffer, nil,
                    tags, ("%s%s\t%s%s%s %s"):format(
                        prefix_c,
                        prefix,
                        w.color('chat_nick_self'),
                        room.users[SERVER.user_id],
                        color,
                        irc_formatting_to_weechat_color(body)
                        )
                    )
            end
        end

        local data = {
            postfields = {
                msgtype = msgtype,
                body = body,
                url = url,
        }}

        if ishtml then
            htmlbody = table.concat(htmlbody, '\n')
            data.postfields.body = strip_irc_formatting(body)
            data.postfields.format = 'org.matrix.custom.html'
            data.postfields.formatted_body = htmlbody
        end

        local api_event_function = 'm.room.message'

        if olmstatus and room.encrypted then
            api_event_function = 'm.room.encrypted'
            local olmd = SERVER.olm

            data.postfields.algorithm = OLM_ALGORITHM
            data.postfields.sender_key = olmd.device_key
            data.postfields.ciphertext = {}

            -- Count number of devices we are sending to
            local recipient_count = 0

            for user_id, _ in pairs(room.users) do
                for device_id, device_data in pairs(olmd.device_keys[user_id] or {}) do -- FIXME check for missing keys?

                    local device_key
                    -- TODO save this better somehow?
                    for key_id, key_data in pairs(device_data.keys) do
                        if key_id:match('^curve25519') then
                            device_key = key_data
                        end
                    end
                    local sessions = olmd:get_sessions(device_key)
                    -- Use the session with the lowest ID
                    -- TODO: figure out how to pick session better?
                    table.sort(sessions)
                    local pickled = next(sessions)
                    if pickled then
                        local session = olm.Session.new()
                        session:unpickle(OLM_KEY, pickled)
                        local session_id = session:session_id()
                        perr(('Session ID: %s, user_id: %s, device_id: %s'):
                            format(session_id, user_id, device_id))
                        local payload = {
                            room_id = room.identifier,
                            ['type'] = "m.room.message",
                            fingerprint = "", -- TODO: Olm:sha256 participants
                            sender_device = olmd.device_id,
                            content = {
                                msgtype = msgtype,
                                body = data.postfields.body or '',
                                url = url
                            }
                        }
                        -- encrypt body
                        local mtype, e_body = session:encrypt(json.encode(payload))
                        local ciphertext = {
                            ["type"] = mtype,
                            body = e_body
                        }
                        data.postfields.ciphertext[device_key] = ciphertext
                        recipient_count = recipient_count + 1

                        -- Save session
                        olmd:store_session(device_key, session)
                        session:clear()
                    end
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
        data.customrequest = 'PUT'

        http(('/rooms/%s/send/%s/%s?access_token=%s')
            :format(
              urllib.quote(id),
              api_event_function,
              get_next_transaction_id(),
              urllib.quote(SERVER.access_token)
            ),
            data,
            nil,
            nil,
            id -- send room id to extra
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

function MatrixServer:SendPresence(p, status_msg)
    -- One of: ["online", "offline", "unavailable", "free_for_chat"]
    local data = {
        presence = p,
        status_msg = status_msg
    }
    http(('/presence/%s/status?access_token=%s')
        :format(
          urllib.quote(self.user_id),
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

function MatrixServer:Upload(room_id, filename)
    local content_type = 'image/jpeg'
    if filename:match'%.[Pp][nN][gG]$' then
        content_type = 'image/png'
    end
    local url = w.config_get_plugin('homeserver_url') ..
        ('_matrix/media/r0/upload?access_token=%s')
        :format( urllib.quote(SERVER.access_token) )
    w.hook_process_hashtable('/usr/bin/curl', {
        arg1 = '--data-binary', -- no encoding of data
        arg2 = '@'..filename, -- @means curl will load the filename
        arg3 = '-XPOST', -- HTTP POST method
        arg4 = '-H', -- header
        arg5 = 'Content-Type: '..content_type,
        arg6 = '-s', -- silent
        arg7 = url,
    }, 30*1000, 'upload_cb', room_id)
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

function MatrixServer:CreateRoomAlias(room_id, alias)
    local data = {room_id = room_id}
    alias = urllib.quote(alias)
    http(('/directory/room/%s?access_token=%s')
            :format(alias, urllib.quote(self.access_token)),
        {customrequest = 'PUT',
         postfields = json.encode(data),
    })
end

function MatrixServer:ListRooms(arg)
    local apipart = ('/publicRooms?access_token=%s'):format(urllib.quote(self.access_token))
    if arg then
        local url = 'https://' .. arg .. "/_matrix/client/r0"
        http(url..apipart)
    else
        http(apipart)
    end
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
            data = data:gsub('^//', '/')
            SERVER:Msg(r_id, data)
            break
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
    local _, server = room.identifier:match('^(.*):(.+)$')
    room.server = server
    room.member_count = 0
    -- Cache users for presence/nicklist
    room.users = {}
    -- Table of ids currently typing
    room.typing_ids = {}
    -- Cache the rooms power levels state
    room.power_levels = {users={}, users_default=0}
    -- Encryption status of room
    room.encrypted = false
    room.visibility = 'public'
    room.join_rule = nil
    room.roomname = nil -- m.room.name
    room.aliases = nil -- aliases
    room.canonical_alias = nil

    -- We might not be a member yet
    local state_events = obj.state or {}
    for _, state in ipairs(state_events) do
        if state['type'] == 'm.room.aliases' then
            local name = state.content.aliases[1]
            if name then
                room.name, _ = name:match('(.+):(.+)')
            end
        end
    end
    if not room.name then
        room.name = room.identifier
    end
    if not room.server then
        room.server = 'matrix'
    end

    room.visibility = obj.visibility
    if not obj['visibility'] then
        room.visibility = 'public'
    end

    return room
end

function Room:SetName(name)
    if not name or name == '' or name == json.null then
        return
    end
    -- override hierarchy
    if self.roomname and self.roomname ~= '' then
        name = self.roomname
    elseif self.canonical_alias then
        name = self.canonical_alias
        local short_name, _ = self.canonical_alias:match('^(.-):(.+)$')
        if short_name then
            name = short_name
        end
    elseif self.aliases then
        local alias = self.aliases[1]
        if name then
            local _
            name, _ = alias:match('(.+):(.+)')
        end
    else
        -- NO names. Set dynamic name based on members
        local new = {}
        for id, nick in pairs(self.users) do
            -- Set the name to the other party
            if id ~= SERVER.user_id then
                new[#new+1] = nick
            end
        end
        name = table.concat(new, ',')
    end

    if not name or name == '' or name == json.null then
        return
    end

    -- Check for dupe
    local buffer_name = w.buffer_get_string(self.buffer, 'name')
    if buffer_name == name then
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

function Room:Topic(topic)
    SERVER:state(self.identifier, 'm.room.topic', {topic=topic})
end

function Room:Name(name)
    SERVER:state(self.identifier, 'm.room.name', {name=name})
end

function Room:public()
    SERVER:state(self.identifier, 'm.room.join_rules', {join_rule='public'})
end

function Room:Upload(filename)
    SERVER:Upload(self.identifier, filename)
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
    -- Needs to correspond with return values from Room:GetNickGroup()
    -- We will use 5 nick groups:
    -- 1: Ops
    -- 2: Half-ops
    -- 3: Voice
    -- 4: People with presence
    -- 5: People without presence
    self.nicklist_groups = {
        -- Emulate OPs
        w.nicklist_add_group(self.buffer,
            '', "000|o", "weechat.color.nicklist_group", 1),
        w.nicklist_add_group(self.buffer,
            '', "001|h", "weechat.color.nicklist_group", 1),
        -- Emulate half-op
        w.nicklist_add_group(self.buffer,
            '', "002|v", "weechat.color.nicklist_group", 1),
        -- Defined in weechat's irc-nick.h
        w.nicklist_add_group(self.buffer,
            '', "998|...", "weechat.color.nicklist_group", 1),
        w.nicklist_add_group(self.buffer,
            '', "999|...", "weechat.color.nicklist_group", 1),
    }
    w.buffer_set(self.buffer, "nicklist", "1")
    -- Set to 1 for easier debugging of nick groups
    w.buffer_set(self.buffer, "nicklist_display_groups", "0")
    w.buffer_set(self.buffer, "localvar_set_server", self.server)
    w.buffer_set(self.buffer, "localvar_set_roomid", self.identifier)
    self:SetName(self.name)
    if self.membership == 'invite' then
        self:addNick(self.inviter)
        if w.config_get_plugin('autojoin_on_invite') ~= 'on' then
            w.print_date_tags(
                self.buffer,
                nil,
                'notify_message',
                ('You have been invited to join room %s by %s. Type /join in this buffer to join.')
                    :format(
                      self.name,
                      self.inviter,
                      self.identifier)
            )
        end
    end
end

function Room:Freeze()
    -- Function that saves all the lines in a buffer in a cache to be thawed
    -- later. Used to redraw buffer when user requests more lines. Since
    -- WeeChat can only render lines in order this is the workaround
    local freezer = {}
    local lines = w.hdata_pointer(w.hdata_get('buffer'), self.buffer, 'own_lines')
    if lines == '' then return end
    -- Start at top
    local line = w.hdata_pointer(w.hdata_get('lines'), lines, 'first_line')
    if line == '' then return end
    local hdata_line = w.hdata_get('line')
    local hdata_line_data = w.hdata_get('line_data')
    while #line > 0 do
        local data = w.hdata_pointer(hdata_line, line, 'data')
        local tags = {}
        local tag_count = w.hdata_integer(hdata_line_data, data, "tags_count")
        if tag_count > 0 then
            for i = 0, tag_count-1 do
                local tag = w.hdata_string(hdata_line_data, data, i .. "|tags_array")
                -- Skip notify tags since this is backlog
                if not tag:match'^notify' then
                    tags[#tags+1] = tag
                end
            end
        end
        tags[#tags+1] = 'no_log'
        freezer[#freezer+1] = {
            time = w.hdata_integer(hdata_line_data, data, 'time'),
            tags = tags,
            prefix = w.hdata_string(hdata_line_data, data, 'prefix'),
            message = w.hdata_string(hdata_line_data, data, 'message'),
        }
        -- Move forward since we start at top
        line = w.hdata_move(hdata_line, line, 1)
    end
    self.freezer = freezer
end

function Room:Thaw()
    for _,l in ipairs(self.freezer) do
        w.print_date_tags(
            self.buffer,
            l.time,
            table.concat(l.tags, ','),
            l.prefix .. '\t' .. l.message
        )
    end
    -- Clear old data
    self.freezer = nil
end

function Room:Clear()
    w.buffer_clear(self.buffer)
end

function Room:destroy()
    w.buffer_close(self.buffer)
end

function Room:_nickListChanged()
    -- Check the user count, if it's 2 or less then we decide this buffer
    -- is a "private" one like IRC's query type
    if self.member_count == 3 then
        w.buffer_set(self.buffer, "localvar_set_type", 'channel')
        self.buffer_type = 'channel'
    elseif self.member_count == 2 then
        -- At the point where we reach two nicks, set the buffer name to be
        -- the display name of the other guy that is not our self since it's
        -- in effect a query, but the matrix protocol doesn't have such
        -- a concept
        w.buffer_set(self.buffer, "localvar_set_type", 'private')
        self.buffer_type = 'query'
    elseif self.member_count == 1 then
        if not self.roomname and not self.aliases then
            -- Set the name to ourselves
            self:SetName(self.users[SERVER.user_id])
        end
    end
end

function Room:addNick(user_id, displayname)
    local newnick = false
    -- Sanitize displaynames a bit
    if not displayname
        or displayname == json.null
        or displayname == ''
        or displayname:match'^%s+$' then
        displayname = user_id:match('@(.*):.+')
    end
    if not self.users[user_id] then
        self.member_count = self.member_count + 1
        newnick = true
    end

    if self.users[user_id] ~= displayname then
        self.users[user_id] = displayname
    end

    local nick_c = self:GetPresenceNickColor(user_id, SERVER.presence[user_id])
    -- Check if this is ourselves
    if user_id == SERVER.user_id then
        w.buffer_set(self.buffer, "highlight_words", displayname)
        w.buffer_set(self.buffer, "localvar_set_nick", displayname)
    end

    local ngroup, nprefix, nprefix_color = self:GetNickGroup(user_id)
    -- Check if nick already exists
    --local nick_ptr = w.nicklist_search_nick(self.buffer, '', displayname)
    --if nick_ptr == '' then
    local nick_ptr = w.nicklist_add_nick(self.buffer,
        self.nicklist_groups[ngroup],
        displayname,
        nick_c, nprefix, nprefix_color, 1)
    --else
    --    -- TODO CHANGE nickname here
    --end
    if nick_ptr == '' then
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

    if newnick then -- run this after nick been added so it can be used
        self:_nickListChanged()
    end

    return displayname
end

function Room:GetNickGroup(user_id)
    -- TODO, cache
    local ngroup = 5
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
        ngroup = 3
        nprefix = '+'
        nprefix_color = 'yellow'
    elseif SERVER.presence[user_id] then
        -- User has a presence, put him in group3
        ngroup = 4
    end
    return ngroup, nprefix, nprefix_color
end

function Room:GetPowerLevel(user_id)
    return tonumber(self.power_levels.users[user_id] or self.power_levels.users_default or 0)
end

function Room:ClearTyping()
    for user_id, nick in pairs(self.users) do
        local _, nprefix, nprefix_color = self:GetNickGroup(user_id)
        self:UpdateNick(user_id, 'prefix', nprefix)
        self:UpdateNick(user_id, 'prefix_color', nprefix_color)
    end
end

function Room:GetPresenceNickColor(user_id, presence)
    local nick = self.users[user_id]
    local nick_c
    if user_id == SERVER.user_id then
        -- Always use correct color for self
        nick_c = 'weechat.color.chat_nick_self'
    elseif presence == 'online' then
        nick_c =  w.info_get('irc_nick_color_name', nick)
    elseif presence == 'unavailable' then
        nick_c = 'weechat.color.nicklist_away'
    elseif presence == 'offline' then
        nick_c = 'red'
    elseif presence == nil then
        nick_c = 'bar_fg'
    else
        dbg{err='unknown presence type',presence=presence}
    end
    return nick_c
end

function Room:UpdatePresence(user_id, presence)
    if presence == 'typing' then
        self:UpdateNick(user_id, 'prefix', '!')
        self:UpdateNick(user_id, 'prefix_color', 'magenta')
        return
    end
    local nick_c = self:GetPresenceNickColor(user_id, presence)
    self:UpdateNick(user_id, 'color', nick_c)
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
            w.nicklist_remove_nick(self.buffer, nick_ptr)
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
            -- Check if we are actually updating something, so there's less
            -- updates issued (I think WeeChat sends all changes as nicklist
            -- diffs to both UI code and to relay clients
            local existing = w.nicklist_nick_get_string(self.buffer, nick_ptr, key)
            if val ~= existing then
                w.nicklist_nick_set(self.buffer, nick_ptr, key, val)
            end
        end
    end
end

function Room:delNick(id)
    if self.users[id] then
        local nick = self.users[id]
        local nick_ptr = w.nicklist_search_nick(self.buffer, '', nick)
        if nick_ptr ~= '' then
            w.nicklist_remove_nick(self.buffer, nick_ptr)
        end
        self.users[id] = nil
        self.member_count = self.member_count - 1
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
                    prefix = nil,
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
    -- Remove nasty white space
    nick = nick:gsub('[\n\t]', '')
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

function Room:decryptChunk(chunk)
    -- vector client doesn't provide this
    chunk.content.msgtype = 'm.text'

    if not olmstatus then
        chunk.content.body = 'encrypted message, unable to decrypt'
        return chunk
    end

    chunk.content.body = 'encrypted message, unable to decrypt'
    local device_key = chunk.content.sender_key
    -- Find our id
    local ciphertexts = chunk.content.ciphertext
    local ciphertext
    if not ciphertexts then
        chunk.content.body = 'Recieved an encrypted message, but could not find ciphertext array'
    else
        ciphertext = ciphertexts[SERVER.olm.device_key]
    end
    if not ciphertext then
        chunk.content.body = 'Recieved an encrypted message, but could not find cipher for ourselves from the sender.'
        return chunk
    end

    local session
    local decrypted
    local err
    local found_session = false
    local sessions = SERVER.olm:get_sessions(device_key)
    for id, pickle in pairs(sessions) do
        -- Check if we already successfully decrypted with a sesssion, if that
        -- is the case we break the loop
        if decrypted then
            break
        end
        session = olm.Session.new()
        session:unpickle(OLM_KEY, pickle)
        local matches_inbound = session:matches_inbound(ciphertext.body)
        ---if ciphertext.type == 0 and matches_inbound then
        if matches_inbound then
            found_session = true
        end
        local cleartext
        cleartext, err = session:decrypt(ciphertext.type, ciphertext.body)
        if not err then
            if DEBUG then
                perr(('olm: Able to decrypt with an existing session %s'):format(session:session_id()))
            end
            decrypted = cleartext
            SERVER.olm:store_session(device_key, session)
        else
            chunk.content.body = "Decryption error: "..err
            if DEBUG then
                perr(('olm: Unable to decrypt with an existing session: %s. Session-ID: %s'):format(err, session:session_id()))
            end
        end
        session:clear()
    end
    if ciphertext.type == 0 and not found_session and not decrypted then
        session = olm.Session.new()
        local _
        _, err = session:create_inbound_from(
            SERVER.olm.account, device_key, ciphertext.body)
        if err then
            session:clear()
            chunk.content.body = "Decryption error: create inbound "..err
            return chunk
        end
        decrypted, err = session:decrypt(ciphertext.type, ciphertext.body)
        if err then
            session:clear()
            chunk.content.body = "Decryption error: "..err
            return chunk
        end
        -- TODO SERVER.olm.account:remove_one_time_keys(session)
        local session_id = session:session_id()
        perr(('Session ID: %s, user_id: %s, device_id: %s'):
        format(session_id, SERVER.user_id, SERVER.olm.device_id))
        SERVER.olm:store_session(device_key, session)
        session:clear()
        if err then
            chunk.content.body = "Decryption error: "..err
            return chunk
        end
    end

    if decrypted then
        local success, payload = pcall(json.decode, decrypted)
        if not success then
            chunk.content.body = "Payload error: "..payload
            return chunk
        end
        -- TODO use the room id from payload for security
        chunk.content.msgtype = payload.content.msgtype
        -- Style the message so user can tell if it's
        -- an encrypted message or not
        local color = w.color(w.config_get_plugin(
            'encrypted_message_color'))
        chunk.content.body = color .. payload.content.body
    end

    return chunk
end

-- Parses a chunk of json meant for a room
function Room:ParseChunk(chunk, backlog, chunktype)
    local taglist = {}
    local tag = function(tag)
        -- Helper function to add tags
        if type(tag) == 'table' then
            for _, t in ipairs(tag) do
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
    local was_decrypted = false

    -- Sender of chunk, used to be chunk.user_id, v2 uses chunk.sender
    local sender = chunk.sender or chunk.user_id
    -- Check if own message
    if sender == SERVER.user_id then
        is_self = true
        tag{'no_highlight','notify_none'}
    end
    -- Add Event ID to each line so can use it later to match on for things
    -- like redactions and localecho, etc
    tag{chunk.event_id}

    -- Some messages are missing ts
    local origin_server_ts = chunk['origin_server_ts'] or 0
    local time_int = origin_server_ts/1000

    if chunk['type'] == 'm.room.message' or chunk['type'] == 'm.room.encrypted' then
        if chunk['type'] == 'm.room.encrypted'  then
            tag{'no_log'} -- Don't log encrypted message
            chunk = self:decryptChunk(chunk)
            was_decrypted = true
        end

        if not backlog and not is_self then
            tag'notify_message'
            if self.buffer_type == 'query' then
                tag'notify_private'
            end
        end

        local color = default_color
        local content = chunk['content']
        local body = content['body']

        if not content['msgtype'] then
            -- We don't support redactions
            return
        end

        -- If it has transaction id, it is from this client.
        local is_from_this_client = false
        if chunk.unsigned and chunk.unsigned.transaction_id then
            is_from_this_client = true
        end

        -- luacheck: ignore 542
        if content['msgtype'] == 'm.text' then
            -- TODO
            -- Parse HTML here:
            -- content.format = 'org.matrix.custom.html'
            -- fontent.formatted_body...
        elseif content['msgtype'] == 'm.image' then
            local url = content['url']
            if type(url) ~= 'string' then
                url = ''
            end
            url = url:gsub('mxc://',
                w.config_get_plugin('homeserver_url')
                .. '_matrix/media/v1/download/')
            -- Synapse homeserver supports arbitrary file endings, so we put
            -- filename at the end to make it nicer for URL "sniffers" to
            -- realise it's a image URL
            body = url .. '/' .. content.body
        elseif content.msgtype == 'm.file' or content.msgtype == 'm.video' or
            content.msgtype == 'm.audio' then
            local url = content['url'] or ''
            url = url:gsub('mxc://',
                w.config_get_plugin('homeserver_url')
                .. '_matrix/media/v1/download/')
            body = 'File upload: ' ..
                   tostring(content['body'])
                   .. ' ' .. url
        elseif content['msgtype'] == 'm.notice' then
            color = wcolor('irc.color.notice')
            body = content['body']
        elseif content['msgtype'] == 'm.emote' then
            local nick_c
            local nick = self.users[sender] or sender
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
            prefix = prefix_c .. prefix
            local data = ("%s\t%s"):format(prefix, body)
            if not backlog and is_self and is_from_this_client and
              (   w.config_get_plugin('local_echo') == 'on'
                  or was_decrypted -- local echo for encryption
              )
              then
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
        if not backlog and is_self and is_from_this_client
          -- TODO better check, to work for multiple weechat clients
          and (
              w.config_get_plugin('local_echo') == 'on'
              or was_decrypted -- local echo for encrypted messages
            )
          and (-- we don't generate local echo for files and images
              content.msgtype == 'm.text'
          )
          then
            -- We have already locally echoed this line
            return
        end
        local data = ("%s\t%s%s"):format(
                self:formatNick(sender),
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
        local nick = self.users[sender] or sender
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
        if name ~= '' or name ~= json.null then
            self.roomname = name
            self:SetName(name)
        end
    elseif chunk['type'] == 'm.room.member' then
        if chunk['content']['membership'] == 'join' then
            tag"irc_join"
            --- FIXME shouldn't be neccessary adding all the time
            local name = self.users[sender] or self:addNick(sender, chunk.content.displayname)
            if not name or name == json.null or name == '' then
                name = sender
            end
            -- Check if the chunk has prev_content or not
            -- if there is prev_content there wasn't a join but a nick change
            -- or duplicate join
            local prev_content = chunk.unsigned and chunk.unsigned.prev_content
            if prev_content
                    and prev_content.membership == 'join'
                    and chunktype == 'messages' then
                local oldnick = prev_content.displayname
                if not oldnick or oldnick == json.null then
                    oldnick = sender
                else
                    if oldnick == name then
                        -- Maybe they changed their avatar or something else
                        -- that we don't care about (or multiple joins)
                        return
                    end
                    if not backlog then
                        self:delNick(sender)
                        self:addNick(sender, chunk.content.displayname)
                    end
                end
                local pcolor = wcolor'weechat.color.chat_prefix_network'
                tag'irc_nick'
                local data = ('%s--\t%s%s%s is now known as %s%s'):format(
                    pcolor,
                    w.info_get('irc_nick_color', oldnick),
                    oldnick,
                    default_color,
                    w.info_get('irc_nick_color', name),
                    name)
                w.print_date_tags(self.buffer, time_int, tags(), data)
            elseif chunktype == 'messages' then
                tag"irc_smart_filter"
                local data = ('%s%s\t%s%s%s (%s%s%s) joined the room.'):format(
                    wcolor('weechat.color.chat_prefix_join'),
                    wconf('weechat.look.prefix_join'),
                    w.info_get('irc_nick_color', name),
                    name,
                    wcolor('irc.color.message_join'),
                    wcolor'weechat.color.chat_host',
                    sender,
                    wcolor('irc.color.message_join')
                )
                w.print_date_tags(self.buffer, time_int, tags(), data)
                -- if this is an encrypted room, also download key
                if olmstatus and self.encrypted then
                    SERVER.olm:query{sender}
                end
            end
        elseif chunk['content']['membership'] == 'leave' then
            if chunktype == 'messages' then
                local nick = self.users[chunk.state_key] or sender
                local prev = chunk.unsigned.prev_content
                if (prev and
                        prev.displayname and
                        prev.displayname ~= json.null) then
                    nick = prev.displayname
                end
                if sender ~= chunk.state_key then -- Kick
                    tag{"irc_quit","irc_kick","irc_smart_filter"}
                    local reason = chunk.content.reason or ''
                    local sender_nick = self.users[chunk.sender]
                    local data = ('%s%s\t%s%s%s has kicked %s%s%s (%s).'):format(
                        wcolor('weechat.color.chat_prefix_quit'),
                        wconf('weechat.look.prefix_quit'),
                        w.info_get('irc_nick_color', sender_nick),
                        sender_nick,
                        wcolor('irc.color.message_quit'),
                        w.info_get('irc_nick_color', nick),
                        nick,
                        default_color,
                        reason
                    )
                    w.print_date_tags(self.buffer, time_int, tags(), data)
                else
                    tag{"irc_quit","irc_smart_filter"}
                    local data = ('%s%s\t%s%s%s left the room.'):format(
                        wcolor('weechat.color.chat_prefix_quit'),
                        wconf('weechat.look.prefix_quit'),
                        w.info_get('irc_nick_color', nick),
                        nick,
                        wcolor('irc.color.message_quit')
                    )
                    w.print_date_tags(self.buffer, time_int, tags(), data)
                end
            end
            self:delNick(chunk.state_key)
        elseif chunk['content']['membership'] == 'invite' then
            -- Check if we were the one being invited
            if chunk.state_key == SERVER.user_id and (
                  (not backlog and chunktype == 'messages') or
                  chunktype == 'states') then
                --self:addNick(sender)
                if w.config_get_plugin('autojoin_on_invite') == 'on' then
                    SERVER:Join(self.identifier)
                    mprint(('%s invited you'):format(sender))
                else
                    mprint(('You have been invited to join room %s by %s. Type /join %s to join.')
                        :format(
                          self.name,
                          sender,
                          self.identifier))
                end
            end
            if chunktype == 'messages' then
                tag"irc_invite"
                local prefix_c = wcolor'weechat.color.chat_prefix_action'
                local prefix = wconf'weechat.look.prefix_action'
                local data = ("%s%s\t%s invited %s to join"):format(
                    prefix_c,
                    prefix,
                    self.users[sender] or sender,
                    self.users[chunk.state_key] or chunk.state_key
                )
                w.print_date_tags(self.buffer, time_int, tags(), data)
            end
        elseif chunk['content']['membership'] == 'ban' then
            if chunktype == 'messages' then
                tag"irc_ban"
                local prefix_c = wcolor'weechat.color.chat_prefix_action'
                local prefix = wconf'weechat.look.prefix_action'
                local data = ("%s%s\t%s banned %s"):format(
                    prefix_c,
                    prefix,
                    self.users[sender] or sender,
                    self.users[chunk.state_key] or chunk.state_key
                )
                w.print_date_tags(self.buffer, time_int, tags(), data)
            end
        else
            dbg{err= 'unknown membership type in ParseChunk', chunk= chunk}
        end
        -- if it's backlog this is done at the end from the caller place
        if not backlog then
            -- Run SetName on each member change in case we need to update room name
            self:SetName(self.identifier)
        end
    elseif chunk['type'] == 'm.room.create' then
        self.creator = chunk.content.creator
    elseif chunk['type'] == 'm.room.power_levels' then
        if chunk.content.users then
            self.power_levels = chunk.content
            for user_id, lvl in pairs(self.power_levels.users) do
                -- TODO
                -- calculate changes here and generate message lines
                -- describing the change
            end
            for user_id, lvl in pairs(self.power_levels.users) do
                local _, nprefix, nprefix_color = self:GetNickGroup(user_id)
                self:UpdateNick(user_id, 'prefix', nprefix)
                self:UpdateNick(user_id, 'prefix_color', nprefix_color)
            end
        end
    elseif chunk['type'] == 'm.room.join_rules' then
        -- TODO: parse join_rules events --
        self.join_rules = chunk.content
    elseif chunk['type'] == 'm.typing' then
        -- Store the typing ids in a table that the bar item can use
        local typing_ids = {}
        for _, id in ipairs(chunk.content.user_ids) do
            self:UpdatePresence(id, 'typing')
            typing_ids[#typing_ids+1] = self.users[id]
        end
        self.typing_ids = typing_ids
        w.bar_item_update('matrix_typing_notice')
    elseif chunk['type'] == 'm.presence' then
        SERVER:UpdatePresence(chunk)
    elseif chunk['type'] == 'm.room.aliases' then
        -- Use first alias, weechat doesn't really support multiple  aliases
        self.aliases = chunk.content.aliases
        self:SetName(chunk.content.aliases[1])
    elseif chunk['type'] == 'm.room.canonical_alias' then
        self.canonical_alias = chunk.content.alias
        self:SetName(self.canonical_alias)
    elseif chunk['type'] == 'm.room.redaction' then
        local redact_id = chunk.redacts
        --perr('Redacting message ' .. redact_id)
        local result = self:UpdateLine(redact_id, w.color'darkgray'..'(redacted)')
        if not result and not backlog then
            -- backlog doesn't send original message
            perr 'Could not find message to redact :('
        end
    elseif chunk['type'] == 'm.room.history_visibility' then
        self.history_visibility = chunk.content.history_visibility
    -- luacheck: ignore 542
    elseif chunk['type'] == 'm.receipt' then
        -- TODO: figure out if we can do something sensible with read receipts
    else
        if DEBUG then
            perr(('Unknown event type %s%s%s in room %s%s%s'):format(
                w.color'bold',
                chunk.type,
                default_color,
                w.color'bold',
                self.name,
                default_color))
                dbg{chunk=chunk}
        end
    end
end

function Room:Op(nick)
    for id, name in pairs(self.users) do
        if name == nick then
            -- patch the locally cached power levels
            self.power_levels.users[id] = 99
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
            self.power_levels.users[id] = 25
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
            local pdata = ('%s--\t%s%s%s has presence %s%s'):format(
                pcolor,
                w.info_get('irc_nick_color', nick),
                nick,
                default_color,
                pcolor,
                SERVER.presence[id] or 'offline')
            w.print_date_tags(self.buffer, nil, 'notify_message', pdata)
            -- TODO support printing status_msg field in presence data here
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
        SERVER.olm:query({id})
    end
end

function Room:MarkAsRead()
    -- Get event id from tag of last line in buffer
    local lines = w.hdata_pointer(w.hdata_get('buffer'), self.buffer, 'own_lines')
    if lines == '' then return end
    local line = w.hdata_pointer(w.hdata_get('lines'), lines, 'last_line')
    if line == '' then return end
    local hdata_line = w.hdata_get('line')
    local hdata_line_data = w.hdata_get('line_data')
    local data = w.hdata_pointer(hdata_line, line, 'data')
    local tag_count = w.hdata_integer(hdata_line_data, data, "tags_count")
    if tag_count > 0 then
        for i = 0, tag_count-1 do
            local tag = w.hdata_string(hdata_line_data, data, i .. "|tags_array")
            -- Event ids are like $142533663810152bfUKc:matrix.org
            if tag:match'^%$.*:' then
                SERVER:SendReadReceipt(self.identifier, tag)
                break
            end
        end
    end
end

function poll(a, b)
    SERVER:poll()
    return w.WEECHAT_RC_OK
end

function polltimer_cb(a, b)
    local now = os.time()
    if (now - SERVER.polltime) > POLL_INTERVAL+10 then
        -- Release the poll lock
        SERVER.poll_lock = false
        SERVER:poll()
    end
    return w.WEECHAT_RC_OK
end

function otktimer_cb(a, b)
    SERVER.olm:check_server_keycount()
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
        local _, alias = split_args(args)
        if not alias then
            -- To support running /join on a invited room without args
            SERVER:Join(room.identifier)
        else
            SERVER:Join(alias)
        end
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
        local _, message = split_args(args)
        room:emote(message or '')
        return w.WEECHAT_RC_OK_EAT
    else
        return w.WEECHAT_RC_OK
    end
end

function topic_command_cb(data, current_buffer, args)
    local room = SERVER:findRoom(current_buffer)
    if room then
        local _, topic = split_args(args)
        room:Topic(topic)
        return w.WEECHAT_RC_OK_EAT
    else
        return w.WEECHAT_RC_OK
    end
end

function upload_command_cb(data, current_buffer, args)
    local room = SERVER:findRoom(current_buffer)
    if room then
        local _, upload = split_args(args)
        room:Upload(upload)
        return w.WEECHAT_RC_OK_EAT
    else
        return w.WEECHAT_RC_OK
    end
end

function query_command_cb(data, current_buffer, args)
    local room = SERVER:findRoom(current_buffer)
    if room then
        local _, query = split_args(args)
        for id, displayname in pairs(room.users) do
            if displayname == query then
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
    local command, arg = split_args(args)
    local room = SERVER:findRoom(current_buffer)
    if (room or current_buffer == BUFFER) and command == '/create' then
        if arg then
            -- Room names are supposed to be without # and homeserver, so
            -- we try to help the user out here
            local alias = arg:match'#?(.*):?'
            -- Create a non-public room with argument as alias
            SERVER:CreateRoom(false, alias, nil)
        else
            mprint 'Use /create room-name'
        end
        return w.WEECHAT_RC_OK_EAT
    else
        return w.WEECHAT_RC_OK
    end
end

function createalias_command_cb(data, current_buffer, args)
    local room = SERVER:findRoom(current_buffer)
    if room then
        local _, alias = split_args(args)
        SERVER:CreateRoomAlias(room.identifier, alias)
        return w.WEECHAT_RC_OK_EAT
    elseif current_buffer == BUFFER then
        mprint 'Use /createalias #alias:homeserver.domain from a room'
        return w.WEECHAT_RC_OK_EAT
    else
        return w.WEECHAT_RC_OK
    end
end

function invite_command_cb(data, current_buffer, args)
    local room = SERVER:findRoom(current_buffer)
    if room then
        local _, invitee = split_args(args)
        room:Invite(invitee)
        return w.WEECHAT_RC_OK_EAT
    else
        return w.WEECHAT_RC_OK
    end
end

function list_command_cb(data, current_buffer, args)
    local room = SERVER:findRoom(current_buffer)
    if room or current_buffer == BUFFER then
        local _, target = split_args(args)
        SERVER:ListRooms(target)
        return w.WEECHAT_RC_OK_EAT
    else
        return w.WEECHAT_RC_OK
    end
end

function op_command_cb(data, current_buffer, args)
    local room = SERVER:findRoom(current_buffer)
    if room then
        local _, target = split_args(args)
        room:Op(target)
        return w.WEECHAT_RC_OK_EAT
    else
        return w.WEECHAT_RC_OK
    end
end

function voice_command_cb(data, current_buffer, args)
    local room = SERVER:findRoom(current_buffer)
    if room then
        local _, target = split_args(args)
        room:Voice(target)
        return w.WEECHAT_RC_OK_EAT
    else
        return w.WEECHAT_RC_OK
    end
end

function devoice_command_cb(data, current_buffer, args)
    local room = SERVER:findRoom(current_buffer)
    if room then
        local _, target = split_args(args)
        room:Devoice(target)
        return w.WEECHAT_RC_OK_EAT
    else
        return w.WEECHAT_RC_OK
    end
end
function deop_command_cb(data, current_buffer, args)
    local room = SERVER:findRoom(current_buffer)
    if room then
        local _, target = split_args(args)
        room:Deop(target)
        return w.WEECHAT_RC_OK_EAT
    else
        return w.WEECHAT_RC_OK
    end
end

function kick_command_cb(data, current_buffer, args)
    local room = SERVER:findRoom(current_buffer)
    if room then
        local _, target = split_args(args)
        room:Kick(target)
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
    local _, msgmask = split_args(args)
    local mask, msg = split_args(msgmask)
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
        local _, arg = split_args(args)
        if arg == 'on' then
            mprint('Enabling encryption for outgoing messages in room ' .. tostring(room.name))
            room:Encrypt()
        elseif arg == 'off' then
            mprint('Disabling encryption for outgoing messages in room ' .. tostring(room.name))
            room.encrypted = false
        else
            w.print(current_buffer, 'Use /encrypt on or /encrypt off to turn encryption on or off')
        end
        return w.WEECHAT_RC_OK_EAT
    else
        return w.WEECHAT_RC_OK
    end
end

function public_command_cb(data, current_buffer, args)
    local room = SERVER:findRoom(current_buffer)
    if room then
        mprint('Marking room as public: ' .. tostring(room.name))
        room:public()
        return w.WEECHAT_RC_OK_EAT
    else
        mprint('Run command from a room')
        return w.WEECHAT_RC_OK
    end
end

function names_command_cb(cbdata, current_buffer, args)
    local room = SERVER:findRoom(current_buffer)
    if room then
        local nrcolor = function(nr)
            return wcolor'weechat.color.chat_channel'
                .. tostring(nr)
                .. default_color
        end
        local buffer_name = nrcolor(w.buffer_get_string(room.buffer, 'name'))
        local delim_c = wcolor'weechat.color.chat_delimiters'
        local tags = 'no_highlight,no_log,irc_names'
        local pcolor = wcolor'weechat.color.chat_prefix_network'
        local ngroups = {}
        local nicks = {}
        for id, name in pairs(room.users) do
            local ncolor
            if id == SERVER.user_id then
                ncolor = w.color('chat_nick_self')
            else
                ncolor = w.info_get('irc_nick_color', name)
            end
            local ngroup, nprefix, nprefix_color = room:GetNickGroup(id)
            if nprefix == ' ' then nprefix = '' end
            nicks[#nicks+1] = ('%s%s%s%s'):format(
                w.color(nprefix_color),
                nprefix,
                ncolor,
                name
            )
            if not ngroups[ngroup] then
                ngroups[ngroup] = 0
            end
            ngroups[ngroup] = ngroups[ngroup] + 1
        end
        local line1 = ('%s--\tNicks %s: %s[%s%s]'):format(
            pcolor,
            buffer_name,
            delim_c,
            table.concat(nicks, ' '),
            delim_c
        )
        w.print_date_tags(room.buffer, 0, tags, line1)
        local line2 = (
            '%s--\tChannel %s: %s nicks %s(%s%s ops, %s voice, %s normals%s)'
            ):format(
                pcolor,
                buffer_name,
                nrcolor(room.member_count),
                delim_c,
                default_color,
                nrcolor((ngroups[1] or 0) + (ngroups[2] or 0)),
                nrcolor(ngroups[3] or 0),
                nrcolor((ngroups[4] or 0) + (ngroups[5] or 0)),
                delim_c
            )
        w.print_date_tags(room.buffer, 0, tags, line2)
        return w.WEECHAT_RC_OK_EAT
    else
        perr('Could not find room')
        return w.WEECHAT_RC_OK
    end
end

function more_command_cb(data, current_buffer, args)
    local room = SERVER:findRoom(current_buffer)
    if room then
        SERVER:getMessages(room.identifier, 'b', room.prev_batch, 120)
        return w.WEECHAT_RC_OK_EAT
    else
        perr('/more Could not find room')
    end
    return w.WEECHAT_RC_OK
end

function roominfo_command_cb(data, current_buffer, args)
    local room = SERVER:findRoom(current_buffer)
    if room then
        dbg{room=room}
        return w.WEECHAT_RC_OK_EAT
    else
        perr('/roominfo Could not find room')
    end
    return w.WEECHAT_RC_OK
end

function name_command_cb(data, current_buffer, args)
    local room = SERVER:findRoom(current_buffer)
    if room then
        local _, name = split_args(args)
        room:Name(name)
        return w.WEECHAT_RC_OK_EAT
    else
        perr('/name Could not find room')
    end
    return w.WEECHAT_RC_OK
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
        local input = w.buffer_get_string(data, "input")
        -- Start sending when it reaches > 4 and doesn't start with command
        if #input > 4 and not input:match'^/' then
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

function buffer_switch_cb(signal, sig_type, data)
    -- Update bar item
    w.bar_item_update('matrix_typing_notice')
    local current_buffer = w.current_buffer()
    local room = SERVER:findRoom(current_buffer)
    if room then
        room:MarkAsRead()
    end
    return w.WEECHAT_RC_OK
end

function typing_bar_item_cb(data, buffer, args)
    local current_buffer = w.current_buffer()
    local room = SERVER:findRoom(current_buffer)
    if not room then return '' end
    local typing_ids = table.concat(room.typing_ids, ' ')
    if #typing_ids > 0 then
        return "Typing: ".. typing_ids
    end
    return ''
end

if w.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE, SCRIPT_DESC, "matrix_unload", "UTF-8") then
    -- Save WeeChat version to a global so other functionality can see it
    local version = w.info_get('version_number', '') or 0
    WEECHAT_VERSION = tonumber(version)
    local settings = {
        homeserver_url= {'https://matrix.org/', 'Full URL including port to your homeserver (including trailing slash) or use default matrix.org'},
        user= {'', 'Your homeserver username'},
        password= {'', 'Your homeserver password'},
        backlog_lines= {'120', 'Number of lines to fetch from backlog upon connecting'},
        presence_filter = {'off', 'Filter presence messages and ephemeral events (for performance)'},
        autojoin_on_invite = {'on', 'Automatically join rooms you are invited to'},
        typing_notices = {'on', 'Send typing notices when you type'},
        local_echo = {'on', 'Print lines locally instead of waiting for return from server'},
        debug = {'off', 'Print a lot of extra information to help with finding bugs and other problems.'},
        encrypted_message_color = {'lightgreen', 'Print encrypted mesages with this color'},
        --olm_secret = {'', 'Password used to secure olm stores'},
    }
    -- set default settings
    for option, value in pairs(settings) do
        if w.config_is_set_plugin(option) ~= 1 then
            w.config_set_plugin(option, value[1])
        end
        if WEECHAT_VERSION >= 0x00030500 then
            w.config_set_desc_plugin(option, ('%s (default: "%s")'):format(
                     value[2], value[1]))
        end
    end
    errprefix = wconf'weechat.look.prefix_error'
    errprefix_c = wcolor'weechat.color.chat_prefix_error'
    HOMEDIR = w.info_get('weechat_dir', '') .. '/'
    local commands = {
        'join', 'part', 'leave', 'me', 'topic', 'upload', 'query', 'list',
        'op', 'voice', 'deop', 'devoice', 'kick', 'create', 'createalias', 'invite', 'nick',
        'whois', 'notice', 'msg', 'encrypt', 'public', 'names', 'more',
        'roominfo', 'name'
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

    w.hook_config('plugins.var.lua.matrix.debug', 'configuration_changed_cb', '')

    local cmds = {'help', 'connect', 'debug', 'msg'}
    w.hook_command(SCRIPT_COMMAND, 'Plugin for matrix.org chat protocol',
        '[command] [command options]',
        'Commands:\n' ..table.concat(cmds, '\n') ..
        '\nUse /matrix help [command] to find out more\n' ..
        '\nSupported slash commands (i.e. /commands):\n' ..
        table.concat(commands, ', '),
        -- Completions
        table.concat(cmds, '|'),
        'matrix_command_cb', '')

    w.hook_command_run('/away -all*', 'matrix_away_command_run_cb', '')
    SERVER = MatrixServer.create()

    if WEECHAT_VERSION < 0x01040000 then
       perr(SCRIPT_NAME .. ': Please upgrade your WeeChat before using this script. Using this script on older WeeChat versions may lead to crashes. Many bugs have been fixed in newer versions of WeeChat.')
       perr(SCRIPT_NAME .. ': Refusing to automatically connect you. If you insist, type /'..SCRIPT_COMMAND..' connect, and do not act surprised if it crashes :-)')
    else
        SERVER:connect()
    end

    w.hook_signal('buffer_switch', "buffer_switch_cb", "")
    w.bar_item_new('matrix_typing_notice', 'typing_bar_item_cb', '')
end
