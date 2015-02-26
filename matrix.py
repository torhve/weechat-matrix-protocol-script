# WeeChat Matrix.org Client
# -*- coding: utf-8 -*-

'''
 Author: xt <xt@xt.gg>
 Thanks to Ryan Huber of wee_slack.py for some ideas and inspiration.

 This script is considered alpha quality as only the bare minimal of
 functionality is in place and it is not very well tested.
'''

import time
import json
import urllib
import urlparse
#import HTMLParser
import sys

# Very ugly hack to kill all unicode errors with fire.
reload(sys)
sys.setdefaultencoding('utf-8')
import weechat as w

SCRIPT_NAME = "matrix"
SCRIPT_AUTHOR = "xt <xt@xt.gg>"
SCRIPT_VERSION = "1"
SCRIPT_LICENSE = "MIT"
SCRIPT_DESC = "Matrix.org chat plugin"
SCRIPT_COMMAND = SCRIPT_NAME

CONF = {}
SERVER = None
default_color = w.color('default')

def dbg(message, fout=True, main_buffer=True):
    message = "DEBUG: {}".format(message)
    #message = message.encode('utf-8', 'replace')
    if fout:
        file('/tmp/debug.log', 'a+').writelines(message + '\n')
    if main_buffer:
            w.prnt("", message)

def weechat_eval(text):
    if int(version) >= 0x00040200:
        return w.string_eval_expression(text,{},{},{})
    return text

def unload():
    w.unhook(SERVER.polltimer)
    return w.WEECHAT_RC_OK

def wconf(optionname):
    return w.config_string(w.config_get(optionname))

def wcolor(optionname):
    return w.color(wconf(optionname))

def command_help(current_buffer, args):
    help_cmds = { k[8:]: v.__doc__ for k, v in globals().items() if k.startswith("command_") }

    if args:
        try:
             help_cmds = {args: help_cmds[args]}
        except KeyError:
            w.prnt("", "Command not found: " + args)
            return

    for cmd, helptext in help_cmds.items():
        w.prnt('', w.color("bold") + cmd)
        w.prnt('', (helptext or 'No help text').strip())
        w.prnt('', '')

def command_connect(current_buffer, args):
    if not SERVER.connected:
        SERVER.connect()

def matrix_command_cb(data, current_buffer, args):
    a = args.split(' ', 1)
    if len(a) > 1:
        function_name, args = a[0], " ".join(a[1:])
    else:
        function_name, args = a[0], None

    try:
        command = cmds[function_name](current_buffer, args)
    except KeyError:
        w.prnt("", "Command not found: " + function_name)

    return w.WEECHAT_RC_OK

def http(url, post, cb, timeout=30*1000):

    homeserver_url = w.config_get_plugin('homeserver_url')
    homeserver_url = urlparse.urljoin(homeserver_url, "/_matrix/client/api/v1")
    url = homeserver_url + url
    HOOK_URL = w.hook_process_hashtable('url:'+ url, post, timeout, cb, '')

STDOUT = {}
def http_cb(data, command, rc, stdout, stderr):
    if stderr != '':
        w.prnt('', '{}: {}'.format(SCRIPT_NAME, stderr))
        return w.WEECHAT_RC_OK

    if stdout != '':
        if not command in STDOUT:
            STDOUT[command] = []
        STDOUT[command].append(stdout)

    if int(rc) >= 0:
        stdout = "".join(STDOUT[command])
        del STDOUT[command]
        js = json.loads(stdout)
        # Get correct handler
        if 'login' in command:
            for k, v in js.items():
                SERVER.__setattr__(k, v)
            SERVER.connected = True
            create_matrix_buffer()
            SERVER.initial_sync()
        elif 'initialSync' in command:
            for room in js['rooms']:
                myroom = SERVER.addRoom(room)
                for chunk in room['messages']['chunk']:
                    myroom.parseChunk(chunk)
        elif 'messages' in command:
            for chunk in reversed(js.get('chunk', [])):
                room = SERVER.rooms[chunk['room_id']]
                if room:
                    room.parseChunk(chunk)
            SERVER.poll()
        elif 'events' in command:
            SERVER.end = js['end']
            SERVER.polling = False
            for chunk in js.get('chunk', []):
                ### XXX parse presence
                if 'room_id' in chunk:
                    room = SERVER.rooms[chunk['room_id']]
                    if room:
                        room.parseChunk(chunk)
        elif 'leave' in command:
            if js:
                dbg(js)
        elif '/state/' in command:
            if js:
                # TODO errorcode: M_FORBIDDEN
                dbg(js)
        elif '/send/' in command:
            ''' XXX Errorhandling '''
        else:
            w.prnt('', 'Uknown command in http cb')
            dbg(command)
            dbg(js)

    return w.WEECHAT_RC_OK

class MatrixServer(object):

    def __init__(self):
        self.nick = None
        self.buffer = None
        self.token = None
        self.connecting = False
        self.polling = False
        self.connected = False
        self.message_buffer = {}
        self.rooms = {}
        self.end = 'END'
        self.connect()
        self.polltimer = w.hook_timer(5*1000, 0, 0, "poll", "")

    def _getPost(self, post):
        extra = {
            'accept_encoding': 'application/json',
            'transfer': 'application/json',
            'postfields': json.dumps(post)
        }
        return extra

    def findRoom(self, buffer_ptr):
        for id, room in self.rooms.iteritems():
            if room.channel_buffer == buffer_ptr:
                return room

    def connect(self):
        if not self.connecting:
            user = weechat_eval(w.config_get_plugin('user'))
            password = weechat_eval(w.config_get_plugin('password'))
            if user == '' or password == '':
                w.prnt('', 'Please set your username and password using the settings system and then type /matrix connect')
                return

            self.connecting = True
            w.prnt('', 'Connecting to homeserver.')
            post = {
                "type":"m.login.password",
                "user":"%s" %user,
                "password":"%s" %password
            }
            http('/login', self._getPost(post), 'http_cb')

    def initial_sync(self):
        data = urllib.urlencode({
            'access_token': self.access_token,
            'limit': w.config_get_plugin('backlog_lines'),
        })
        http('/initialSync?%s'%data, {}, 'http_cb')

    def join(self, room):
        if not self.connected:
            '''XXX'''
            return

        room = urllib.quote(room)
        http('/join/%s' % room,
            {"postfields": "access_token="+self.access_token}, 'http_cb')
    def part(self, room):
        if not self.connected:
            '''XXX'''
            return

        room = urllib.quote(room.identifier)
        data = urllib.urlencode({
            'access_token': self.access_token,
        })
        # TODO: close buffer, delete data, etc
        http('/rooms/%s/leave?%s'
                % (room,data), {"postfields": "{}"}, 'http_cb')

    def initial_messages(self):
        for room in self.rooms:
            data = urllib.urlencode({
                'access_token': self.access_token,
                'dir': 'b',
                'from': 'END',
                'limit': w.config_get_plugin('backlog_lines'),
            })
            http('/rooms/%s/messages?%s'
               %(urllib.quote(room), data), {}, 'http_cb')

    def poll(self):
        if self.connected == False or self.polling:
            return
        self.polling = True
        data = urllib.urlencode({
            'access_token': self.access_token,
            'timeout': 1000*30,
            'from': self.end
        })
        http('/events?%s'%(data), {}, 'http_cb')


    def addRoom(self, room):
        myroom = Room(room)
        self.rooms[room['room_id']] = myroom
        return myroom

    def msg(self, room_id, body, msgtype='m.text'):
        data = {
            'accept_encoding': 'application/json',
            'transfer': 'application/json',
            'postfields': json.dumps({
                'msgtype': msgtype,
                'body': body,
        })}

        http('/rooms/%s/send/m.room.message?access_token=%s'
            %(urllib.quote(room_id), urllib.quote(self.access_token)), data, 'http_cb')

    def emote(self, room_id, body):
        self.msg(room_id, body, msgtype='m.emote')

    def state(self, room_id, key, data):
        http('/rooms/%s/state/%s?access_token=%s'
            %(urllib.quote(room_id),
              urllib.quote(key),
              urllib.quote(self.access_token)),
            {'customrequest': 'PUT',
             'accept_encoding': 'application/json',
             'transfer': 'application/json',
             'postfields': json.dumps(data),
            }, 'http_cb')


def buffer_input_cb(b, buffer, data):
    for r_id, room in SERVER.rooms.items():
        if buffer == room.channel_buffer:
            SERVER.msg(r_id, data)
    return w.WEECHAT_RC_OK

class Room(object):

    def __init__(self, obj):
        self.channel_buffer = None
        self.identifier = obj['room_id']
        for state in obj['state']:
            if state['type'] == 'm.room.aliases':
                name = state['content']['aliases'][0]
                self.name, self.server = name.split(':')
                if self.server == 'matrix.org':
                    self.sever = 'matrix'
                break
        else:
            self.name = self.identifier
            self.server = 'matrix'

        self.visibility = obj.get('visibility', 'public')
        if not 'visibility' in obj:
            dbg(obj)

        # Cache lines for dedup?
        self.lines = {}
        # Cache users for presence/nicklist
        self.users = {}
        self.create_buffer()

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name

    def topic(self, topic):
        SERVER.state(self.identifier, 'm.room.topic', {'topic':topic})

    def create_buffer(self):
        channel_buffer = w.buffer_search("", "{}.{}"
            .format(self.server, self.name))
        if channel_buffer:
            self.channel_buffer = channel_buffer
        else:
            self.channel_buffer = w.buffer_new("{}.{}"
                .format(self.server, self.name), "buffer_input_cb",
                self.name, "", "")
            w.buffer_set(self.channel_buffer, "nicklist", "1")
            w.buffer_set(self.channel_buffer, "nicklist_display_groups", "0")
            # Defined in weechat's irc-nick.h
            self.nicklist_group = w.nicklist_add_group(self.channel_buffer,
                    '', "999|...", "weechat.color.nicklist_group", 1)
            #TODO
            #weechat.buffer_set(self.channel_buffer, "highlight_words", self.nick)
            # TODO maybe use servername of homeserver?
            w.buffer_set(self.channel_buffer, "localvar_set_server", 'matrix')
            w.buffer_set(self.channel_buffer, "short_name", self.name)
            w.buffer_set(self.channel_buffer, "name", self.name)
            w.buffer_set(self.channel_buffer, "full_name", "matrix."+self.name)
            # TODO, needs better logic for detection of "private chat"
            if self.visibility == "private":
                w.buffer_set(self.channel_buffer, "localvar_set_type", 'private')
            elif self.visibility == "public":
                w.buffer_set(self.channel_buffer, "localvar_set_type", 'channel')
            else:
                dbg(self.visbility)

    def addNick(self, obj):
        nick = obj['user_id'].split(':')[0].lstrip('@')
        self.users[obj['user_id']] = nick
        w.nicklist_add_nick(self.channel_buffer, self.nicklist_group, nick,
                w.info_get('irc_nick_color_name', nick), '', '', 1)
        return nick

    def parseChunk(self, chunk):
        if chunk['type'] == 'm.room.message':
            tags = "notify_message"
            time_int = int(time.time()-chunk['age']/1000)
            color = default_color
            nick = ''
            if chunk['user_id'] in self.users:
                nick = self.users[chunk['user_id']]
            else:
                nick = self.addNick(chunk)
            # Check if own message
            if chunk['user_id'] == SERVER.user_id:
                w.buffer_set(self.channel_buffer, "localvar_set_nick",
                        self.users[SERVER.user_id])
                tags += ",no_highlight"
                nick_c = w.color('chat_nick_self')
            else:
                nick_c = w.info_get('irc_nick_color', nick)
            content = chunk['content']
            body = ''
            if not 'msgtype' in content:
                ''' We don't support redactions '''
                return
            if content['msgtype'] == 'm.text':
                body = content['body']
            elif content['msgtype'] == 'm.image':
                url = content['url'].replace('mxc://',
                    w.config_get_plugin('homeserver_url') \
                    + '_matrix/media/v1/download/')
                body = content['body'] + ' ' + url
            elif content['msgtype'] == 'm.notice':
                color = wcolor('irc.color.notice')
                body = content['body']

            elif content['msgtype'] == 'm.emote':
                prefix = w.config_string(
                        w.config_get('weechat.look.prefix_action'))
                body = "{}{} {}{}".format(
                    nick_c, nick, color, content['body']
                )
                nick_c = color
                nick = prefix
            else:
                body = content['body']
                w.prnt('', 'Uknown content type')
                dbg(content)
            data = "{}{}\t{}{}".format(nick_c, nick, color, body)
            w.prnt_date_tags(self.channel_buffer, time_int, tags,
                data.encode('UTF-8'))
        elif chunk['type'] == 'm.room.topic':
            title = chunk['content']['topic']
            w.buffer_set(self.channel_buffer, "title", title)
            color = wcolor("irc.color.topic_new")
            nick = self.users[SERVER.user_id]
            data = '--\t{}{}{} has changed the topic to "{}{}{}"'.format(
                    w.info_get('irc_nick_color', nick),
                    nick,
                    default_color,
                    color,
                    title,
                    default_color
                  )
            w.prnt_date_tags(self.channel_buffer, int(time.time()), "",
                data.encode('UTF-8'))
        elif chunk['type'] == 'm.room.name':
            name = chunk['content']['name']
            w.buffer_set(self.channel_buffer, "short_name", name)
        elif chunk['type'] == 'm.room.member':
            # TODO presence, leave, invite
            if chunk['content']['membership'] == 'join':
                ### TODO addnick logic
                nick = chunk['content']['displayname']
                self.users[chunk['user_id']] = nick
                w.nicklist_add_nick(self.channel_buffer, self.nicklist_group,
                    nick, w.info_get('irc_nick_color_name', nick), '', '', 1)

                time_int = int(time.time()-chunk['age']/1000)
                data = '{}{}\t{}{}{} joined the room.'.format(
                    wcolor('weechat.color.chat_prefix_join'),
                    wconf('weechat.look.prefix_join'),
                    w.info_get('irc_nick_color', nick),
                    nick,
                    wcolor('irc.color.message_join'),
                )
                w.prnt_date_tags(self.channel_buffer, time_int, "irc_join",
                    data.encode('UTF-8'))
            if chunk['content']['membership'] == 'leave':
                ### TODO delnick logic
                nick = chunk['prev_content'].get('displayname', chunk['user_id'])
                if chunk['user_id'] in self.users:
                    del self.users[chunk['user_id']]
                #TODO delnick w.nicklist_add_nick(self.channel_buffer, self.nicklist_group,
                #    nick, w.info_get('irc_nick_color_name', nick), '', '', 1)
                time_int = int(time.time()-chunk['age']/1000)
                data = '{}{}\t{}{}{} left the room.'.format(
                    wcolor('weechat.color.chat_prefix_quit'),
                    wconf('weechat.look.prefix_quit'),
                    w.info_get('irc_nick_color', nick),
                    nick,
                    wcolor('irc.color.message_quit'),
                )
                w.prnt_date_tags(self.channel_buffer, time_int, "irc_quit",
                    data.encode('UTF-8'))
        elif chunk['type'] == 'm.typing':
            ''' TODO: Typing notices. '''
        else:
            dbg(chunk)

def poll(*kwargs):
    SERVER.poll()
    return w.WEECHAT_RC_OK

def join_command_cb(data, current_buffer, args):
    if current_buffer == mbuffer:
        args = args.split()
        args = " ".join(args[1:])
        SERVER.join(args)
        return w.WEECHAT_RC_OK_EAT
    else:
        return w.WEECHAT_RC_OK

def part_command_cb(data, current_buffer, args):
    room = SERVER.findRoom(current_buffer)
    if room:
        SERVER.part(room)
        return w.WEECHAT_RC_OK_EAT
    else:
        return w.WEECHAT_RC_OK

def emote_command_cb(data, current_buffer, args):
    room = SERVER.findRoom(current_buffer)
    if room:
        msg = " ".join(args.split()[1:])
        SERVER.emote(room.identifier, msg)
        return w.WEECHAT_RC_OK_EAT
    else:
        return w.WEECHAT_RC_OK

def topic_command_cb(data, current_buffer, args):
    room = SERVER.findRoom(current_buffer)
    if room:
        msg = " ".join(args.split()[1:])
        room.topic(msg)
        return w.WEECHAT_RC_OK_EAT
    else:
        return w.WEECHAT_RC_OK


def closed_matrix_buffer_cb(data, buffer):
    global mbuffer
    mbuffer = None
    return w.WEECHAT_RC_OK

def create_matrix_buffer():
    global mbuffer
    mbuffer = w.buffer_new("matrix", "", "", "closed_matrix_buffer_cb", "")
    w.buffer_set(mbuffer, "short_name", "matrix")
    w.buffer_set(mbuffer, "localvar_set_type", "server")
    w.buffer_set(mbuffer, "localvar_set_server", "matrix")
    w.buffer_set(mbuffer, "display", "auto")
    return w.WEECHAT_RC_OK

if __name__ == "__main__" and \
    w.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE,
        SCRIPT_DESC, "unload", ""):
    settings = {
        'homeserver_url': ('https://matrix.org/', 'Full URL including port to your homeserver or use default matrix.org'),
        'user': ('', 'Your homeserver username'),
        'password': ('', 'Your homeserver password'),
        'backlog_lines': ('20', 'Number of lines to fetch from backlog upon connecting'),
    }
    # set default settings
    version = w.info_get('version_number', '') or 0
    for option, value in settings.iteritems():
        if w.config_is_set_plugin(option):
            CONF[option] = w.config_get_plugin(option)
        else:
            w.config_set_plugin(option, value[0])
            CONF[option] = value[0]
        if int(version) >= 0x00030500:
            w.config_set_desc_plugin(option, '%s (default: "%s")'
                    % (value[1], value[0]))
    w.hook_command_run('/join', 'join_command_cb', '')
    w.hook_command_run('/part', 'part_command_cb', '')
    w.hook_command_run('/leave', 'part_command_cb', '')
    w.hook_command_run('/me', 'emote_command_cb', '')
    w.hook_command_run('/topic', 'topic_command_cb', '')
    # Such elegance, much woe.
    cmds = {k[8:]: v for k, v in globals().items() if k.startswith("command_")}
    w.hook_command(SCRIPT_COMMAND, 'Plugin for matrix.org chat protocol',
        '[command] [command options]',
        'Commands:\n' +
        '\n'.join(cmds.keys()) +
        '\nUse /matrix help [command] to find out more\n',
        # Completions
        '|'.join(cmds.keys()),
        'matrix_command_cb', '')

    SERVER = MatrixServer()
