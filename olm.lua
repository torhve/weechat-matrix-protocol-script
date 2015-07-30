-- libolm ffi wrapper for Lua(JIT)
--[[
--Copyright 2015 Tor Hveem <tor@hveem.no>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
--]]
local ffi = require'ffi'

ffi.cdef[[
typedef struct {
    void * memory;
} OlmAccount ;
size_t olm_account_size();
size_t olm_create_account(
    OlmAccount * account,
    void const * random, size_t random_length
);
OlmAccount * olm_account(
    void * memory
);
size_t olm_create_account_random_length(
    OlmAccount * account
);
size_t olm_account_identity_keys(
    OlmAccount * account,
    void * identity_keys, size_t identity_key_length
);
size_t olm_account_identity_keys_length(
    OlmAccount * account
);
size_t olm_account_signature_length(
    OlmAccount * account
);
size_t olm_account_sign(
    OlmAccount * account,
    void const * message, size_t message_length,
    void * signature, size_t signature_length
);
typedef struct {
    void * memory;
} OlmSession ;
OlmSession * olm_session(
    void * memory
);
size_t olm_session_size();
size_t olm_account_generate_one_time_keys_random_length(
    OlmAccount * account,
    size_t number_of_keys
);
size_t olm_account_generate_one_time_keys(
    OlmAccount * account,
    size_t number_of_keys,
    void const * random, size_t random_length
);
size_t olm_account_one_time_keys_length(
    OlmAccount * account
);
size_t olm_account_one_time_keys(
    OlmAccount * account,
    void * one_time_keys, size_t one_time_keys_length
);
size_t olm_create_outbound_session_random_length(
    OlmSession * session
);
size_t olm_create_outbound_session(
    OlmSession * session,
    OlmAccount * account,
    void const * their_identity_key, size_t their_identity_key_length,
    void const * their_one_time_key, size_t their_one_time_key_length,
    void const * random, size_t random_length
);
size_t olm_encrypt_random_length(
    OlmSession * session
);
size_t olm_encrypt_message_type(
    OlmSession * session
);
size_t olm_encrypt_message_length(
    OlmSession * session,
    size_t plaintext_length
);
size_t olm_encrypt(
    OlmSession * session,
    void const * plaintext, size_t plaintext_length,
    void const * random, size_t random_length,
    void * message, size_t message_length
);
size_t olm_create_inbound_session(
    OlmSession * session,
    OlmAccount * account,
    void * one_time_key_message, size_t message_length
);
size_t olm_create_inbound_session_from(
    OlmSession * session,
    OlmAccount * account,
    void const * their_identity_key, size_t their_identity_key_length,
    void * one_time_key_message, size_t message_length
);
size_t olm_decrypt_max_plaintext_length(
    OlmSession * session,
    size_t message_type,
    void * message, size_t message_length
);
size_t olm_decrypt(
    OlmSession * session,
    size_t message_type,
    void * message, size_t message_length,
    void * plaintext, size_t max_plaintext_length
);
size_t olm_pickle_account_length(
    OlmAccount * account
);
size_t olm_pickle_session_length(
    OlmSession * session
);
size_t olm_pickle_account(
    OlmAccount * account,
    void const * key, size_t key_length,
    void * pickled, size_t pickled_length
);
size_t olm_pickle_session(
    OlmSession * session,
    void const * key, size_t key_length,
    void * pickled, size_t pickled_length
);
size_t olm_unpickle_account(
    OlmAccount * account,
    void const * key, size_t key_length,
    void * pickled, size_t pickled_length
);
size_t olm_unpickle_session(
    OlmSession * session,
    void const * key, size_t key_length,
    void * pickled, size_t pickled_length
);
size_t olm_matches_inbound_session(
    OlmSession * session,
    void * one_time_key_message, size_t message_length
);
size_t olm_error();
const char * olm_session_last_error(
    OlmSession * session
);
const char * olm_account_last_error(
    OlmAccount * account
);
size_t olm_clear_account(
    OlmAccount * account
);
size_t olm_clear_session(
    OlmSession * session
);
size_t olm_session_id_length(
    OlmSession * session
);
size_t olm_session_id(
    OlmSession * session,
    void * id, size_t id_length
);
size_t olm_account_mark_keys_as_published(
    OlmAccount * account
);
size_t olm_remove_one_time_keys(
    OlmAccount * account,
    OlmSession * session
);

]]

local olm = ffi.load('libolm')
local ERR = olm.olm_error()

local function create_string_buffer(obj, arg)
    -- most of the API calls return ULL which is of type cdata, we can convert to lua numbers using tonumber
    -- with regular Lua FFI type is userdata
    if type(arg) == 'number' or type(arg) == 'cdata' or type(arg) == 'userdata' then
        local buf = ffi.new("uint8_t[?]", tonumber(arg))
        table.insert(obj.strings, buf)
        return buf
    end
    return arg
end

local function create_string(str, size)
    if not size then
        size = #str
    end
    local msg = ffi.new('uint8_t[?]', size)
    ffi.copy(msg, str, size)
    return msg
end

local function len(arg)
    -- Helper for porting from olm.py
    return #arg
end

local function read_random(n)
    local fd = io.open('/dev/urandom', 'rb')
    local rnd = fd:read(tonumber(n))
    fd:close()
    return rnd
end

local Account = {}
Account.__index = Account

Account.new = function()
    local account = {}
    setmetatable(account, Account)
    local size = tonumber(olm.olm_account_size())

    -- Save C string buffer to a table so the garbage collector does not clean
    -- the buffers before the olm library is done reading and writing to them
    -- TODO: check why this is needed
    account.strings = {}
    account.ptr = olm.olm_account(create_string_buffer(account, size))
    return account
end

function Account:clear()
    return olm.olm_clear_account(self.ptr)
end

function Account:last_error()
    return ffi.string(olm.olm_account_last_error(self.ptr))
end

function Account:errcheck(val)
    if val == ERR then
        local err = self:last_error()
        return val, err
    end
    return val, nil
end


function Account:create()
    local random_length = tonumber(olm.olm_create_account_random_length(self.ptr))
    local random = create_string(read_random(random_length), random_length)
    local acccountdata = olm.olm_create_account(self.ptr, random, random_length)
end

function Account:identity_keys()
    local out_length, err  = self:errcheck(olm.olm_account_identity_keys_length(self.ptr))
    if err then
        return out_length, err
    end
    out_length = tonumber(out_length)
    local out_buffer = create_string_buffer(self, out_length)
    local ret, err = self:errcheck(olm.olm_account_identity_keys(self.ptr, out_buffer, out_length))
    if err then
        return '', err
    end
    local identity_keys = ffi.string(out_buffer, out_length)
    return identity_keys
end

function Account:sign(message)
    local out_length = tonumber(olm.olm_account_signature_length(self.ptr))
    local message_buffer = create_string_buffer(self, message)
    local out_buffer = create_string_buffer(self, out_length)
    olm.olm_account_sign(
        self.ptr, message_buffer, len(message), out_buffer, out_length
    )
    return ffi.string(out_buffer, out_length)
end

function Account:one_time_keys()
    local out_length = tonumber(olm.olm_account_one_time_keys_length(self.ptr))
    local out_buffer = create_string_buffer(self, out_length)
    local ret, err = olm.olm_account_one_time_keys(self.ptr, out_buffer, out_length)
    if err then return '', err end
    local out = ffi.string(out_buffer, out_length)
    return out
end

function Account:generate_one_time_keys(count)
    local random_length = tonumber(olm.olm_account_generate_one_time_keys_random_length(self.ptr, count))
    local random = create_string(read_random(random_length), random_length)
    return self:errcheck(olm.olm_account_generate_one_time_keys(
        self.ptr, count, random, random_length
    ))
end

function Account:pickle(key)
    local key_buffer = create_string_buffer(self, key)
    local pickle_length = tonumber(olm.olm_pickle_account_length(self.ptr))
    local pickle_buffer = create_string_buffer(self, pickle_length)
    local ret, err = olm.olm_pickle_account(
        self.ptr, key_buffer, #key, pickle_buffer, pickle_length
    )
    if err then
        return nil, err
    end
    return ffi.string(pickle_buffer, pickle_length)
end

function Account:unpickle(key, pickle)
    local pickle_buffer = create_string(pickle, #pickle)
    local ret, err = self:errcheck(olm.olm_unpickle_account(
        self.ptr, key, #key, pickle_buffer, #pickle
    ))
    return ret, err
end

function Account:mark_keys_as_published()
    return self:errcheck(olm.olm_account_mark_keys_as_published(self.ptr))
end

function Account:remove_one_time_keys(session)
    return self:errcheck(olm.olm_remove_one_time_keys(self.ptr, session.ptr))
end

local Session = {}
Session.__index = Session

Session.new = function()
    local session = {}
    setmetatable(session, Session)
    session.strings = {}
    local buf = create_string_buffer(session, tonumber(olm.olm_session_size()))
    session.ptr = olm.olm_session(buf)
    return session
end

function Session:clear()
    local ret, err = self:errcheck(olm.olm_clear_session(self.ptr))
    if err then return nil, err end
    -- Save C string buffer to a table so the garbage collector does not clean
    -- the buffers before the olm library is done reading and writing to them
    -- TODO: check why this is needed
    self.strings = {}
    return ret
end

function Session:errcheck(val)
    if val == ERR then
        local err = self:last_error()
        return val, err
    end
    return val, nil
end

function Session:last_error()
    return ffi.string(olm.olm_session_last_error(self.ptr))
end

function Session:create_outbound(account, identity_key, one_time_key)
    local r_length = olm.olm_create_outbound_session_random_length(self.ptr)
    local random = read_random(r_length)
    return self:errcheck(olm.olm_create_outbound_session(
        self.ptr,
        account.ptr,
        identity_key, #identity_key,
        one_time_key, #one_time_key,
        random, r_length
    ))
end

function Session:create_inbound(account, one_time_key_message)
    local msg = create_string(one_time_key_message)
    olm.olm_create_inbound_session(
        self.ptr,
        account.ptr,
        msg, #one_time_key_message
    )
end

function Session:create_inbound_from(account, identity_key, one_time_key_message)
    local one_time_key_message_buffer = create_string(one_time_key_message)
    return self:errcheck(olm.olm_create_inbound_session_from(
        self.ptr,
        account.ptr,
        identity_key, #identity_key,
        one_time_key_message_buffer, #one_time_key_message
    ))
end

function Session:matches_inbound(one_time_key_message)
    local one_time_key_message_buffer = create_string(one_time_key_message)
    local matches = olm.olm_matches_inbound_session(
        self.ptr,
        one_time_key_message_buffer, len(one_time_key_message)
    )
    if tonumber(matches) == 1 then
        return true
    end
    return false
end

function Session:session_id()
    local id_length = tonumber(olm.olm_session_id_length(self.ptr))
    local id_buffer = create_string_buffer(self, id_length)
    local ret, err = self:errcheck(olm.olm_session_id(self.ptr, id_buffer, id_length))
    if err then return ret, err end
    local ret = ffi.string(id_buffer, id_length)
    return ret
end

function Session:encrypt(plaintext)
    local r_length = olm.olm_encrypt_random_length(self.ptr)
    local random = read_random(r_length)

    local message_type = tonumber(olm.olm_encrypt_message_type(self.ptr))
    local message_length = tonumber(olm.olm_encrypt_message_length(
        self.ptr, #plaintext
    ))
    local message_buffer = create_string_buffer(self, message_length)

    olm.olm_encrypt(
        self.ptr,
        plaintext, #plaintext,
        random, r_length,
        message_buffer, message_length
    )
    message_buffer = ffi.string(message_buffer, message_length)
    return message_type, message_buffer
end

function Session:decrypt(message_type, message)
    local message_buffer = create_string(message)
    local max_plaintext_length, err = self:errcheck(olm.olm_decrypt_max_plaintext_length(
        self.ptr, message_type, message_buffer, #message
    ))
    if err then return nil, err end
    max_plaintext_length = tonumber(max_plaintext_length)
    local plaintext_buffer = create_string_buffer(self, max_plaintext_length)
    local message_buffer = create_string(message)
    local plaintext_length, err = self:errcheck(olm.olm_decrypt(
        self.ptr, message_type, message_buffer, #message,
        plaintext_buffer, max_plaintext_length
    ))
    if err then return nil, err end
    local plaintext = ffi.string(plaintext_buffer, tonumber(plaintext_length))
    return plaintext
end

function Session:pickle(key)
    local key_buffer = create_string_buffer(self, key)
    local pickle_length = tonumber(olm.olm_pickle_session_length(self.ptr))
    local pickle_buffer = create_string_buffer(self, pickle_length)
    olm.olm_pickle_session(
        self.ptr, key_buffer, len(key), pickle_buffer, pickle_length
    )
    return ffi.string(pickle_buffer, pickle_length)
end

function Session:unpickle(key, pickle)
    local pickle_buffer = create_string(pickle, #pickle)
    local ret = olm.olm_unpickle_session(
        self.ptr, key, #key, pickle_buffer, #pickle
    )
    return self:errcheck(ret)
end

-- Invoke program with --test to run tests
local test = arg and arg[1] and arg[1] == '--test'
if test then
    local json = require'cjson'
    local key = 'test'

    alice = Account.new()
    a_session = Session.new()
    bob = Account.new()
    b_session = Session.new()

    alice:create()



    local pickle = alice:pickle(key)

    local a_keys = json.decode(alice:identity_keys())

    alice = Account.new()
    local unpickle = alice:unpickle(key, pickle)
    local a_keys_2 = json.decode(alice:identity_keys())
    assert(a_keys.curve25519 == a_keys_2.curve25519)

    local unpickle, err = alice:unpickle('invalid key', pickle)
    assert(err, 'BAD_ACCOUNT_KEY')

    local pickle = a_session:pickle(key)
    local unpickle = a_session:unpickle(key, pickle)

    local unpickle, err = a_session:unpickle(key, 'invalid base64')
    assert(err, 'BAD_ACCOUNT_KEY')
    local unpickle, err = a_session:unpickle('invalid key', pickle)
    assert(err, 'BAD_ACCOUNT_KEY')
    local unpickle, err = a_session:unpickle('invalid key', 'invalid bad64')
    assert(err, 'INVALID_BASE64')

    local sign_message = 'yepyepyep'
    local signed = alice:sign(sign_message)
    print('signed', signed)

    bob:create()
    local bobs_id_keys = json.decode(bob:identity_keys())
    bob:generate_one_time_keys(50)
    local bobs_id_keys = json.decode(bob:identity_keys())
    local bobs_id_key = bobs_id_keys.curve25519
    local bobs_ot_keys = json.decode(bob:one_time_keys())
    local bobs_ot_key
    for _,k in pairs(bobs_ot_keys.curve25519) do
        bobs_ot_key = k
    end
    a_session:create_outbound(alice, bobs_id_key, bobs_ot_key)
    bob:remove_one_time_keys(b_session)
    local secret_message = 'why not zoidberg?'
    message_1_type, message_1_body = a_session:encrypt(secret_message)

    b_session:create_inbound(bob, message_1_body)
    print('Matches inbound:', assert(b_session:matches_inbound(message_1_body)))
    local decrypted = b_session:decrypt(message_1_type, message_1_body)
    print( 'Decrypted message: ', decrypted)
    assert(secret_message == decrypted)


    b_session:create_inbound_from(bob, a_keys.curve25519, message_1_body)

    bob:mark_keys_as_published()
    print('A session id: ', a_session:session_id())
    for i=1,10000 do
        Account.new():clear()
    end

    alice:clear()
    bob:clear()
    a_session:clear()
    b_session:clear()
    print('Temp strings: '.. tostring(#strings))
    strings = {}
end

return {
    Account=Account,
    Session=Session,
}
