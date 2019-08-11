from google.protobuf import json_format
from math import ceil, floor
from whatsapp_pb2 import WebMessageInfo

import json


class WhatsAppWriter:
    # Constants

    LIST_EMPTY = 0
    STREAM_END = 2
    DICTIONARY_0 = 236
    DICTIONARY_1 = 237
    DICTIONARY_2 = 238
    DICTIONARY_3 = 239
    LIST_8 = 248
    LIST_16 = 249
    JID_PAIR = 250
    HEX_8 = 251
    BINARY_8 = 252
    BINARY_20 = 253
    BINARY_32 = 254
    NIBBLE_8 = 255
    SINGLE_BYTE_MAX = 256

    tokens = [None, None, None, "200", "400", "404", "500", "501", "502", "action", "add", "after", "archive", "author",
              "available", "battery", "before", "body", "broadcast", "chat", "clear", "code", "composing", "contacts",
              "count", "create", "debug", "delete", "demote", "duplicate", "encoding", "error", "false", "filehash",
              "from", "g.us", "group", "groups_v2", "height", "id", "image", "in", "index", "invis", "item", "jid",
              "kind", "last", "leave", "live", "log", "media", "message", "mimetype", "missing", "modify", "name",
              "notification", "notify", "out", "owner", "participant", "paused", "picture", "played", "presence",
              "preview", "promote", "query", "raw", "read", "receipt", "received", "recipient", "recording", "relay",
              "remove", "response", "resume", "retry", "s.whatsapp.net", "seconds", "set", "size", "status", "subject",
              "subscribe", "t", "text", "to", "true", "type", "unarchive", "unavailable", "url", "user", "value", "web",
              "width", "mute", "read_only", "admin", "creator", "short", "update", "powersave", "checksum", "epoch",
              "block", "previous", "409", "replaced", "reason", "spam", "modify_tag", "message_info", "delivery",
              "emoji", "title", "token_from_tokensiption", "canonical-url", "matched-text", "star", "unstar",
              "media_key", "filename", "identity", "unread", "page", "page_count", "search", "media_message",
              "security", "call_log", "profile"]


    def __init__(self, message, char_diff):
        self.data = []
        self.original_data = message
        self.character_difference = char_diff

    def write_list_start(self, list_size):
        if list_size == 0:
            self.push_byte(self.LIST_EMPTY)
        elif list_size < 256:
            self.push_bytes([self.LIST_8])
            self.push_bytes([list_size])
        else:
            self.push_bytes([self.LIST_16])
            self.push_int16([list_size])

    def push_byte(self, value):
        self.data.append(value)

    def push_bytes(self, bytes):
        self.data += bytes

    def write_string(self, token):
        if not isinstance(token, str):
            raise ValueError("invalid string")

        if token == "c.us":
            self.write_token(self.tokens.index("s.whatsapp.net"))
            return

        if token not in self.tokens:
            token_index_of_at = token.index("@") if "@" in token else -1
            if token_index_of_at < 1:
                self.write_string_raw(token)
            else:
                self.write_jid(token[:token_index_of_at], token[token_index_of_at + 1:])
                
        else:
            token_pos = self.tokens.index(token)
            if token_pos < self.SINGLE_BYTE_MAX:
                self.write_token(token_pos)
            else:
                byte_overrun = token_pos - self.SINGLE_BYTE_MAX
                dictionary_index = byte_overrun >> 8
                byte_overrun %= 256

                if dictionary_index < 0 or dictionary_index > 3:
                    raise ValueError("double byte dictionary token out of range: {}".format(token_pos))

                self.write_token(self.DICTIONARY_0 + dictionary_index)
                self.write_token(byte_overrun)

    def write_string_raw(self, data):
        data = data.encode("utf8")
        data_len = len(data)
        if data_len > 4294967296:
            raise ValueError("invalid children; too long len = {}".format(data_len))

        if data_len >= 1 << 20:
            self.push_Byte(self.BINARY_32)
            self.push_int32(data_len)

        elif data_len >= 256:
            self.push_byte(self.BINARY_20)
            self.push_int20(data_len)
        else:
            self.push_byte(self.BINARY_8)
            self.push_byte(data_len)

        self.push_string(data)

    def push_string(self, data):
        if not isinstance(data, str):
            assert ValueError("invalid string")

        self.data += map(ord, data.encode("utf-8"))

    def write_jid(self, t, a):
        self.push_byte(self.JID_PAIR)

        if t:
            self.write_packed_bytes(t)
        else:
            self.write_token(self.LIST_EMPTY)

        self.write_string(a)

    def write_packed_bytes(self, data):
        try:
            self.write_packed_bytes_impl(data, self.NIBBLE_8)
        except Exception as e:
            self.write_packed_bytes_impl(data, self.HEX_8)

    def write_packed_bytes_impl(self, data, data_type):
        data = data.encode("utf8")

        data_len = len(data)

        if data_len > self.PACKED_MAX:
            raise ValueError("too many bytes to nibble-encode: len = {}".format(data_len))

        self.push_byte(data_type)
        s = 128 if (data_len % 2) > 0 else 0
        self.push_byte( s | ceil(data_len / 2))

        for i in range(floor(data_len / 2)):
            self.push_byte(self.pack_byte_pair(data_type, data[2 * i], data[2 * i + 1]))

        if s:
            self.push_byte(self.pack_byte_pair(data_type, data[data_len - 1], "\0"))

    def pack_byte_pair(self, data_type, t, a):
        if data_type == self.NIBBLE_8:
            pack = self.pack_nibble(t)
            pack_type = self.pack_nibble(a)

        elif data_type == self.HEX_8:
            pack = self.pack_hex(t)
            pack_type = self.pack_hex(a)

        else:
            raise ValueError("invalid byte pack type: ".format(data_type))

        return pack << 4 | pack_type

    def pack_nibble(self, value):
        nibble = {"1": 1, "2": 2, "3": 3, "4": 4, "5": 5, "6": 6, "7": 7, "8": 8, "9": 9, "-": 10, ".": 11, "\0": 15}

        if value in nibble.keys():
            return nibble[value]

        raise ValueError("invalid byte to nibble-pack: {}".format(value))

    def pack_hex(self, value):

        if "0" <= value <= "9" or "A" <= value <= "F":
            print int(value, 16)

        elif value == "\0":
            return 15

        raise ValueError("packHex:invalid byte: " + str(value))

    def write_token(self, token):
        if token < 245:
            self.push_byte(token)
        elif token <= 500:
            raise ValueError("invalid token")

    def write_attributes(self, token_attributes):
        if not token_attributes:
            return

        for keys, values in token_attributes.iteritems():
            if values:
                self.write_string(keys)
                self.write_string(values)

    def write_children(self, children):
        if not children:
            return

        if isinstance(children, str):
            self.write_string(children, True)

        elif isinstance(children, bytes):
            bytes_len = len(children)
            if bytes_len > 4294967296:
                raise ValueError("invalid children; too long len = {}".format(bytes_len))

            if bytes_len >= 1 << 20:
                self.push_Byte(self.BINARY_32)
                self.push_int32(bytes_len)

            elif bytes_len >= 256:
                self.push_byte(self.BINARY_20)
                self.push_int20(bytes_len)
            else:
                self.push_byte(self.BINARY_8)
                self.push_byte(bytes_len)
                self.push_bytes(children)

        else:
            if not isinstance(children, list):
                raise ValueError("invalid children".format())

            self.write_list_start(len(children))

            # Lazy temporary solution
            if isinstance(children[0], dict):
                # Take the Token and Token Attributes from the original message
                self.data = [ord(x) for x in self.original_data[:12]]

                # TODO:// check if there is a positive/negative overflow and fix it
                print "CHARACTERS LENGTH BEFORE FIX: ", self.data[11]

                self.data[11] += self.character_difference  # modify the characters difference

                data = json_format.Parse(json.dumps(children[0]), WebMessageInfo(),
                                         ignore_unknown_fields=True)

                self.data.extend(data.SerializeToString())

                for i in range(len(self.data)):
                    if isinstance(self.data[i], str):
                        self.data[i] = ord(self.data[i])


                return True

            for child in children:
                self.write_node(child)

    def push_int16(self, value):
        for i in range(2):
            shift = (2 - i - 1) * 8
            self.data.append((value >> shift) & 0xFF)

    def push_int20(self, value):
        raise NotImplementedError("This function not implemented yet")

    def push_int32(self, value):
        for i in range(4):
            shift = (4 - i - 1) * 8
            self.data.append((value >> shift) & 0xFF)

    def get_data(self):
        return "".join(map(chr, self.data))

    def write_node(self, node):
        if not node:
            return

        if len(node) != 3:
            raise ValueError("invalid node")

        if node[1]:
            tokens = 2 * len(node[1].keys())
        else:
            tokens = 0

        self.write_list_start( 1 + tokens + (1 if node[2] else 0))
        self.write_string(node[0])
        self.write_attributes(node[1])
        self.write_children(node[2])


def whatsapp_write(node, message, char_diff):
    stream = WhatsAppWriter(message, char_diff)
    stream.write_node(node)
    return stream.get_data()
