import struct


class WhatsAppReader:
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

    tokens = [None, None, None, "200", "400", "404", "500", "501", "502", "action", "add", "after", "archive", "author", "available", "battery", "before", "body", "broadcast", "chat", "clear", "code", "composing", "contacts", "count", "create", "debug", "delete", "demote", "duplicate", "encoding", "error", "false", "filehash", "from", "g.us", "group", "groups_v2", "height", "id", "image", "in", "index", "invis", "item", "jid", "kind", "last", "leave", "live", "log", "media", "message", "mimetype", "missing", "modify", "name", "notification", "notify", "out", "owner", "participant", "paused", "picture", "played", "presence", "preview", "promote", "query", "raw", "read", "receipt", "received", "recipient", "recording", "relay", "remove", "response", "resume", "retry", "s.whatsapp.net", "seconds", "set", "size", "status", "subject", "subscribe", "t", "text", "to", "true", "type", "unarchive", "unavailable", "url", "user", "value", "web", "width", "mute", "read_only", "admin", "creator", "short", "update", "powersave", "checksum", "epoch", "block", "previous", "409", "replaced", "reason", "spam", "modify_tag", "message_info", "delivery", "emoji", "title", "token_from_tokensiption", "canonical-url", "matched-text", "star", "unstar", "media_key", "filename", "identity", "unread", "page", "page_count", "search", "media_message", "security", "call_log", "profile"]

    def __init__(self, data):
        self.data = data
        self.pos = 0

    def read_byte(self):
        char_data = ord(self.data[self.pos])
        self.pos += 1
        return char_data

    def read_list_size(self, char_data):
        if char_data == self.LIST_EMPTY:
            return 0

        elif char_data == self.LIST_8:
            return self.read_byte()

        elif char_data == self.LIST_16:
            return self.read_int16()

        raise ValueError("invalid list size {}".format(char_data))

    def read_string(self, char_data):
        if char_data == -1:
            raise ValueError("invalid start token readString {}".format(char_data))

        if 2 < char_data < 236:
            token = self.get_token(char_data)
            if token == "s.whatsapp.net":
                token = "c.us"
            return token

        if char_data == self.DICTIONARY_0 or char_data == self.DICTIONARY_1 or char_data == self.DICTIONARY_2 or char_data == self.DICTIONARY_3:
            tmp = self.read_byte()
            return self.get_token_double(char_data - self.DICTIONARY_0, tmp)

        elif char_data == self.LIST_EMPTY:
            return

        elif char_data == self.BINARY_8:
            return self.readStringEx(self.read_byte())

        elif char_data == self.BINARY_20:
            return self.readStringEx(self.readInt20())

        elif char_data == self.BINARY_32:
            return self.readStringEx(self.read_int32())

        elif char_data == self.JID_PAIR:
            i = self.read_string(self.read_byte())
            j = self.read_string(self.read_byte())

            if i is None or j is None:
                raise ValueError("invalid jid {},{}".format(i,j))
            return i + "@" + j

        elif char_data == self.NIBBLE_8 or char_data == self.HEX_8:
            return self.read_packed8(char_data)
        else:
            raise ValueError("invalid string {}".format(char_data))

    # Strange behavior
    def readStringEx(self, length):
        output = self.data[self.pos:self.pos + length]
        self.pos += length
        return output

    def get_token(self, pos):
        try:
            token = self.tokens[pos]
            return token
        except Exception as e:
            raise ValueError("invalid token {}".format(token))

    # TODO: While debugging we didn't see a flow that need this, we will implement that later
    def get_token_double(self, pos):
        raise NotImplementedError("This function not implemented yet")

    def read_attributes(self, n):
        output = {}

        for i in range(n):
            index = self.read_string(self.read_byte())
            output[index] = self.read_string(self.read_byte())

        return output
    
    def read_list(self, char_data):
        output = []
        for i in range(self.read_list_size(char_data)):
            output.append(self.read_node())
        return output

    def read_list_size(self, char_data):
        if char_data == self.LIST_EMPTY:
            return 0

        elif char_data == self.LIST_8:
            return self.read_byte()

        elif char_data == self.LIST_16:
            return self.read_int16()

        raise ValueError("invalid list size {}".format(char_data))

    def read_bytes(self, n):
        output = ""
        for i in range(n):
            output += chr(self.read_byte())
        return output

    def read_int16(self):
        output = struct.unpack(">H",self.data[self.pos:self.data+2])[0]
        self.pos+=2
        return output

    # TODO: While debugging we didn't see a flow that need this, we will implement that later
    def read_int20(self):
        raise NotImplementedError("This function not implemented yet")

    def read_int32(self):
        output = struct.unpack(">L",self.data[self.pos:self.data+4])[0]
        self.pos+=4
        return output

    def read_int64(self):
        output = struct.unpack(">Q",self.data[self.pos:self.data+8])[0]
        self.pos+=8
        return output

    def read_packed8(self, char_data):
        start_byte = self.read_byte()
        output = ""

        for i in range(start_byte & 127):
            current_byte = self.read_byte()
            output += self.unpack_byte(char_data, (current_byte & 0xF0) >> 4) + self.unpack_byte(char_data, current_byte & 0x0F)

        if (start_byte >> 7) == 0:
            output = output[:len(output) - 1]

        return output

    def unpack_byte(self, char_data, value):
        if char_data == self.NIBBLE_8:
            return self.unpack_nibble(value)

        elif char_data == self.HEX_8:
            return self.unpack_hex(value)

    def unpack_nibble(self, value):

        nibble = {10:"-", 11:".", 15:"\0"}

        if 0 <= value <= 9:
            return str(value)

        elif value in nibble.keys():
            return nibble[value]

        raise ValueError("invalid nibble to unpack {}".format(value))

    def unpack_hex(self, value):
        if 0 <= value <= 15:
            return value.encode("hex").upper()

        raise ValueError("invalid hex to unpack {}".format(value))

    def read_node(self):
        char_data = self.read_byte()
        list_size = self.read_list_size(char_data)
        token_byte = self.read_byte()

        if token_byte == self.STREAM_END:
            raise ValueError("unexpected stream end {}".format(token_byte))

        token_from_tokens = self.read_string(token_byte)
        if list_size == 0 or not token_from_tokens:
            raise ValueError("invalid node")

        token_attributes = self.read_attributes((list_size - 1) >> 1)
        if list_size % 2 == 1:
            return [token_from_tokens, token_attributes, None]

        char_data = self.read_byte()

        # isListTag(t)
        if char_data == self.LIST_EMPTY or char_data == self.LIST_8 or char_data == self.LIST_16:
            content = self.read_list(char_data)

        elif char_data == self.BINARY_8:
            content = self.read_bytes(self.read_byte())

        elif char_data == self.BINARY_20:
            content = self.read_bytes(self.readInt20())

        elif char_data == self.BINARY_32:
            content = self.read_bytes(self.read_int32())

        else:
            content = self.read_string(char_data)

        return [token_from_tokens, token_attributes, content]
