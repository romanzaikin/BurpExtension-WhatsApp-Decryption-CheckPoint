#!/usr/bin/python
# -*- coding: utf-8 -*-
from Crypto.Cipher import AES
from google.protobuf import json_format

from libs.whatsapp_read import WhatsAppReader
from libs.whatsapp_write import WhatsAppWriter
from libs.whatsapp_pb2 import WebMessageInfo

import os
import base64
import json
import hashlib
import hmac
import curve25519
import socket
import ast


def hmac_sha256(key, sign):
    return hmac.new(key, sign, hashlib.sha256).digest()


def HKDF(key, length, app_info=""):
    key = hmac_sha256("\0" * 32, key)
    key_stream = ""
    key_block = ""
    block_index = 1
    while len(key_stream) < length:
        key_block = hmac.new(key, msg=key_block + app_info + chr(block_index), digestmod=hashlib.sha256).digest()
        block_index += 1
        key_stream += key_block
    return key_stream[:length]


def aes_pad(s):
    bs = AES.block_size
    return s + (bs - len(s) % bs) * chr(bs - len(s) % bs)


def aes_unpad(s):
    return s[:-ord(s[len(s) - 1:])]


def aes_encrypt(key, plaintext):
    plaintext = aes_pad(plaintext)
    iv = os.urandom(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(plaintext)


def WhatsAppEncrypt(enc_key, mac_key, plaintext):
    enc = aes_encrypt(enc_key, plaintext)
    return hmac_sha256(mac_key, enc) + enc


def AESDecrypt(key, ciphertext):  # from https://stackoverflow.com/a/20868265
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return aes_unpad(plaintext)


class WhatsAppWebClient(object):

    def __init__(self, ref_dict, priv_key_list, pub_key_list):

        self.conn_data = {
            "private_key": None,
            "public_key": None,
            "secret": None,
            "shared_secret": None,
            "shared_secret_ex": None,
            "aes_key": None,
            "mac_key": None
        }

        self.conn_data["private_key"] = curve25519.Private("".join([chr(x) for x in priv_key_list]))
        self.conn_data["public_key"] = self.conn_data["private_key"].get_public()

        assert (self.conn_data["public_key"].serialize() == "".join([chr(x) for x in pub_key_list]))

        self.conn_data["secret"] = base64.b64decode(ref_dict["secret"])
        self.conn_data["shared_secret"] = self.conn_data["private_key"].get_shared_key(curve25519.Public(self.conn_data["secret"][:32]), lambda key: key)

        shared_expended = self.conn_data["shared_secret_ex"] = HKDF(self.conn_data["shared_secret"], 80)

        check_hmac = hmac_sha256(shared_expended[32:64], self.conn_data["secret"][:32] + self.conn_data["secret"][64:])

        if check_hmac != self.conn_data["secret"][32:64]:
            raise ValueError("Error hmac mismatch")

        keysDecrypted = AESDecrypt(shared_expended[:32], shared_expended[64:] + self.conn_data["secret"][64:])

        self.conn_data["aes_key"] = keysDecrypted[:32]
        self.conn_data["mac_key"] = keysDecrypted[32:64]

    def decrypt_incoming_message(self, message):
        message = base64.b64decode(message)
        message_parts = message.split(",", 1)
        self.message_tag = message_parts[0]
        content = message_parts[1]

        check_hmac = hmac_sha256(self.conn_data["mac_key"], content[32:])
        if check_hmac != content[:32]:
            raise ValueError("Error hmac mismatch")

        self.decrypted_content = AESDecrypt(self.conn_data["aes_key"], content[32:])

        node = WhatsAppReader(self.decrypted_content)
        node = node.read_node()

        output = []

        for item in node[2]:
            msg = WebMessageInfo()
            msg.ParseFromString(item[2])
            output.append(json.loads(json_format.MessageToJson(msg)))

        node[2] = output
        self.decrypted_seralized_content = node

        return self.decrypted_seralized_content

    def encrypt_incoming_message(self, message, char_diff):
        stream = WhatsAppWriter(self.decrypted_content, char_diff)
        stream.write_node(message)
        whatsapp_data = stream.get_data()

        enc = aes_encrypt(self.conn_data["aes_key"], whatsapp_data)
        data = hmac_sha256(self.conn_data["mac_key"], enc) + enc

        return base64.b64encode("{0},{1}".format(self.message_tag, data))

    def decrypt_outgoing_message(self, message):
        output = []

        self.original = message
        self.decrypted_content = "".join([chr(x) for x in message])

        node = WhatsAppReader(self.decrypted_content)
        node = node.read_node()

        for item in node[2]:
            msg = WebMessageInfo()
            msg.ParseFromString(item[2])
            output.append(json.loads(json_format.MessageToJson(msg)))

        node[2] = output

        return node

    def encrypt_out_going(self, message, char_diff=0):
        output = self.original[:17]

        stream = WhatsAppWriter(self.decrypted_content, char_diff)
        stream.write_node(message)
        whatsapp_data = stream.get_data()

        for i in range(len(whatsapp_data)):
            if i < 12:
                continue

            output.append(ord(whatsapp_data[i]))

        # Fix protobuf manually
        # TODO:// fix the whatsapp_write code, seems that there is a bug somewhere...
        char_diff = len(output) - len(self.original)
        print "ENCRYPTED DIFF: {}".format(char_diff)

        output[9] += char_diff
        output[16] += char_diff

        return output


server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(("", 2912))

error_codes = {
    0: "Success.",
    1: "Wrong keys or ref.",
    2: "Bad message, can't decrypt the incoming message.",
    3: "Can't encrypt the incoming message, something wrong with the data.",
    4: "Bad message, can't decrypt the outgoing message.",
    5: "Can't encrypt the outgoing message, something wrong with the data."
}

print "Waiting for connection"
print """

Dikla Barda:
    Linkedin - https://www.linkedin.com/in/diklabarda/ 


Roman Zaikin:
    Linkedin - https://www.linkedin.com/in/romanzaikin/
    Twitter -  https://twitter.com/R0m4nZ41k1n
    
"""

while True:
    data, client = server.recvfrom(4096)
    print "connection received from client {0}".format(client)

    try:
        data = json.loads(data)
    except Exception as e:
        continue

    if data["action"] == "init":
        public = ast.literal_eval(data["data"]["public"])
        private = ast.literal_eval(data["data"]["private"])

        try:
            wb = WhatsAppWebClient(data["data"]["ref"], private, public)
        except Exception as e:
            server.sendto(json.dumps({"status": 1,"data": error_codes[1]}), client)
        else:
            server.sendto(json.dumps({"status": 0, "data": error_codes[0]}), client)

    elif data["action"] == "decrypt":

        # decrypt incoming messages
        if data["data"]["direction"] == "in":
            try:
                # fix len
                decrypted_message = wb.decrypt_incoming_message(data["data"]["msg"])
                print "DECRYPTED: ", len(str(decrypted_message).replace("u'","'"))

            except Exception as e:
                server.sendto(json.dumps({"status": 2, "data": error_codes[2]}), client)
            else:
                server.sendto(json.dumps({"status": 0, "data": decrypted_message}), client)

        # decrypt outgoing messages
        elif data["data"]["direction"] == "out":
            try:
                decrypted_message = wb.decrypt_outgoing_message(ast.literal_eval(data["data"]["msg"]))
            except Exception as e:
                server.sendto(json.dumps({"status": 4, "data": error_codes[4]}), client)
            else:
                server.sendto(json.dumps({"status": 0, "data": decrypted_message}), client)

    elif data["action"] == "encrypt":

        # encrypt incoming messages
        if data["data"]["direction"] == "in":
            try:
                #TODO:// I have to find a better way to translate the json to list,
                #TODO:// The problem is that we have (false,true) in it...

                received_unencrypted = ast.literal_eval(data["data"]["msg"].replace("false","False").replace("true","True"))
                print "ENCRYPTED: ", len(str(received_unencrypted))

                char_diff = len(str(received_unencrypted)) - len(str(decrypted_message).replace("u'","'"))
                encrypted_message = wb.encrypt_incoming_message(received_unencrypted, char_diff)
            except Exception as e:
                print e
                server.sendto(json.dumps({"status": 3, "data": error_codes[3]}), client)
            else:
                server.sendto(json.dumps({"status": 0, "data": encrypted_message}), client)

        # encrypt outgoing messages
        elif data["data"]["direction"] == "out":
            try:
                #TODO:// I have to find a better way to translate the json to list,
                #TODO:// The problem is that we have (false,true) in it...
                received_unencrypted = ast.literal_eval(data["data"]["msg"].replace("false","False").replace("true","True"))
                encrypted_message = wb.encrypt_out_going(received_unencrypted, 0)
            except Exception as e:
                print e
                server.sendto(json.dumps({"status": 5, "data": error_codes[5]}), client)
            else:
                server.sendto(json.dumps({"status": 0, "data": encrypted_message}), client)
