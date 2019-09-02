from common import Modules, data_strings, load_yara_rules, PEParseModule, ModuleMetadata
from string import ascii_lowercase, ascii_uppercase, digits
from Crypto.Cipher import AES
from Crypto.Hash import MD5
import binascii
import re

class limerat(PEParseModule):
    def __init__(self):
        md = ModuleMetadata(
            module_name="limerat",
            bot_name="Lime-RAT",
            description=".NET RAT",
            authors="Paul Melson (@pmelson)",
            version="1.0",
            date="January 22, 2019",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None
        pass

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("limerat.yara")
        return self.yara_rules

    def get_bot_information(self, file_data):
        results = {}
        LIMERATKEY = re.compile('0000([0-9a-f]{2})([0-9a-f]{8,64})00000b7c0027004e0027007c00000b7c0027004c0027007c0000', re.IGNORECASE)
        hexbytes = file_data.encode('hex')
        keybytes = LIMERATKEY.search(hexbytes)
        keybytes = keybytes.group(2)
        keystring = keybytes.decode('hex')
        keystring = keystring.replace('\x00', '')
        LIMERATC2 = re.compile('00008081([0-9a-f]{16,})([0-9a-f]{6})'+keybytes, re.IGNORECASE)
        ciphertext = LIMERATC2.search(hexbytes)
        ciphertext = ciphertext.group(1)
        ciphertext = ciphertext.decode('hex')
        ciphertext = ciphertext.replace('\x00','')
        md5hash = MD5.new()
        md5hash.update(keystring)
        h = md5hash.digest()
        KEY = h[0:15] + h + bytearray(0x01)
        content = binascii.a2b_base64(ciphertext)
        cipher = AES.new(str(KEY), AES.MODE_ECB)
        c2 = cipher.decrypt(content)
        c2 = c2.replace('\x0f','')
        c2 = c2.replace('\x00','')
        results['c2_uri'] = c2
        return results


Modules.list.append(limerat())
