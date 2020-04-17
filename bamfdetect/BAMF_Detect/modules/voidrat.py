from common import Modules, data_strings_wide, load_yara_rules, PEParseModule, ModuleMetadata
import pype32
import base64
import re
import hashlib
from Crypto.Cipher import AES
from pbkdf2 import PBKDF2

class VoidRAT(PEParseModule):
    def __init__(self):
        md = ModuleMetadata(
            module_name="voidrat",
            bot_name="VoidRAT",
            description=".NET RAT",
            authors=["Paul Melson (@pmelson)"],
            version="1.0.0",
            date="March 22, 2020",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("voidrat.yara")
        return self.yara_rules

    @staticmethod
    def _get_strings(pe, dir_type):
        string_list = []
        m = pe.ntHeaders.optionalHeader.dataDirectory[14].info
        for s in m.netMetaDataStreams[dir_type].info:
            for offset, value in s.iteritems():
                string_list.append(value)
        return string_list

    @staticmethod
    def _void_decrypt(ciphertext, encryptionkey):
        keyiterations = 50000
        salt = '\xbf\xeb\x1e\x56\xfb\xcd\x97\x3b\xb2\x19\x02\x24\x30\xa5\x78\x43\x00\x3d\x56\x44\xd2\x1e\x62\xb9\xd4\xf1\x80\xe7\xe6\xc3\x39\x41'
        keybytes = PBKDF2(encryptionkey, salt, keyiterations)
        defaultkey = keybytes.read(16)
        ciphertextbytes = base64.b64decode(ciphertext)
        iv = ciphertextbytes[:16]
        cipher = AES.new(defaultkey, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertextbytes[16:])
        c2 = decrypted[32:].split(';')[0]
        return c2

    def get_bot_information(self, file_data):
        results = {}
        B64_REGEX = re.compile('[a-zA-Z0-9/+\=]{20,88}')
        C2_REGEX = re.compile('[a-z0-9\._\-]{1,100}:[0-9]{1,5}', re.IGNORECASE)
        pe = pype32.PE(data=file_data)
        string_list = VoidRAT._get_strings(pe, 2)
        cfg_strings = []
        for i in range(0, len(string_list)):
            if len(string_list[i]) == 88 and B64_REGEX.match(string_list[i]):
                for j in range(0,10):
                    cfg_strings.append(string_list[i+j])
                break
        ciphertext = str(cfg_strings[1])
        encryptionkey = str(cfg_strings[8])
        c2 = VoidRAT._void_decrypt(ciphertext, encryptionkey)
        if C2_REGEX.match(c2):
            results['c2_uri'] = c2
        return results


Modules.list.append(VoidRAT())
