from common import Modules, data_strings_wide, load_yara_rules, PEParseModule, ModuleMetadata
import pype32
import base64
import re
import hashlib
from Crypto.Cipher import AES
from pbkdf2 import PBKDF2

class AsyncRAT(PEParseModule):
    def __init__(self):
        md = ModuleMetadata(
            module_name="asyncrat",
            bot_name="AsyncRAT",
            description=".NET RAT based on QuasarRAT",
            authors=["Paul Melson (@pmelson)"],
            version="1.0.0",
            date="April 13, 2020",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("asyncrat.yara")
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
    def _async_decrypt(ciphertextbytes, encryptionkey):
        keyiterations = 50000
        salt = '\xbf\xeb\x1e\x56\xfb\xcd\x97\x3b\xb2\x19\x02\x24\x30\xa5\x78\x43\x00\x3d\x56\x44\xd2\x1e\x62\xb9\xd4\xf1\x80\xe7\xe6\xc3\x39\x41'
        keybytes = PBKDF2(encryptionkey, salt, keyiterations)
        defaultkey = keybytes.read(32)
        iv = ciphertextbytes[:16]
        cipher = AES.new(defaultkey, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertextbytes[16:])
        cleartext = AsyncRAT._strip_padding(decrypted[32:])
        return cleartext

    @staticmethod
    def _strip_padding(text):
        stripped = ''
        for char in text:
            if ord(char) > 31 and ord(char) < 127:
                stripped += char
        return stripped

    def get_bot_information(self, file_data):
        results = {}
        B64_REGEX = re.compile('[a-zA-Z0-9/+\=]{20,88}')
        C2_REGEX = re.compile('[a-z0-9\._\-]{1,100}:[0-9]{1,5}', re.IGNORECASE)
        KEY_REGEX = re.compile('[a-zA-Z0-9]{32}')
        pe = pype32.PE(data=file_data)
        string_list = AsyncRAT._get_strings(pe, 2)

        # check for and extract strings from unencoded config
        if '(ext8,ext16,ex32) type $c7,$c8,$c9' in string_list:
            cfg_strings = []
            for i in range(0, len(string_list)):
                if len(string_list[i]) == 88 and B64_REGEX.match(string_list[i]):
                    for j in range(0,10):
                        cfg_strings.append(string_list[i+j])
                    break
                elif C2_REGEX.match(string_list[i+1] + ':' + string_list[i]):
                    c2 = str(string_list[i+1] + ':' + string_list[i])
                    results['c2_uri'] = c2
                    return results
            ports_ciphertext = base64.b64decode(cfg_strings[0])
            hosts_ciphertext = base64.b64decode(cfg_strings[1])
            encryptionkey = base64.b64decode(cfg_strings[6])

        # check for, decode, and extract strings from base64 encoded config
        elif 'KGV4dDgsZXh0MTYsZXgzMikgdHlwZSAkYzcsJGM4LCRjOQ==' in string_list:
            clear_strings = []
            for a in string_list:
                try:
                    clear_strings.append(base64.b64decode(a))
                except:
                    pass
            cfg_strings = []
            for i in range(0, len(clear_strings)):
                if clear_strings[i] == '{{ ProcessId = {0}, Name = {1}, ExecutablePath = {2} }}':
                    for j in range(1,8):
                        cfg_strings.append(clear_strings[i+j])
                    break
            ports_ciphertext = cfg_strings[0]
            hosts_ciphertext = cfg_strings[1]
            for i in range(2,len(cfg_strings)-1):
                if KEY_REGEX.match(cfg_strings[i]):
                    encryptionkey = cfg_strings[i]
                    break
        else:
            return results

        ports = AsyncRAT._async_decrypt(ports_ciphertext, encryptionkey)
        port_list = ports.split(',')
        hosts = AsyncRAT._async_decrypt(hosts_ciphertext, encryptionkey)
        host_list = hosts.split(',')
        if len(host_list[0]) > 1 or hosts[0] == ',':
            results['c2s'] = []
            for h in host_list:
                for p in port_list:
                    c2 = str("{0}:{1}".format(h,p))
                    if C2_REGEX.match(c2):
                        results['c2s'].append({"c2_uri": c2})

        return results


Modules.list.append(AsyncRAT())
