from common import Modules, data_strings_wide, load_yara_rules, PEParseModule, ModuleMetadata, is_ip_or_domain
import re, base64
from Crypto.Cipher import AES

class AgentTesla(PEParseModule):
    def __init__(self):
        md = ModuleMetadata(
            module_name="agenttesla",
            bot_name="AgentTesla",
            description="Agent Tesla",
            authors=["Paul Melson (@pmelson)"],
            version="1.0",
            date="September 11, 2018",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("agenttesla.yara")
        return self.yara_rules

    @staticmethod
    def stringdecrypt(a):
        string = base64.b64decode(a)
        iv = "@1B2c3D4e5F6g7H8"
        key = "\x34\x88\x6D\x5B\x09\x7A\x94\x19\x78\xD0\xE3\x8b\x1b\x5c\xa3\x29\x60\x74\x6a\x5e\x5d\x64\x87\x11\xb1\x2c\x67\xaa\x5b\x3a\x8e\xbf"
        cleartext = AES.new(key[0:32], AES.MODE_CBC, iv).decrypt(string)
        return cleartext

    def get_bot_information(self, file_data):
        results = {}
        results['c2s'] = []
        wide_strings = [i for i in data_strings_wide(file_data, 1)]
        for a in wide_strings:
            if len(a) > 6:
                try:
                    decrypted = AgentTesla.stringdecrypt(a).strip('\n\r\t\x03\x04\x07\x08\x0a\x0b\x0c\x0d\x0e\x0f\x10')
#                    if is_ip_or_domain(decrypted):
#                        results['c2s'].append({"c2_uri": "tcp://{0}".format(decrypted)})
                    if re.match('[^@]+@[^@]+\.[^@]+', decrypted):
                        results['c2s'].append({"c2_uri": "email://{0}".format(decrypted)})
                except:
                    pass
        return results

Modules.list.append(AgentTesla())
