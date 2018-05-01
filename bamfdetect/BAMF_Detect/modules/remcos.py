from common import Modules, data_strings, load_yara_rules, PEParseModule, ModuleMetadata
from re import match
from string import ascii_lowercase, ascii_uppercase, digits
import rc4

class remcos(PEParseModule):
    def __init__(self):
        md = ModuleMetadata(
            module_name="remcos",
            bot_name="Remcos RAT",
            description="Shitty RAT",
            authors=["Paul Melson (@pmelson)","Brian Wallace (@botnet_hunter)"],
            version="1.0",
            date="April 3, 2018",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None
        pass

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("remcos.yar")
        return self.yara_rules

    def get_bot_information(self, file_data):
        results = {}
        offset = file_data.find(b'\x00\x00\x00\x00\xc0\x00\x00\x00\xfc\x00\x00\x00\xfe\x00\x00\x01\xfe\x00\x00\x01\xfc\x01\xf8\x03\xfc\x01\xfc\x03\xfc\x03\xfe\x07\xfe\x03\xff\xff')
        offset = offset+0x24
        key_len = ord(file_data[offset:offset+0x01])
        keyoffset = key_len+1
        key = rc4.convert_key(file_data[offset+0x01:offset+keyoffset])
        keystream = rc4.RC4(key)
        padoffset = file_data.find(b'\x50\x41\x44\x44\x49\x4e\x47\x58\x58')
        encrypted_data = file_data[offset+keyoffset:padoffset]
        decrypted = ''
        for item in encrypted_data:
            decrypted += chr(ord(item) ^ keystream.next())
        urls = decrypted.split('|')[:-1]
        results['c2s'] = []
        for url in urls:
            results['c2s'].append({"c2_uri": "tcp://"+url})
        return results


Modules.list.append(remcos())
