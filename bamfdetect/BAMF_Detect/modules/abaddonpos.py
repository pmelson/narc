from common import Modules, data_strings, load_yara_rules, PEParseModule, ModuleMetadata, is_ip_or_domain
import struct


class abaddon(PEParseModule):
    def __init__(self):
        md = ModuleMetadata(
            module_name="abaddon",
            bot_name="Abaddon",
            description="Point of sale malware designed to extract credit card information from RAM",
            authors=["Brian Wallace (@botnet_hunter)"],
            version="1.0.0",
            date="December 2, 2015",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None
        pass

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("abaddon.yara")
        return self.yara_rules

    def get_bot_information(self, file_data):
        results = {}

        start_search_address = file_data.find("\x90" * 8) + 8

        xor_key = struct.unpack("<I", file_data[start_search_address:][:4])[0] ^ 0x8be58955

        data = file_data[start_search_address:]

        decrypted = ""

        while len(data) > 4:
            d = struct.unpack("<I", data[:4])[0]
            data = data[4:]
            decrypted += struct.pack("<I", d ^ xor_key)

        for s in data_strings(decrypted):
            if is_ip_or_domain(s):
                results['c2_uri'] = s

        return results


Modules.list.append(abaddon())