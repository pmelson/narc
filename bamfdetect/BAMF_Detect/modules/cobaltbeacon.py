from common import Modules, data_strings, load_yara_rules, PEParseModule, ModuleMetadata, is_ip_or_domain
import pefile
import re


class cobaltbeacon(PEParseModule):


    def __init__(self):
        md = ModuleMetadata(
            module_name="cobaltbeacon",
            bot_name="CobaltStrike Beacon",
            description="RAT",
            authors=["Paul Melson (@pmelson)"],
            version="1.0.0",
            date="June 15, 2018",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None


    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("cobaltbeacon.yara")
        return self.yara_rules


    @staticmethod
    def _xor(a):
        result = int(a) ^ int(105)
        return result


    def get_bot_information(self, file_data):
        BEACONC2 = re.compile('[a-zA-Z0-9\.]{4,255},\/[a-zA-Z09\-\.\_\~\:\/\?\#\[\]@\!\$\&\'\(\)\*\+\,\;\=]{1,}')
        results = {}
        pe = pefile.PE(data=file_data)
        dotdata = ''
        for section in pe.sections:
            if section.Name == '.data\x00\x00\x00':
                dotdata = section.get_data()

        frame = bytearray()
        for byte in dotdata:
            decimal = ord(byte)
            newbyte = cobaltbeacon._xor(decimal)
            frame.append(newbyte)

        strings = [i for i in data_strings(str(frame), 1)]
        strings = strings[0:]
        results['c2s'] = []
        for string in strings:
            if BEACONC2.search(string):
                parts = string.split(',')
                g = len(parts)
                if g > 1:
                    while g > 0:
                        path = parts[g-1]
                        host = parts[g-2]
                        if is_ip_or_domain(host):
                            results['c2s'].append({"c2_uri": "http://{0}{1}".format(host,path)})
                        g-=2

        return results


Modules.list.append(cobaltbeacon())
