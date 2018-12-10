from common import Modules, data_strings, load_yara_rules, PEParseModule, ModuleMetadata, is_ip_or_domain
import re


class waketagat(PEParseModule):


    def __init__(self):
        md = ModuleMetadata(
            module_name="waketagat",
            bot_name="WAKETAGAT",
            description="Backdoor",
            authors=["Paul Melson (@pmelson)"],
            version="1.0.0",
            date="August 10, 2018",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None


    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("waketagat.yara")
        return self.yara_rules


    @staticmethod
    def _xor(a):
        result = int(a) ^ int(15)
        return result


    def get_bot_information(self, file_data):
        URL_REGEX = re.compile('(http|https|ftp|cifs|smb)\:\/\/[a-zA-Z0-9\/\.\~\-]+', re.IGNORECASE)
        results = {}
        frame = bytearray()
        for byte in file_data:
            decimal = ord(byte)
            newbyte = waketagat._xor(decimal)
            frame.append(newbyte)

        strings = [i for i in data_strings(str(frame), 1)]
        strings = strings[0:]
        results['c2s'] = []
        for string in strings:
            if URL_REGEX.search(string):
                results['c2s'].append({"c2_uri": "{0}".format(string)})

        return results


Modules.list.append(waketagat())
