from common import Modules, data_strings_wide, load_yara_rules, PEParseModule, ModuleMetadata, is_ip_or_domain
import re, base64

myrex = re.compile('\x00.\x00e\x00x\x00e\x00.?.?(.*)\x00\x01')
myc2rex = re.compile('(.*)#ic')

class Njratgold(PEParseModule):
    def __init__(self):
        md = ModuleMetadata(
            module_name="njratgold",
            bot_name="Njratgold",
            description="Njrat 0.7 Golden edition",
            authors=["Paul Melson (@pmelson)"],
            version="1.0",
            date="January 23, 2018",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("njrat07g.yar")
        return self.yara_rules

    @staticmethod
    def _is_number(s):
        if s != s.strip():
            return False
        try:
            if int(s) < 65536:
                return True
            return False
        except KeyboardInterrupt:
            raise
        except:
            return False

    @staticmethod
    def _getcfg(blob):
        cfg = bytearray()
        try:
            match = myrex.search(blob)
            elements = list(match.group(1))
            for char in elements:
                if char != '\x00':
                    cfg.append(char)
        except:
            print "Error parsing Njrat 0.7 Golden config"
        return cfg

    def get_bot_information(self, file_data):
        results = {}
        config = bytearray()
        config = Njratgold._getcfg(file_data)
        c2 = myc2rex.search(config)
        try:
            d = base64.b64decode(c2.group(1)).replace("~n", "s.")
        except:
            d = "nope"
        if is_ip_or_domain(d):
             results['c2_uri'] = "tcp://{0}".format(d)
        return results

Modules.list.append(Njratgold())
