from common import Modules, data_strings_wide, load_yara_rules, PEParseModule, ModuleMetadata, is_ip_or_domain
import re, base64

class Njratgold(PEParseModule):
    def __init__(self):
        md = ModuleMetadata(
            module_name="njratgold",
            bot_name="Njratgold",
            description="Njrat 0.7 Golden edition",
            authors=["Paul Melson (@pmelson)"],
            version="1.1",
            date="June 4, 2018",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("njrat07g.yara")
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
        myhostrex = re.compile('(\x00h\x00o\x00s\x00t|\x00\x2e\x00e\x00x\x00e)\x00\x00.(.*)(\x00|\x01)\x07#\x00i\x00c')
        myportrex = re.compile('\x07#\x00i\x00c\x00\x00(\x01\x00.|\x09T\x00r\x00u\x00e\x00\x00\x01\x00.|\x0bF\x00a\x00l\x00s\x00e\x00\x00\x01\x00.)(.*)(\x00\x17|\x01.)\w')

        hostmatch = myhostrex.search(blob)
        try:
            hst = hostmatch.group(2)
        except:
            hst = "ERR"
        host = hst.replace('5\t?\t(\t@\t', 'M').replace('!', '=').replace('.\tG\t', 'A').replace('\x82\x84', 'T').replace(',\t@\t*\t@\t', 'Z').replace('\x00', '')

        portmatch = myportrex.search(blob)
        try:
            prt = portmatch.group(2)
        except:
            prt = "ERR"
        port = prt.replace('\xb9|', 'M').replace('$\t>\t', 'T').replace('X\xc7\xc4\xb3', 'A').replace('\xd0\xc5', 'e').replace('\x00', '')

        return host,port


    def get_bot_information(self, file_data):
        results = {}
        host = ""
        port = ""
        host,port = Njratgold._getcfg(file_data)
        try:
            h = base64.b64decode(host)
        except:
            h = "ERR"
        try:
            p = base64.b64decode(port)
        except:
            p = "ERR"
        if is_ip_or_domain(h) and Njratgold._is_number(p):
            results['c2_uri'] = "tcp://{0}:{1}".format(h,p)
        elif is_ip_or_domain(h):
            results['c2_uri'] = "tcp://{0}".format(h)

        return results

Modules.list.append(Njratgold())
