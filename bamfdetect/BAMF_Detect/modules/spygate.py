from common import Modules, data_strings_wide, load_yara_rules, PEParseModule, ModuleMetadata, is_ip_or_domain
import re
import base64


class spygate(PEParseModule):

    def __init__(self):
        md = ModuleMetadata(
            module_name="spygate",
            bot_name="SpyGate",
            description="RAT",
            authors=["Paul Melson @pmelson"],
            version="1.0.0",
            date="June 1, 2018",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None


    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("spygate.yara")
        return self.yara_rules


    def get_bot_information(self, file_data):
        BASE64_REGEX = re.compile('[A-Za-z0-9/]{10,}[\=]{0,2}')
        results = {}
        wide_strings = [i for i in data_strings_wide(file_data, 1)]
        start_index = 0
        wide_strings = wide_strings[start_index:]
        c2s = [d for d in wide_strings if BASE64_REGEX.match(d)]
        for a in c2s:
            try:
                decstr = base64.b64decode(a).decode('ascii')
                if is_ip_or_domain(decstr):
                    results['c2_uri'] = "tcp://{0}".format(decstr)
            except:
                pass
        return results


Modules.list.append(spygate())
