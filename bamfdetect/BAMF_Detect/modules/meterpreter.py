from common import Modules, data_strings_wide, load_yara_rules, PEParseModule, ModuleMetadata, is_ip_or_domain
import re


class meterpreter(PEParseModule):

    def __init__(self):
        md = ModuleMetadata(
            module_name="meterpreter",
            bot_name="meterpreter",
            description="Metasploit interactive shell",
            authors=["Paul Melson @pmelson"],
            version="1.0.0",
            date="March 11, 2020",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None


    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("meterpreter.yara")
        return self.yara_rules


    def get_bot_information(self, file_data):
        C2_TCP_REGEX = re.compile('tcp://[a-z0-9_\-\.]+:[0-9]{1,5}', re.IGNORECASE)
        C2_HTTP_REGEX = re.compile('(http|https)://[a-z0-9_\-\.]+:[0-9]{1,5}/[a-z0-9_-]+/', re.IGNORECASE)
        results = {}
        wide_strings = [i for i in data_strings_wide(file_data, 1)]
        for wide_string in wide_strings:
            if C2_TCP_REGEX.match(wide_string):
                results['c2_uri'] = wide_string
                return results
            elif C2_HTTP_REGEX.match(wide_string):
                results['c2_uri'] = wide_string
                return results
        return results


Modules.list.append(meterpreter())
