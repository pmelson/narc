from common import Modules, data_strings_wide, load_yara_rules, PEParseModule, ModuleMetadata, is_ip_or_domain
import pefile

class infinity(PEParseModule):

    def __init__(self):
        md = ModuleMetadata(
            module_name="infinity",
            bot_name="Infinity",
            description="RAT with DDoS and infostealer functions",
            authors=["Paul Melson @pmelson"],
            version="1.0.0",
            date="August 20, 2018",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None


    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("infinity.yara")
        return self.yara_rules


    def get_bot_information(self, file_data):
        results = {}
        pe = pefile.PE(data=file_data)
        dottext = ''
        for section in pe.sections:
            if section.Name == '.text\x00\x00\x00':
                dottext = section.get_data()
        wide_strings = [i for i in data_strings_wide(dottext, 1)]
        potential_domains = [d for d in wide_strings if is_ip_or_domain(d)]
        extra_hosts = ['1.1.1.1']
        for d in potential_domains:
            if d in extra_hosts:
                potential_domains.remove(d)
        if len(potential_domains) > 0:
            for d in potential_domains:
                results['c2_uri'] = "tcp://{0}".format(d)
        return results


Modules.list.append(infinity())
