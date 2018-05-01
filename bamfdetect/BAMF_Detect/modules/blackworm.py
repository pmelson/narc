from common import Modules, data_strings_wide, load_yara_rules, PEParseModule, ModuleMetadata, is_ip_or_domain


class BlackWorm(PEParseModule):
    first_value_table = None
    precomputed_list = None

    def __init__(self):
        md = ModuleMetadata(
            module_name="blackworm",
            bot_name="BlackWorm",
            description="RAT developed in .NET",
            authors=["Brian Wallace (@botnet_hunter)"],
            version="1.0.0",
            date="May 20, 2015",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None
        self.prng_seed = 0

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("blackworm.yara")
        return self.yara_rules

    def get_bot_information(self, file_data):
        results = {}
        wide_strings = [i for i in data_strings_wide(file_data)]
        for x in xrange(len(wide_strings)):
            s = wide_strings[x]
            if is_ip_or_domain(s):
                ip = s
                port = int(wide_strings[x + 1])
                results['c2_uri'] = "tcp://{0}:{1}".format(ip, port)
                break
        return results


Modules.list.append(BlackWorm())