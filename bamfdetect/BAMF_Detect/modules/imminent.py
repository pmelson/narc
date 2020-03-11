from common import Modules, data_strings_wide, load_yara_rules, PEParseModule, ModuleMetadata, is_ip_or_domain


class imminent(PEParseModule):

    def __init__(self):
        md = ModuleMetadata(
            module_name="imminent",
            bot_name="imminent",
            description="RAT, infostealer, cryptominer",
            authors=["Paul Melson @pmelson"],
            version="1.0.0",
            date="February 21, 2020",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None


    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("imminent.yara")
        return self.yara_rules


    def get_bot_information(self, file_data):
        results = {}
        wide_strings = [i for i in data_strings_wide(file_data, 1)]
        start_index = 0
        wide_strings = wide_strings[start_index:]
        for i in range(0, len(wide_strings)):
            if wide_strings[i] == "_ENABLE_PROFILING":
                for j in range(1,12):
                    if is_ip_or_domain(wide_strings[i+j]):
                        results['c2_uri'] = wide_strings[i+j]
                        return results

        return results


Modules.list.append(imminent())
