from common import Modules, data_strings_wide, load_yara_rules, PEParseModule, ModuleMetadata


class Cythosia(PEParseModule):
    def __init__(self):
        md = ModuleMetadata(
            module_name="cythosia",
            bot_name="Cythosia",
            description="DDoS Bot",
            authors=["Brian Wallace (@botnet_hunter)"],
            version="1.0.0",
            date="March 21, 2015",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("cythosia.yara")
        return self.yara_rules

    def get_bot_information(self, file_data):
        results = {}
        c2s = set()
        for s in data_strings_wide(file_data):
            if s.startswith("http://") and s != "http://":
                c2s.add(s)
        for c2 in c2s:
            if "c2s" not in results:
                results["c2s"] = []
            results["c2s"].append({"c2_uri": c2})
        return results


Modules.list.append(Cythosia())