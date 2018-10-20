from common import Modules, data_strings_wide, load_yara_rules, PEParseModule, ModuleMetadata
from string import lowercase, uppercase, punctuation, digits


class projecthook(PEParseModule):
    def __init__(self):
        md = ModuleMetadata(
            module_name="projecthook",
            bot_name="ProjectHook",
            description="Point of sale malware designed to extract credit card information from RAM",
            authors=["Brian Wallace (@botnet_hunter)"],
            version="1.1.0",
            date="August 9, 2014",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None
        pass

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("projecthook.yara")
        return self.yara_rules

    def get_bot_information(self, file_data):
        results = {}
        gate = None
        for s in data_strings_wide(file_data, charset=lowercase + uppercase + punctuation + digits):
            if s.endswith(".php"):
                if gate is None:
                    gate = set()
                gate.add(s)
        if gate is not None:
            results["c2s"] = []
            for p in gate:
                results["c2s"].append({"c2_uri": p})
        return results


Modules.list.append(projecthook())