from common import Modules, data_strings, load_yara_rules, PEParseModule, ModuleMetadata, is_ip_or_domain


class glassrat(PEParseModule):
    def __init__(self):
        md = ModuleMetadata(
            module_name="glassrat",
            bot_name="GlassRAT",
            description="Trojan",
            authors=["Brian Wallace (@botnet_hunter)"],
            version="1.0.0",
            date="November 25, 2015",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("glassrat.yara")
        return self.yara_rules

    def get_bot_information(self, file_data):
        results = {}

        for s in [i for i in file_data[file_data.find("%%temp%%\%u") + len("%%temp%%\%u"):][:670].split('\x00') if len(i) > 4]:
            l = list(s)
            o = []
            for c in l:
                o.append(chr(ord(c) ^ 0x1))

            if "c2s" not in results:
                results["c2s"] = []

            results["c2s"].append({"c2_uri": "".join(o)})

        return results


Modules.list.append(glassrat())