from common import Modules, data_strings, load_yara_rules, PEParseModule, ModuleMetadata, is_ip_or_domain


class dexter(PEParseModule):
    def __init__(self):
        md = ModuleMetadata(
            module_name="dexter",
            bot_name="Dexter",
            description="Point of sale malware designed to extract credit card information from RAM",
            authors=["Brian Wallace (@botnet_hunter)"],
            version="1.0.0",
            date="March 14, 2014",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None
        pass

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("dexter.yara")
        return self.yara_rules

    def get_bot_information(self, file_data):
        results = {}
        gate = None
        server = None
        for s in data_strings(file_data):
            if s.find(".php") != -1:
                if s[0] != "/":
                    s = "/" + s
                gate = s
            if is_ip_or_domain(s):
                server = s
        if server is not None and gate is not None:
            results["c2_uri"] = "%s%s" % (server, gate)
        return results


Modules.list.append(dexter())