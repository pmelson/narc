from common import Modules, data_strings, load_yara_rules, PEParseModule, ModuleMetadata, is_ip_or_domain


class pony(PEParseModule):
    def __init__(self):
        md = ModuleMetadata(
            module_name="pony",
            bot_name="Pony",
            description="",
            authors=["Brian Wallace (@botnet_hunter)"],
            version="1.1.0",
            date="April 14, 2014",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None
        pass

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("pony.yara")
        return self.yara_rules

    def get_bot_information(self, file_data):
        results = {}
        uri = None
        uris = []
        all_uris = []
        for s in data_strings(file_data):
            if s.startswith("http://") and len(s) > len("http://"):
                domain = s[7:]
                if domain.find('/') != -1:
                    domain = domain[:domain.find('/')]
                if is_ip_or_domain(domain):
                    all_uris.append(s)
                    if s.endswith(".php"):
                        uri = s
                        uris.append(s)
        if uri is not None and len(uris) > 0:
            if "c2s" not in results:
                results["c2s"] = []
            for i in uris:
                results["c2s"].append({"c2_uri": i})
            results["all_uris"] = list(set(all_uris))
        return results


Modules.list.append(pony())