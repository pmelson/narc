from common import Modules, data_strings, load_yara_rules, PEParseModule, ModuleMetadata, is_ip_or_domain
from pefile import PE


class backoff(PEParseModule):
    def __init__(self):
        md = ModuleMetadata(
            module_name="backoff",
            bot_name="Backoff",
            description="Point of sale malware designed to extract credit card information from RAM",
            authors=["Brian Wallace (@botnet_hunter)"],
            version="1.0.1",
            date="August 24, 2014",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None
        pass

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("backoff.yara")
        return self.yara_rules

    def get_bot_information(self, file_data):
        results = {}
        gate = None
        server = None
        pe = PE(data=file_data)
        for x in xrange(len(pe.sections)):
            for s in data_strings(pe.get_data(pe.sections[x].VirtualAddress)):
                if s.find(".php") != -1:
                    if s[0] != "/":
                        s = "/" + s
                    if gate is None:
                        gate = set()
                    gate.add(s)
                if is_ip_or_domain(s):
                    if server is None:
                        server = set()
                    server.add(s)
        if server is not None and gate is not None:
            results["c2s"] = []
            for ip in server:
                for p in gate:
                    uri = "%s%s" % (ip, p)
                    results["c2s"].append({"c2_uri": uri})
        return results


Modules.list.append(backoff())