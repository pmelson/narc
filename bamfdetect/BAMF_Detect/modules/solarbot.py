from common import Modules, data_strings, load_yara_rules, PEParseModule, ModuleMetadata, is_ip_or_domain


class Solar(PEParseModule):
    def __init__(self):
        md = ModuleMetadata(
            module_name="solar",
            bot_name="Solar",
            description="Botnet",
            authors=["Brian Wallace (@botnet_hunter)"],
            version="1.0.0",
            date="March 21, 2015",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("solarbot.yara")
        return self.yara_rules

    def get_bot_information(self, file_data):
        results = {}
        c2s = set()
        ip = None
        path = None
        next_is_path = False
        start_checking = False
        for s in data_strings(file_data, 1):
            if s == "C:\\swi.txt":
                start_checking = True
            if start_checking and path is None:
                if next_is_path:
                    if s.startswith("http://"):
                        ip = None
                        path = None
                        next_is_path = False
                        continue
                    path = s
                    next_is_path = False
                elif is_ip_or_domain(s) and ip is None:
                    ip = s
                    next_is_path = True
        if ip is not None and path is not None:
            results['c2_uri'] = "http://{0}{1}".format(ip, path)
        return results


Modules.list.append(Solar())