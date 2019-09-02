from common import Modules, data_strings, load_yara_rules, PEParseModule, ModuleMetadata, is_ip_or_domain


class virusrat(PEParseModule):
    def __init__(self):
        md = ModuleMetadata(
            module_name="virusrat",
            bot_name="VirusRat",
            description="Remote access trojan",
            authors=["Paul Melson (@pmelson)"],
            version="1.0.0",
            date="December 7, 2018",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None
        pass


    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("virusrat.yara")
        return self.yara_rules


    def get_bot_information(self, file_data):
        results = {}
        config = data.split("abccba")
        if len(config) > 5:
            dict["Domain"] = config[1]
            dict["Port"] = config[2]
            dict["Campaign Name"] = config[3]
            dict["Copy StartUp"] = config[4]
            dict["StartUp Name"] = config[5]
            dict["Add To Registry"] = config[6]
            dict["Registry Key"] = config[7]
            dict["Melt + Inject SVCHost"] = config[8]
            dict["Anti Kill Process"] = config[9]
            dict["USB Spread"] = config[10]
            dict["Kill AVG 2012-2013"] = config[11]
            dict["Kill Process Hacker"] = config[12]
            dict["Kill Process Explorer"] = config[13]
            dict["Kill NO-IP"] = config[14]
            dict["Block Virus Total"] = config[15]
            dict["Block Virus Scan"] = config[16]
            dict["HideProcess"] = config[17]
        return dict

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


Modules.list.append(virusrat())
