from common import Modules, data_strings_wide, load_yara_rules, PEParseModule, ModuleMetadata, is_ip_or_domain
import pype32

class atraps(PEParseModule):
    def __init__(self):
        md = ModuleMetadata(
            module_name="atraps",
            bot_name="atraps",
            description="atraps aka NYAN w0rm",
            authors=["Brian Wallace (@botnet_hunter)", "Paul Melson (@pmelson)","Kevin Breen (code borrowed from RATdecoders project"],
            version="1.0.0",
            date="June 26, 2019",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("atraps.yara")
        return self.yara_rules

    @staticmethod
    def _is_number(s):
        if s != s.strip():
            return False
        try:
            if int(s) < 65536:
                return True
            return False
        except KeyboardInterrupt:
            raise
        except:
            return False

    @staticmethod
    def _get_strings(pe, dir_type):
        string_list = []
        m = pe.ntHeaders.optionalHeader.dataDirectory[14].info
        for s in m.netMetaDataStreams[dir_type].info:
            for offset, value in s.iteritems():
                string_list.append(value)
        return string_list

    @staticmethod
    def _parse_config(string_list):
        config_dict = {}
        if string_list[23] == 'v0.3':
            config_dict["version"] = string_list[23]
            config_dict["Domain"] = string_list[24]
            config_dict["Port"] = string_list[25]
            return config_dict
        if string_list[28] == 'v0.2.3' or string_list[28] == 'v0.2.5':
            config_dict["version"] = string_list[28]
            config_dict["Domain"] = string_list[29]
            config_dict["Port"] = string_list[30]
            return config_dict
        if string_list[28] == 'NYAN WORM v0.1':
            config_dict["version"] = string_list[28]
            config_dict["Domain"] = string_list[30]
            config_dict["Port"] = string_list[31]
            return config_dict
        if string_list[29] == 'v0.3.5':
            config_dict["version"] = string_list[29]
            config_dict["Domain"] = string_list[30]
            config_dict["Port"] = string_list[31]
            return config_dict

    def get_bot_information(self, file_data):
        results = {}
        pe = pype32.PE(data=file_data)
        string_list = atraps._get_strings(pe, 2)
        config_dict = atraps._parse_config(string_list)
        if config_dict:
            domain = config_dict["Domain"]
            port = config_dict["Port"]
            results['c2_uri'] = "tcp://{0}:{1}".format(domain, port)
            results['version'] = config_dict["version"]
        return results


Modules.list.append(atraps())
