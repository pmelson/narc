from common import Modules, data_strings, load_yara_rules, PEParseModule, ModuleMetadata


class vertexnet(PEParseModule):
    def __init__(self):
        md = ModuleMetadata(
            module_name="vertexnet",
            bot_name="VertexNet",
            description="General purpose malware",
            authors=["Brian Wallace (@botnet_hunter)"],
            version="1.0.0",
            date="March 25, 2015",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None
        pass

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("vertexnet.yara")
        return self.yara_rules

    def get_bot_information(self, file_data):
        results = {}
        for s in data_strings(file_data):
            if r'<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">' in s:
                s = s[:s.find(r'<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">')]
                config = []
                c = ""
                index = 0
                for x in s:
                    c += x
                    index += 1
                    if index % 4 == 0 and (c.endswith("P") or c.endswith("PA") or c.endswith("PAD")):
                        for suff in ["P", "PA", "PAD"]:
                            if c.endswith(suff):
                                c = c[:-len(suff)]
                                break
                        config.append(c)
                        c = ""
                if len(c) > 0:
                    config.append(c)

                if len(config) == 7:
                    results['drop_location'] = config[0]
                    results['cmd_get_interval'] = int(config[1])
                    results['http_port'] = int(config[2])
                    results['refresh_interval'] = int(config[3])
                    results['mutex'] = config[4]
                    results['http_path'] = config[5]
                    results['server'] = config[6]
                    if results['server'].startswith("http://"):
                        results['server'] = results['server'][len('http://'):]
                    if results['server'].endswith("/"):
                        results['server'] = results['server'][:-1]
                    results['c2_uri'] = "http://{0}:{1}{2}".format(results['server'], results['http_port'], results['http_path'])
                    return results
        return results


Modules.list.append(vertexnet())