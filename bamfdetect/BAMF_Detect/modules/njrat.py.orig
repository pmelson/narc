from common import Modules, data_strings_wide, load_yara_rules, PEParseModule, ModuleMetadata, is_ip_or_domain


class njRat(PEParseModule):
    def __init__(self):
        md = ModuleMetadata(
            module_name="njrat",
            bot_name="njRat",
            description="RAT",
            authors=["Brian Wallace (@botnet_hunter)"],
            version="1.1.0",
            date="May 27, 2015",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("njrat.yara")
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

    def get_bot_information(self, file_data):
        # todo Pimp this out with https://github.com/kevthehermit/RATDecoders/blob/master/njRat.py
        results = {}
        wide_strings = [i for i in data_strings_wide(file_data, 1)]
        #if "[endof]" not in wide_strings:
        #    return results
        #wide_strings = wide_strings[:wide_strings.index("[endof]")]

        start_index = 0
        for x in xrange(len(wide_strings)):
            if wide_strings[x].startswith("0.") or "netsh firewall add allowedprogram" in wide_strings[x]:
                start_index = x
                break

        wide_strings = wide_strings[start_index:]

        potential_domains = [d for d in wide_strings if is_ip_or_domain(d)]
        potential_ports = [int(p) for p in wide_strings if njRat._is_number(p)]

        extra_domains = ["winlogon.com", "Microsoft.com"]
        for d in extra_domains:
            if d in potential_domains:
                potential_domains.remove(d)

        if len(potential_ports) > 1:
            potential_ports = [p for p in potential_ports if p > 10]

        #print potential_ports
        #print potential_domains

        # todo have less shitty extraction method
        if len(potential_domains) > 0 and len(potential_ports) > 0:
            if potential_domains[0].endswith(":" + str(potential_ports[0])):
                results['c2_uri'] = "tcp://{0}".format(potential_domains[0])
            else:
                results['c2_uri'] = "tcp://{0}:{1}".format(potential_domains[0], potential_ports[0])
        #else:
        #    print "SHIT {0} {1}".format(potential_domains, potential_ports)

        return results


Modules.list.append(njRat())