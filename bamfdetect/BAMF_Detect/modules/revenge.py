from common import Modules, data_strings_wide, load_yara_rules, PEParseModule, ModuleMetadata, is_ip_or_domain


class Revenge(PEParseModule):
    def __init__(self):
        md = ModuleMetadata(
            module_name="revenge",
            bot_name="Revenge",
            description="RAT",
            authors=["Paul Melson @pmelson", "Brian Wallace (@botnet_hunter)"],
            version="1.0",
            date="July 12, 2017",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("revenge.yara")
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
        results = {}
        wide_strings = [i for i in data_strings_wide(file_data, 1)]
        start_index = 0

        wide_strings = wide_strings[start_index:]

        potential_domains = []
        for d in wide_strings:
          if d.endswith(',') and len(d) > 4:
            h = []
            h = d[:-1].strip().split(',')
            for j in h:
              if is_ip_or_domain(j):
                potential_domains.append(j)
        potential_ports = []
        for p in wide_strings:
          if p.endswith(',') and len(p) > 2:
            t = []
            t = p[:-1].strip().split(',')
            for u in t:
              if Revenge._is_number(u):
                potential_ports.append(u)
#        potential_ports = [int(p) for p in wide_strings if Revenge._is_number(p)]

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
          if len(potential_domains) == 1 and len(potential_ports) == 1:
            if potential_domains[0].endswith(":" + str(potential_ports[0])):
                results['c2_uri'] = "tcp://{0}".format(potential_domains[0])
            else:
                results['c2_uri'] = "tcp://{0}:{1}".format(potential_domains[0], potential_ports[0])
          else:
            results['c2s'] = []
            i=0
            while i < len(potential_domains):
              results['c2s'].append({"c2_uri": "tcp://{0}:{1}".format(potential_domains[i], potential_ports[i])})
              i+=1
        return results


Modules.list.append(Revenge())
