from common import Modules, load_yara_rules, PHPParseModule, ModuleMetadata
from re import compile as recompile, MULTILINE
from urllib import urlencode


class pbot(PHPParseModule):
    def __init__(self):
        md = ModuleMetadata(
            module_name="pbot",
            bot_name="pBot",
            description="PHP IRC bot which can be used to drop other malware, spread and launch denial of service "
                        "attacks",
            authors=["Brian Wallace (@botnet_hunter)"],
            version="1.0.0",
            date="March 14, 2014",
            references=[]
        )
        PHPParseModule.__init__(self, md)
        self.yara_rules = None
        pass

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("pbot.yara")
        return self.yara_rules

    def get_config_values(self, config):
        try:
            p = recompile(r'[\'"](?P<key>[^\'"]+)[\'"][\s]*=>[\s]*[\'"](?P<value>[^\'"]+)[\'"]', MULTILINE)
            results = p.findall(config)
            ret = {}
            for pair in results:
                ret[unicode(pair[0], errors='ignore')] = unicode(pair[1], errors='ignore')
            return ret
        except:
            return {}

    def get_bot_information(self, file_data):
        ret = {}
        try:
            p = recompile(r'var[\s]+\$config[\s]*=[\s]*array[\s]*\([\s]*(\"[^\"]*\"[\s]*=>.*,?[\s]*)*(//)?\);', MULTILINE)
            result = p.search(file_data)
            if result is None:
                return {}
            ret = self.get_config_values(result.group(0))
            uris = []
            server = ret['server'] if 'server' in ret else None
            server_pass = ret['pass'] if "pass" in ret else None
            port = int(ret['port']) if 'port' in ret else 6667
            chan = ret['chan'] if 'chan' in ret else None
            chan2 = ret['chan2'] if 'chan2' in ret else None
            key = ret['key'] if 'key' in ret else server_pass

            uris.append("pbot://{0}:{1}/?{2}".format(server, port, urlencode({"server_pass": server_pass,
                                                                              "chan": chan, "channel_pass": key})))
            if chan2 is not None:
                uris.append("pbot://{0}:{1}/?{2}".format(server, port, urlencode({"server_pass": server_pass,
                                                                                  "chan": chan2, "channel_pass": key})))
            ret['c2s'] = []
            for uri in uris:
                ret['c2s'].append({"c2_uri": uri})

        except KeyboardInterrupt:
            raise
        except:
            pass
        return ret

Modules.list.append(pbot())