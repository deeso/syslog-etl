from rule_chains.frontend import GrokFrontend
from rule_chains import get_names, get_patterns, get_grokit_config
import socket

LOG_STASH_HOST = '10.18.120.13'
LOG_STASH_PORT = 5002
LOG_STASH_PROTO = 'UDP'
LOG_STASH_SOCK = None



DEFAULT_NAMES = get_names()
DEFAULT_PATTERNS = get_patterns()
GROK_FE = None
DEFAULT_CONFIG = get_grokit_config()
SYSLOG_DISPATCH = 'syslog_dispatcher'


class ETL(object):
    

    @classmethod
    def get_logstash_server(cls):
        global LOG_STASH_HOST, LOG_STASH_PORT
        return (LOG_STASH_HOST, LOG_STASH_PORT)

    @classmethod
    def get_logstash_sock(cls, force_reconnect=False):
        global LOG_STASH_PROTO, LOG_STASH_PORT, LOG_STASH_HOST, LOG_STASH_SOCK
        sock = None
        if LOG_STASH_SOCK is not None and not force_reconnect:
            return LOG_STASH_SOCK
        if LOG_STASH_PROTO.lower() == 'tcp':
            sock =  socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(cls.get_logstash_server())
        elif LOG_STASH_PROTO.lower() == 'udp':
            sock =  socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            raise Exception("Unknown protocol %s"%LOG_STASH_PROTO)
        LOG_STASH_SOCK = sock
        return sock

    @classmethod
    def send_msg(cls, message):
        global LOG_STASH_PROTO
        conn = cls.get_logstash_sock()
        server = cls.get_logstash_server()
        if LOG_STASH_PROTO.lower() == 'udp':
            try:
                l = conn.sendto(message, server)
                return True, l
            except Exception as e:
                raise e
        elif LOG_STASH_PROTO.lower() == 'tcp':
            try:
                l = conn.send(message)
                return True, l
            except Exception as e:
                raise e
        else:
            raise Exception("Unknown protocol %s"%LOG_STASH_PROTO)

    @classmethod
    def build_grok_etl(cls, config=DEFAULT_CONFIG, names=DEFAULT_NAMES,
                     custom_patterns=DEFAULT_PATTERNS):
        gfe = GrokFrontend(config=config, custom_patterns_dir=custom_patterns,
                            patterns_names=names)
        return gfe

    @classmethod
    def create_global_gfe(cls, config=DEFAULT_CONFIG, names=DEFAULT_NAMES,
                     custom_patterns=DEFAULT_PATTERNS):
        global GROK_FE
        GROK_FE = cls.build_grok_etl(config=config, names=names,
                                   custom_patterns=custom_patterns)
        return GROK_FE

    @classmethod
    def syslog_et(cls, syslog_msg, exclude_results=['SYSLOG_PRE', 'SYSLOG_PRE_MSG']):
        global GROK_FE
        my_fe = GROK_FE
        if my_fe is None:
            my_fe = cls.build_grokit()
        # 'syslog_app_dispatch'
        try:
            fe_results = my_fe.execute_dispatch_table(SYSLOG_DISPATCH, syslog_msg)
            if fe_results['outcome']:
                return fe_results['rule_results']
        except:
            pass

        fe_results = my_fe.match_runall_patterns(syslog_msg)
        print fe_results
        for n,v in fe_results.items():
            if n in exclude_results:
                continue
            if v is not None and 'rule_results' in v and \
               len(v['rule_results']) > 0:
                return v
        return {}
