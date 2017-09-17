from rule_chains.frontend import GrokFrontend
from rule_chains import get_names, get_patterns, get_grokit_config
import socket
import logging

ETL_DEST_HOST = '10.18.120.13'
ETL_DEST_PORT = 5002
ETL_DEST_PROTO = 'UDP'
ETL_DEST_SOCK = None



DEFAULT_NAMES = get_names()
DEFAULT_PATTERNS = get_patterns()
GROK_FE = None
DEFAULT_CONFIG = get_grokit_config()
SYSLOG_DISPATCH = 'syslog_dispatcher'


class ETL(object):

    @classmethod
    def setup_grokker(cls, parser_args):
        global ETL_DEST_PROTO, ETL_DEST_HOST, ETL_DEST_PORT
        patterns_dir = parser_args.cpdir
        config = parser_args.gconfig
        names = parser_args.names
        ETL_DEST_PROTO = getattr(parser_args, 'lproto', ETL_DEST_PROTO)
        ETL_DEST_HOST = getattr(parser_args, 'lhost', ETL_DEST_HOST)
        ETL_DEST_PORT = getattr(parser_args, 'lport', ETL_DEST_PORT)
        logging.debug("Loading Grok ETL")
        gr = cls.create_global_gfe(  # default chains configuration
                          config=config,
                          # patterns created for pfsense filterlog and openvpn
                          custom_patterns=patterns_dir,
                          # patterns to load individual groks for
                          names=names)
        logging.debug("Loading Grok ETL completed")
        return gr

    @classmethod
    def get_logstash_server(cls):
        global ETL_DEST_HOST, ETL_DEST_PORT
        return (ETL_DEST_HOST, ETL_DEST_PORT)

    @classmethod
    def get_logstash_sock(cls, force_reconnect=False):
        global ETL_DEST_PROTO, ETL_DEST_PORT, ETL_DEST_HOST, ETL_DEST_SOCK
        sock = None
        if ETL_DEST_SOCK is not None and not force_reconnect:
            return ETL_DEST_SOCK
        if ETL_DEST_PROTO.lower() == 'tcp':
            sock =  socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(cls.get_logstash_server())
        elif ETL_DEST_PROTO.lower() == 'udp':
            sock =  socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            raise Exception("Unknown protocol %s"%ETL_DEST_PROTO)
        ETL_DEST_SOCK = sock
        return sock

    @classmethod
    def send_msg(cls, message):
        global ETL_DEST_PROTO
        conn = cls.get_logstash_sock()
        server = cls.get_logstash_server()
        if ETL_DEST_PROTO.lower() == 'udp':
            try:
                l = conn.sendto(message, server)
                return True, l
            except Exception as e:
                raise e
        elif ETL_DEST_PROTO.lower() == 'tcp':
            try:
                l = conn.send(message)
                return True, l
            except Exception as e:
                raise e
        else:
            raise Exception("Unknown protocol %s"%ETL_DEST_PROTO)

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
