from rule_chains import get_names, get_patterns, get_grokit_config
from rule_chains.frontend import GrokFrontend
import logging
import argparse


parser = argparse.ArgumentParser(description='Start syslog-grok-mongo captures.')

parser.add_argument('-mhost', type=str, default='',
                    help='mongo host address or name')
parser.add_argument('-mport', type=int, default=27017,
                    help='mongo port')
parser.add_argument('-muser', type=str, default=None,
                    help='mongo username')
parser.add_argument('-mpass', type=str, default=None,
                    help='mongo user password')
parser.add_argument('-mdb', type=str, default=None,
                    help='mongo db name')

parser.add_argument('-shost', type=str, default='',
                    help='syslog listener host address or name')
parser.add_argument('-sport', type=int, default=5001,
                    help='syslog listener port (udp)')

parser.add_argument('-cpdir', type=str, default=get_patterns(),
                    help='directory containing custom grok patterns directory')
parser.add_argument('-names', type=str, default=get_names(),
                    help='file containing all the names for rule patterns')
parser.add_argument('-gconfig', type=str, default=get_grokit_config(),
                    help='Grok frontend configuration for rule chains')

parser.add_argument('-known_hosts', type=str, default=None,
                    help='file containing all the <ip> <name> for known hosts')

logging.getLogger().setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(message)s')
ch.setFormatter(formatter)
logging.getLogger().addHandler(ch)


def setup_known_hosts(parser_args):
    global KNOWN_HOSTS
    known_hosts = parser_args.known_hosts
    if known_hosts is not None:
        logging.debug("Loading known hosts")
        data = open(known_hosts).read()
        for line in data.splitlines():
            if len(line.strip()) == 0:
                continue
            ip, host = line.strip().split()
            KNOWN_HOSTS[ip] = host
        logging.debug("Loading known hosts completed")


def setup_grokker(parser_args):
    patterns_dir = parser_args.cpdir
    config = parser_args.gconfig
    names = parser_args.names
    logging.debug("Loading grok rules")
    gr = GrokFrontend(  # default chains configuration
                      config=config,
                      # patterns created for pfsense filterlog and openvpn
                      custom_patterns_dir=patterns_dir,
                      # patterns to load individual groks for
                      patterns_names=names)
    logging.debug("Loading grok rules completed")
    return gr

if __name__ == "__main__":
    args = parser.parse_args()
    mongo_backend = MongoConnection(args.mhost, args.mport,
                                    args.muser, args.mpass,
                                    args.mdb)
    grok_frontend = setup_grokker(args)
    setup_known_hosts(args)
    SyslogUDPHandler.set_mongo_backend(mongo_backend)
    SyslogUDPHandler.set_grok_frontend(grok_frontend)
    try:
        logging.debug("Starting the syslog listener")
        server = SocketServer.UDPServer(
                  (args.shost, args.sport), SyslogUDPHandler)
        server.serve_forever(poll_interval=0.5)
    except (IOError, SystemExit):
        raise
    except KeyboardInterrupt:
        raise

