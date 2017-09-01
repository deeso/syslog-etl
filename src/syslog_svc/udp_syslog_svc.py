#!/usr/bin/env python
# based on: https://gist.github.com/marcelom/4218010
import logging
import SocketServer
import sys
from pymongo import MongoClient
from bson.objectid import ObjectId
import urllib
from home_soc_parsers.grokit import GrokIt
from hashlib import sha256
import argparse
import socket

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

parser.add_argument('-cpdir', type=str, default=None,
                    help='custom patterns directory for GrokIt')
parser.add_argument('-names', type=str, default=None,
                    help='file containing all the names for GrokIt patterns')

parser.add_argument('-known_hosts', type=str, default=None,
                    help='file containing all the <ip> <name> for known hosts')

logging.getLogger().setLevel(logging.DEBUG)

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(message)s')
ch.setFormatter(formatter)
logging.getLogger().addHandler(ch)

KNOWN_HOSTS = {}
GROKKER = None
MONGO_CON = None

class MongoConnection(object):
    DB_NAME = 'syslog-events'
    GROKKED_COLLECTION = 'groked-messages'
    RAW_COLLECTION = 'syslog-messages'
    JSON_COLLECTION = 'syslog-messages-parsed'
    FMT_UP = "mongodb://{username}:{password}@{host}:{port}"
    FMT_NUP = "mongodb://{host}:{port}"

    def __init__(self, host, port, user=None, password=None, db_name=None):
        global MONGO_CON
        self.host = host
        self.port = port
        self.password = None
        if password is not None:
            self.password = urllib.quote_plus(password)
        self.user = user
        self.db_name = self.DB_NAME if db_name is None else db_name
        self.uri = self.FMT_NUP.format(**{'host': host, 'port': port})
        if self.user is not None and self.password is not None:
            self.uri = self.FMT_NUP.format(**{'host': host, 'port': port,
                                              'username': user,
                                              'password': self.password})
        MONGO_CON = self

    def has_obj(self, mongodb_col, data):
        x = [i for i in mongodb_col.find(data).limit(1)]
        return len(x) > 0 

    def insert_raw(self, syslog_msg, check_id=True):
        sm = {'message_source': 'syslog',
              'message': syslog_msg, 'raw': syslog_msg,
              '_id': sha256(syslog_msg).hexdigest()}
        conn = MongoClient(self.uri)
        db = conn[self.db_name]
        col = db[self.RAW_COLLECTION]
        failed_check = True
        if check_id:
            failed_check = not self.has_obj(col, {'_id':sm['_id']})

        if not failed_check:
            x = [i for i in col.find({'_id':sm['_id']}).limit(1)][0]
            return False, x['_id']
        return True, col.insert_one(sm).inserted_id

    def insert_json(self, json_data, check_id=True):
        conn = MongoClient(self.uri)
        db = conn[self.db_name]
        col = db[self.JSON_COLLECTION]
        if check_id and '_id' in json_data:
            failed_check = not self.has_obj(col, {'_id':json_data['_id']})

        if not failed_check:
            x = [i for i in col.find({'_id':json_data['_id']}).limit(1)][0]
            return False, x['_id']
        return True, col.insert_one(json_data).inserted_id


class SyslogUDPHandler(SocketServer.BaseRequestHandler):
    SYSLOG_MSG_TYPE = {
        0: "EMERGENCY",
        1: "ALERT",
        2: "CRITICAL",
        3: "ERROR",
        4: "WARNING",
        5: "NOTICE",
        6: "INFORMATIONAL",
        7: "DEBUG",
    }

    def resolve_host(self, ip):
        if ip in KNOWN_HOSTS:
            return KNOWN_HOSTS[ip]
        try:
            name, _, _ = socket.gethostbyname(ip)
            KNOWN_HOSTS[ip] = name
        except:
            name = ip
            KNOWN_HOSTS[ip] = name
        return name

    def insert_syslog_host(self, data, host):
        tag, rest = data.split('>')
        msg = tag + '>' + " ".join([rest[:15], host, rest[16:]])
        return msg

    def split_alert_message(self, data):
        t = ''
        msg = data
        end = data.find('>')
        start = data.find('<')
        if len(data) < end+1:
            return '', msg
        if start == 0 and end > 0 and end < 10:
            t = data[start+1:end]
            if not t.isdigit():
                return '', data
            else:
                msg = data[end+1:]
        return t, msg


    def calculate_msg_type(self, data):
        t, msg = self.split_alert_message(data)
        if len(t) == 0:
            return "UNKNOWN"
        v = int(t, 10)
        if v > 7:
            v &= 0x7
        return self.SYSLOG_MSG_TYPE[v]

    def create_json(self, syslog_msg):
        sm = {'log_type': "syslog", 'raw': '',
              '_id': sha256(syslog_msg).hexdigest()}
        sm['msg_tag_text'] = self.calculate_msg_type(syslog_msg)
        t, msg = self.split_alert_message(syslog_msg)
        sm['raw'] = msg
        sm['msg_tag'] = t
        grok_results = GROKKER.runall_grok_patterns_match_text(syslog_msg)
        max_sz = 0
        _r = {}
        for name, result in grok_results.items():
            if result is None or len(result) == 0:
                continue
            result['patterns'] = [name]
            if len(result) > max_sz:
                _r = result
            elif len(result) == max_sz:
                print _r
                _patterns = _r['patterns']
                _patterns.append(name)
                _r.update(result)
                _r['patterns'] = _patterns
        result = _r
        result.update(sm)
        return result

    def handle(self):
        logging.debug("Handling syslog message")
        data = bytes.decode(self.request[0].strip())
        # socket = self.request[1]
        #print data
        logging.debug("Resolving syslog message source")
        host = self.resolve_host(self.client_address[0])
        #print data
        logging.debug("Mutating syslog message with source")
        data = self.insert_syslog_host(data,  host)
        # Getting duplicates, so moved this down below
        # print( "%s : " % self.client_address[0], str(data))
        logging.info(str(data))
        # results = {}
        # pass to grokit
        # take results send to mongodb
        json_data = self.create_json(data)
        inserted, result = MONGO_CON.insert_raw(data)
        inserted2, result = MONGO_CON.insert_json(json_data)
        msg_type = self.calculate_msg_type(data)
        if inserted:
            logging.info('Inserted into the raw collection:'+msg_type+':'+str(data))
        if inserted2:
            logging.info('Inserted into the json collection:'+msg_type+':'+str(data))


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
    global GROKKER
    cpdir = parser_args.cpdir
    names = parser_args.names
    if names is None:
        p = "Must specify a names file containing patterns of interest"
        raise Exception(p)
    logging.debug("Loading grok rules")
    GROKKER = GrokIt(names, custom_patterns_dir=cpdir)
    logging.debug("Loading grok rules completed")


if __name__ == "__main__":
    args = parser.parse_args()
    MongoConnection(args.mhost, args.mport, args.muser, args.mpass, args.mdb)
    setup_grokker(args)
    setup_known_hosts(args)
    try:
        logging.debug("Starting the syslog listener")
        server = SocketServer.UDPServer((args.shost, args.sport), SyslogUDPHandler)
        server.serve_forever(poll_interval=0.5)
    except (IOError, SystemExit):
        raise
    except KeyboardInterrupt:
        raise
