#!/usr/bin/env python
# based on: https://gist.github.com/marcelom/4218010
import logging
import SocketServer
import sys
from hashlib import sha256
import socket
from etl import ETL

logging.getLogger().setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(message)s')
ch.setFormatter(formatter)
logging.getLogger().addHandler(ch)


KNOWN_HOSTS = {}
ETL_FRONTEND = None
MONGO_CON = None


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
    MONGO_CON = None
    ETL_FRONTEND = None

    @classmethod
    def get_server(cls, shost, sport):
        try:
            logging.debug("starting the syslog listener")
            server = SocketServer.UDPServer((shost, sport), cls)
            return server
        except:
            raise

    @classmethod
    def set_mongo_backend(cls, mongo_backend):
        cls.MONGO_CON = mongo_backend

    @classmethod
    def etl_frontend(cls, etl_frontend):
        cls.ETL_FRONTEND = etl_frontend

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
        result = {}
        try:
            result = ETL.syslog_et(syslog_msg)
        except:
            raise

        result.update(sm)
        return result

    def handle(self):
        logging.debug("Handling syslog message")
        data = bytes.decode(self.request[0].strip())
        logging.debug("Resolving syslog message source")
        host = self.resolve_host(self.client_address[0])
        logging.debug("Mutating syslog message with source")
        data = self.insert_syslog_host(data,  host)
        logging.info(str(data))
        json_data = self.create_json(data)
        inserted, result = self.MONGO_CON.insert_raw(data)
        inserted2, result = self.MONGO_CON.insert_json(json_data)
        msg_type = self.calculate_msg_type(data)
        if inserted:
            logging.info('Inserted into the raw collection:'+msg_type+':'+str(data))
        if inserted2:
            logging.info('Inserted into the json collection:'+msg_type+':'+str(json_data))


