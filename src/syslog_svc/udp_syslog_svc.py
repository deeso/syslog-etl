#!/usr/bin/env python
# based on: https://gist.github.com/marcelom/4218010
import logging
import SocketServer
import sys
import json
from hashlib import sha256
import socket
from datetime import datetime
from etl import ETL
# import logstash
import pytz

TZ_ASCII = 'America/Chicago'
MY_TZ = pytz.timezone(TZ_ASCII)



logging.getLogger().setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(message)s')
ch.setFormatter(formatter)
logging.getLogger().addHandler(ch)

import sys

host = 'localhost'

test_logger = None


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

    def format_timestamp(self, tstamp):
        global MY_TZ
        local_tz = MY_TZ.localize(tstamp, is_dst=None)
        utc_tz = local_tz.astimezone(pytz.utc)
        return utc_tz.strftime("%Y-%m-%dT%H:%M:%S") + ".%03d" % (tstamp.microsecond / 1000) + "Z" 

    def send_to_logstash(self, json_data):
        global test_logger
        if test_logger is None:
            try:
                import logstash
                test_logger = logging.getLogger('python-logstash-logger')
                test_logger.setLevel(logging.INFO)
                etl_host, etl_port = ETL.get_logstash_server()
                test_logger.addHandler(logstash.LogstashHandler(etl_host,
                                                                etl_port,
                                                                version=1))
            except:
                raise
        test_logger.info('python-logstash', extra=json_data)

    def create_json(self, syslog_msg):
        r = {'source': "syslog", 'raw': syslog_msg, 
              'type':'json',
              '_id': sha256(syslog_msg).hexdigest(),
              '@timestamp': self.format_timestamp(datetime.now()),
              '@version': "1",
              'message': "transformed syslog",
              'path': '',
              'tags': [],
              #'@fields': {
              #  #'levelname': record.levelname,
              #  #'logger': record.name,
              #},
              }
        t, msg = self.split_alert_message(syslog_msg)
        sm = {}
        sm['raw'] = syslog_msg
        sm['syslog_level'] = self.calculate_msg_type(syslog_msg)
        sm['syslog_msg'] = msg
        sm['syslog_tag'] = t
        try:
            result = ETL.syslog_et(syslog_msg)
            #sm['@fields'].update(result)
            sm.update(result.get('rule_results', result))
            if 'rule_name' in result:
                sm['rule_name'] = result.get('rule_name')

            sm.update(result.get('rule_results', result))
            #r.update(sm)
            sm['tags'] = []  
            if sm.get('syslog_server', None) is None:
                host = self.resolve_host(self.client_address[0])
                sm['syslog_server'] = host
            if sm.get('syslog_level', None) is not None:
                sm['tags'].append(sm['syslog_level'])
            if sm.get('rule_name', None) is not None:
                sm['tags'].append(sm['rule_name'])

        except:
            pass
        #r['message'] = sm
        r.update(sm)
        return r

    def handle(self):
        logging.debug("Handling syslog message")
        data = bytes.decode(self.request[0].strip())
        logging.debug("Resolving syslog message source")
        host = self.resolve_host(self.client_address[0])
        logging.debug("Mutating syslog message with source")
        #data = self.insert_syslog_host(data,  host)
        logging.info(str(data))
        json_data = self.create_json(data)
        inserted, result = self.MONGO_CON.insert_raw(data)
        inserted2, result = self.MONGO_CON.insert_json(json_data)
        del json_data['_id']
        inserted3, ls = ETL.send_msg(json.dumps(json_data)+'\n')
        #inserted3 = self.send_to_logstash(json_data)
        msg_type = self.calculate_msg_type(data)
        if inserted:
            logging.info('Inserted into the raw collection:'+msg_type+':'+str(data))
        if inserted2:
            logging.info('Inserted into the json collection:'+msg_type+':'+str(json_data))
        if inserted3:
            logging.info('Inserted into the ELF instance')


