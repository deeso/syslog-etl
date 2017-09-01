from pyparsing import hexnums, oneOf, Word, Combine, nums, \
                    alphanums, Group, printables, Suppress, \
                    OneOrMore, Optional, Empty

from ..util import CD, SYSLOG_TS, HOSTNAME, SP, INT, TEXT, SQ,\
                   IP4_ADDRESS, IP6_ADDRESS, WORD, DATA_NO_CD, \
                   PRINTABLES_NO_CD, EMPTY, PORT, USERNAME, ARROW_S, \
                   INT, CN
import sys


log_start = Combine(SYSLOG_TS("timestamp") + SP + HOSTNAME("syslog_host") + SP)


username_host_port = Combine(USERNAME("username") + Suppress("/") +
                             IP4_ADDRESS("ip_address") + ":" +
                             PORT("port"))

host_port = Combine(IP4_ADDRESS("ip_address") + ":" +
                    PORT("port"))

MULTI_LEARN_S = Suppress(" MULTI: Learn: ")
MULTI_LEARN = Combine(username_host_port + MULTI_LEARN_S +
                      IP4_ADDRESS("local_ip") + SP + ARROW_S +
                      SP + username_host_port)

MULTI_VA_S = Suppress(" MULTI_sva: pool returned ")
NOT_ENABLED = Suppress('(Not enabled)')
IPV4_ALLOC = Combine(Suppress('IPv4=') +
                     Optional(IP4_ADDRESS('allocated_ip4') |
                              NOT_ENABLED('ipv4_not_enabled')))

IPV6_ALLOC = Combine(Suppress('IPv6=') +
                     Optional(IP6_ADDRESS('allocated_ip6') |
                              NOT_ENABLED('ipv6_not_enabled')))

ml_test = 'dso/50.205.219.98:1194 MULTI: Learn: 10.153.153.2 -> dso/50.205.219.98:1194'

MULTI_VA = Combine(username_host_port + MULTI_VA_S +
                   IPV4_ALLOC + CD + SP + IPV6_ALLOC)

ml_va = 'dso/50.205.219.98:1194 MULTI_sva: pool returned IPv4=10.153.153.2, IPv6=fe80::200:5aee:feaa:20a2'
ml_va_no_v6 = 'dso/50.205.219.98:1194 MULTI_sva: pool returned IPv4=10.153.153.2, IPv6=(Not enabled)'
ml_va_no_v4_v4 = 'dso/50.205.219.98:1194 MULTI_sva: pool returned IPv4=(Not enabled), IPv6=(Not enabled)'

TLS_S = Suppress("TLS")
UN_S = Suppress("Username")
PASS_S = Suppress("Password")
AUTH_S = Suppress('authentication')
SUCC_S = Suppress('succeeded')
FOR_S = Suppress('for')
UNL_S = Suppress('username')

DATA_CHANNEL_ENCRYPT = Suppress(" Data Channel Encrypt: ")
CIPHER = Suppress("Cipher")

# INIT_WITH = Combine(Suppress('initialized') + SP + Suppress('with') + SP)
INIT_WITH = Suppress('initialized with ')

DTE_CIPHER = Combine(host_port + DATA_CHANNEL_ENCRYPT + CIPHER + SP + SQ +
                     Word(alphanums+'-')('cipher') + SQ + SP +
                     INIT_WITH + INT('key_size'))

BIT_MSG = Suppress(" bit message hash '")

DTE_HMAC = Combine(host_port + DATA_CHANNEL_ENCRYPT + Suppress("Using ") +
                   INT('hmac_bits') + BIT_MSG +
                   Word(alphanums+'-')('hmac'))


TLS_S = Suppress("TLS: Username/Password authentication succeeded for username '")

class OpenVPNLogParser(object):
    
    TLS_USER_AUTH = Combine(host_port + TLS_S + USERNAME("username") + SQ)

    @classmethod
    def is_log_type(cls, string):
        pass

    @classmethod
    def parse_log(cls, string):
        pass

    @classmethod
    def parse_user_success_authentication(cls, string):
        pass

    @classmethod
    def parse_user_failed_authentication(cls, string):
        pass

    @classmethod
    def parse_multi_learn(cls, string):
        res = False
        results = {}
        if string.find(MULTI_LEARN) == -1:
            return res, results

        try:
            results = multi_learn.parseString(string).asDict()
            res = 'ip_address' in results and \
                  'port' in results and \
                  'username' in results and \
                  'local_ip' in results
            return res, results
        except:
            pass
        return res, results

    @classmethod
    def parse_local_ip(cls, string):
        pass

    @classmethod
    def parse_data_channel(cls, string):
        pass

    @classmethod
    def parse_control_channel(cls, string):
        pass

    @classmethod
    def parse_tls_connection(cls, string):
        pass

    @classmethod
    def parse_tls_authentication(cls, string):
        pass
