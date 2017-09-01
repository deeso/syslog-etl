from pyparsing import Word, Combine, nums, \
                    alphanums, Suppress, Optional

from ..util import CD, SYSLOG_TS, HOSTNAME, SP, REPEATED, INT, TEXT,\
                   IP4_ADDRESS, IP6_ADDRESS, WORD, DATA_NO_CD, \
                   PRINTABLES_NO_CD, EMPTY

'''
from https://doc.pfsense.org/index.php/Filter_Log_Format_for_pfSense_2.2
'''


_fl = Word("filterlog: ")
_pass = Word("pass")
_block = Word("block")
_action = Optional(_pass | _block)
_in = Word("in")
_out = Word("out")
_4 = Word("4")("ip4")
_6 = Word("6")("ip6")

_none = Word("none")
_tcp = Word("tcp")
_udp = Word("udp")


_port_num = INT
_proto_id = INT


_repeated_tail = Suppress(']\n')

_icmp = Word("icmp")
_icmp_request = Word("request")("icmp_type")
_icmp_reply = Word("reply")("icmp_type")
_icmp_unreachproto = Word("unreachproto")("icmp_type")
_icmp_unreachport = Word("unreachport")("icmp_type")
_icmp_needfrag = Word("needfrag")("icmp_type")
_icmp_tstamp = Word("tstamp")("icmp_type")
_icmp_tstamp_reply = Word("tstampreply")("icmp_type")
_icmp_unreach = Word("unreach")("icmp_type")
_icmp_timexceed = Word("timexceed")("icmp_type")
_icmp_paramprob = Word("paramprob")("icmp_type")
_icmp_redirect = Word("redirect")("icmp_type")
_icmp_maskreply = Word("maskreply")("icmp_type")
_icmp_dst_ip = IP4_ADDRESS("icmp_destination_ip4_address")
_icmp_echo_id = Word(nums)('echo_id')
_icmp_echo_sequence = Word(nums)('echo_sequence')

_icmp_otime = Word(nums)("icmp_otime")
_icmp_rtime = Word(nums)("icmp_rtime")
_icmp_ttime = Word(nums)("icmp_ttime")
_icmp_mtu = Word(nums)("icmp_mtu")
_icmp_seq_num = Word(nums)("icmp_sequnce_num")
_icmp_id = Word(nums)("icmp_id")
_icmp_unreachable_protocol_id = Word(nums)("unreachable_proto_id")
_icmp_unreachable_port_id = Word(nums)("unreachable_port_id")

log_time_stamp = TEXT
host_name = Word(alphanums)
rule_number = INT("rule_number")
sub_rule_number = INT("sub_rule_number")
anchor = Optional(Word(PRINTABLES_NO_CD+' '))("anchor")
tracker = INT("tracker")
real_interface = Word(alphanums+'.-_')("real_interface")
reason = DATA_NO_CD("reason")

action = Optional(_pass | _block)("action")
direction = Optional(_in | _out)("direction")
ip_version = Optional(_4 | _6)("ip_version")

carp_type = Word(alphanums)('carp_type')
carp_ttl = Word(nums)('carp_ttl')
adv_version = Word(nums)('adv_version')
adv_base = Word(nums)('adv_base')
adv_skew = Word(nums)('adv_skew')

carp_data = Combine(carp_type + CD +
                    carp_ttl + CD +
                    adv_version + CD +
                    adv_base + CD +
                    adv_skew)('carp_data')


ip_protocol_text = Optional(_tcp | _udp | _icmp | WORD)("protocol_name")
ip_protocol_id = _proto_id("protocol_num")

ip4_tos = DATA_NO_CD("ip4_tos")
ip4_ecn = DATA_NO_CD("ip4_ecn")
ip4_ttl = INT("ip4_ttl")
ip4_id = INT("ip4_id")
ip4_offset = INT("ip4_offset")
ip4_flags = Optional(DATA_NO_CD)("ip_flags")
ip_len = INT("ip_len")
ip4_src = IP4_ADDRESS("ip_src")
ip4_dst = IP4_ADDRESS("ip_dst")

ip6_class = Optional(DATA_NO_CD)("ip6_class")
ip6_flow_label = Optional(DATA_NO_CD)("ip6_flow_label")
ip6_hop_limit = Optional(DATA_NO_CD)("ip6_hop_limit")
ip_len = INT("ip_len")
ip6_src = IP6_ADDRESS("ip_src")
ip6_dst = IP6_ADDRESS("ip_dst")


# ip6SPecific_data = Combine(ip6_class + CD +
#                             ip6_flow_label + CD +
#                             ip6_hop_limit)


ip4_data = Combine(ip_len + CD +
                   ip4_src + CD +
                   ip4_dst)

ip6_data = Combine(ip_len + CD +
                   ip6_src + CD +
                   ip6_dst)

tcp_src_port = _port_num("tcp_src_port")
tcp_dst_port = _port_num("tcp_dst_port")
tcp_len = DATA_NO_CD("tcp_len")
tcp_flags = DATA_NO_CD("tcp_flags")
tcp_seq_num = DATA_NO_CD("tcp_seq_num")
tcp_ack_num = DATA_NO_CD("tcp_ack_num")
tcp_win_sz = DATA_NO_CD("tcp_win_sz")
tcp_urg_data = DATA_NO_CD("tcp_urg_data")
tcp_options = DATA_NO_CD("tcp_options")

tcp_data = Combine(tcp_src_port + CD +
                   tcp_dst_port + CD +
                   tcp_len + CD +
                   tcp_flags + CD +
                   tcp_seq_num + CD +
                   tcp_ack_num + CD +
                   tcp_win_sz + CD +
                   tcp_urg_data + CD +
                   tcp_options)

udp_src_port = _port_num("udp_src_port")
udp_dst_port = _port_num("udp_dst_port")
udp_len = INT("udp_len")

udp_data = Combine(udp_src_port + CD +
                   udp_dst_port + CD +
                   udp_len)

icmp_echo_type = Optional(_icmp_request | _icmp_reply)
icmp_echo_data = Combine(_icmp_echo_id + CD +
                         _icmp_echo_sequence)('echo_data')

icmp_echo = Combine(icmp_echo_type + CD + icmp_echo_data)

icmp_unreachproto = Combine(_icmp_unreachproto + CD +
                            _icmp_dst_ip + CD +
                            _icmp_unreachable_protocol_id)('icmp_unreachproto')

icmp_unreachport = Combine(_icmp_unreachport + CD +
                           _icmp_unreachable_protocol_id + CD +
                           _icmp_unreachable_port_id)('icmp_unreachport')

icmp_needfrag = Combine(_icmp_needfrag + CD +
                        _icmp_dst_ip + CD +
                        _icmp_mtu)('icmp_needfrag')

icmp_tstamp_request = Combine(_icmp_tstamp + CD +
                              _icmp_id + CD +
                              _icmp_seq_num)('icmp_tstamp_request')

icmp_tstamp_reply = Combine(_icmp_tstamp_reply + CD +
                            _icmp_id + CD +
                            _icmp_seq_num + CD +
                            _icmp_otime + CD +
                            _icmp_rtime + CD +
                            _icmp_ttime + CD)('icmp_tstamp_reply')

icmp_unreach = Combine(Optional(_icmp_unreach |
                                _icmp_timexceed |
                                _icmp_paramprob |
                                _icmp_redirect |
                                _icmp_maskreply) +
                       CD + DATA_NO_CD("icmp_other_data"))

icmp_default = Combine(DATA_NO_CD("icmp_unknown") + CD +
                       DATA_NO_CD("icmp_unknown"))

icmp_data = Optional(icmp_echo | icmp_unreachproto |
                     icmp_unreachport | icmp_needfrag |
                     icmp_tstamp_request | icmp_tstamp_reply |
                     icmp_unreach | icmp_default)

ip4SPecific_data = Combine(ip4_tos + CD +
                           ip4_ecn + CD +
                           ip4_ttl + CD +
                           ip4_id + CD +
                           ip4_offset + CD +
                           ip4_flags + CD +
                           ip_protocol_id + CD +
                           ip_protocol_text + CD +
                           ip_len + CD +
                           ip4_src + CD +
                           ip4_dst)

ip6SPecific_data = Combine(ip6_class + CD +
                           ip6_flow_label + CD +
                           ip6_hop_limit + CD +
                           ip_protocol_text + CD +
                           ip_protocol_id + CD +
                           ip_len + CD +
                           ip6_src + CD +
                           ip6_dst)


protocolSPecific_data = Combine(CD + Optional(tcp_data | udp_data |
                                icmp_data | carp_data)("protocol_data"))

ipv4_data = Combine(ip4SPecific_data +
                    Optional(protocolSPecific_data | EMPTY))

ipv4 = Combine(_4("ip_version") +
               Optional(ip4SPecific_data | EMPTY))

ipv6_data = Combine(ip6SPecific_data +
                    Optional(protocolSPecific_data | EMPTY))

ipv6 = Combine(_6("ip_version") +
               Optional(ip6SPecific_data | EMPTY))


class FilterLogParser(object):
    APP = 'filterlog'
    W_APP = Word(APP)
    LOG_DATA = Combine(rule_number + CD +
                       sub_rule_number + CD +
                       anchor + CD +
                       tracker + CD +
                       real_interface + CD +
                       reason + CD +
                       action + CD +
                       direction + CD +
                       Optional(_4("ip_version") | _6("ip_version")))
    LOG_START = Combine(SYSLOG_TS + SP + HOSTNAME + SP +
                        Word(APP+": ") +
                        Optional(REPEATED) + LOG_DATA)

    @classmethod
    def is_log_type(cls, string):
        check = Combine(SYSLOG_TS + SP +
                        HOSTNAME + SP +
                        cls.W_APP(cls.APP))
        try:
            r = check.parseString(string).asDict()
            return cls.APP in r and r[cls.APP] == cls.APP
        except:
            pass
        return False

    @classmethod
    def parse_log(cls, string):
        sfmt = '{reason},{action},{direction},{ip_version}'
        le = cls.LOG_START.copy()
        string = string.strip()
        results = {'raw': string}
        if not cls.is_log_type(string):
            results['error'] = 'Not a Pfsense Filter Log'
            results['failed_parse'] = string
            return results
        try:
            _results = le.parseString(string)
            results = _results.asDict()
            if 'real_interface' in results and\
                    results['real_interface'] is not None:
                inf = results['real_interface']
                results['interface'] = inf.split('_')[0]
                results['sub_interfaces'] = []
                if inf.split('_') > 1:
                    results['sub_interfaces'] = inf.split('_')[1:]

            if 'ip_version' in results and results['ip_version'] in ['6', '4']:
                ipv4 = True if results['ip_version'] == '4' else False
                split = sfmt.format(**results)
                _next = split.join(string.split(split)[1:])
                results.update(cls.parse_ip(_next.lstrip(','), ipv4=ipv4))
        except Exception as e:
            if 'error' not in results:
                results['error'] = str(e)
            if 'failed_parse' not in results:
                results['failed_parse'] = string

        return results

    @classmethod
    def parse_ip(cls, string, ipv4=True):
        protos = ['tcp', 'udp', 'icmp', 'carp']
        ipv = ip4SPecific_data.copy()
        results = {}
        if not ipv4:
            ipv = ip6SPecific_data.copy()

        sfmt = '{ip_len},{ip_src},{ip_dst}'
        split = None
        try:
            _results = ipv.parseString(string)
            results = _results.asDict()
            p = 'protocol_name'
            if p in results:
                # Optional
                _proto = results[p]
                results[p] = _proto.lower()
                split = sfmt.format(**results)

            if split is not None and results[p].lower() in protos:
                results[p] = results[p].lower()
                proto = results[p]
                split = sfmt.format(**results)
                _next = split.join(string.split(split)[1:])
                r = cls.parse_app_layer(_next.lstrip(','), proto=proto)
                if r is not None:
                    results.update(r)
                else:
                    results['failed_parse'] = _next
            elif split is not None and len(string.split(split)) > 0:
                proto = results[p] if p in results else p
                rest = split.join(string.split(split)[1:])
                results[proto] = rest
            else:
                results['error'] = 'No IP protocol defined'
                results['failed_parse'] = string
        except Exception as e:
            if 'error' not in results:
                results['error'] = str(e)
            if 'failed_parse' not in results:
                results['failed_parse'] = string
            print ("Failed to parse the IP data: %s" % (string))
        return results

    @classmethod
    def parse_app_layer(cls, string, proto=None):

        protos = {'tcp': tcp_data,
                  'udp': udp_data,
                  'carp': carp_data,
                  'icmp': icmp_data
                  }

        pproto = protos.get(proto, None)
        if pproto is None:
            return None

        results = {}
        try:
            _result = pproto.parseString(string)
            results = _result.asDict()
        except Exception as e:
            if 'error' not in results:
                results['error'] = str(e)
            if 'failed_parse' not in results:
                results['failed_parse'] = string
            return results
        return results
