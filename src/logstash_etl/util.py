from pyparsing import hexnums, oneOf, Word, Combine, nums, \
                    alphanums, Group, printables, Suppress, \
                    OneOrMore, Optional, Empty

SQ = Suppress("'")
DQ = Suppress('"')
SP = Suppress(" ")
CD = Suppress(',')
CN = Suppress(':')

ARROW_S = Suppress('->')

MONTH = oneOf("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec")
DAY = Word(nums)
SL_TIME = Combine(Word(nums)+":"+Word(nums)+":"+Word(nums))
FULL_HEX = Word('x'+hexnums)

PORT = Word(nums)
IP4_ADDRESS = Combine(Word(nums) + ('.' + Word(nums))*3)
IP6_ADDRESS = Word(hexnums+':')
PRINTABLES_NO_CD = printables.replace(',', '')
HOSTNAME = Word(alphanums+'.-_')("HOSTNAME")

INT = Word(nums)
HEX = Word(hexnums)
WORD = Word(alphanums)
TEXT = Group(OneOrMore(Word(printables)))
EMPTY = Empty()
DATA_NO_CD = Optional(Word(PRINTABLES_NO_CD))


SYSLOG_PROC = Combine(WORD("app") + Word("[") + INT("pid") + Word("]: "))
SYSLOG_APP = Combine(WORD("app") + Word(": "))
SYSLOG_TS = Combine(MONTH+" "+DAY+" "+SL_TIME)
USERNAME = Word(alphanums)

APP_LOG_START = Combine(SYSLOG_TS("timestamp") + SP + HOSTNAME("syslog_host") + SP + SYSLOG_APP)
PROC_LOG_START = Combine(SYSLOG_TS("timestamp") + SP + HOSTNAME("syslog_host") + SP + SYSLOG_PROC)

REPEATED = Combine(Word('message repeated ') +
                   Word(nums)('repeated') +
                   Word(' times: [ '))

class CheckLogType(object):
    @classmethod
    def get_log_type(cls, string):
        is_app, result = cls.check_app(string)
        if is_app:
            result['type'] = 'app'
            return result
        is_proc, result = cls.check_app(string)
        if is_proc:
            result['type'] = 'proc'
            return result
        result['type'] = 'unknown'
        return result

    @classmethod
    def check_app(cls, string):
        result = {}
        try:
            result = APP_LOG_START.parseString(string).asDict()
        except:
            return False, {}
        return 'app' in result, result

    @classmethod
    def check_proc(cls, string):
        result = {}
        try:
            result = PROC_LOG_START.parseString(string).asDict()
        except:
            return False, {}
        return 'pid' in result, result
