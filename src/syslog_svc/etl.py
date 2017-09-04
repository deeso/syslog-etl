from rule_chains.frontend import GrokFrontend
from rule_chains import get_names, get_patterns, get_grokit_config


DEFAULT_NAMES = get_names()
DEFAULT_PATTERNS = get_patterns()
GROK_FE = None
DEFAULT_CONFIG = get_grokit_config()
SYSLOG_DISPATCH = 'syslog_dispatcher'


class ETL(object):

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
        GROK_FE = cls.build_grok_etl(config=config, names=name,
                                   custom_patterns=custom_patterns)
        return GROK_FE

    @classmethod
    def syslog_et(cls, syslog_msg):
        global GROK_FE
        my_fe = GROK_FE
        if my_fe is None:
            my_fe = cls.build_grokit()
        # 'syslog_app_dispatch'
        fe_results = my_fe.execute_dispatch_table(SYSLOG_DISPATCH, syslog_msg)
        if fe_results['outcome']:
            return fe_results['rule_results']
        return {}
