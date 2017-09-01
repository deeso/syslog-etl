import pygrok

GROK_IT = None

class GrokIt(object):
    def __init__(self, patterns_file, custom_patterns_dir=None):
        global GROK_IT
        GROK_IT = self
        self.gr = pygrok.Grok('dummy', custom_patterns_dir=custom_patterns_dir)
        self.loaded_patterns = self.gr.predefined_patterns
        self.custom_patterns_dir = custom_patterns_dir
        self.groks = {}
        self.program_matches = {}
        # load all the grok patterns
        lines = [i.strip() for i in open(patterns_file).readlines()
                 if len(i.strip()) > 0]
        for line in lines:
            pattern_name = line
            if pattern_name in self.loaded_patterns:
                p = self.loaded_patterns[pattern_name].regex_str
                self.groks[pattern_name] = pygrok.Grok(p, custom_patterns_dir=custom_patterns_dir)
    def process_syslog(self, string):
        results = {}
        grok = self.groks.get('SYSLOG_PRE', None)
        if grok is None:
            return results
        _r = grok.match(string)
        program = _r.get('program', None)
        if program not in program_matches:
            program_matches[program] = [i for i in self.groks 
                                          if i.lower().find(program) == 0]
        if program == 'filterlog':
            # parse with LOG_START to get IP version and protocol name
            # then perform return results
            pass
        elif program == 'openvpn':
            pass
        else:
            # brute force all the protocols?
            pass
        return results
        
    def runall_patterns_match_text(self, string, ignore_empty=True):
        results = {}
        for pattern, grok in self.groks.items():
            v = grok.match(string)
            if ignore_empty and (v is None or len(v) == 0):
                continue
            results[pattern] = v
        return results

    def runall_grok_patterns_match_text(self, string, ignore_empty=True):
        results = {}
        for pattern, grok in self.groks.items():
            v = grok.match(string)
            if ignore_empty and (v is None or len(v) == 0):
                continue
            results[pattern] = v
        return results

    def first_match_text(self, string):
        v = {}
        pattern = None
        for pattern, grok in self.groks.items():
            v = grok.match(string)
            if v is not None and len(v) > 0:
                break
        return pattern, v

    def pattern_match_text(self, string, pattern):
        v = None
        if pattern in self.groks:
            grok = self.groks[pattern]
            v = grok.match(string)
            return v
        elif pattern in self.gr.predefined_patterns:
            p = self.loaded_patterns[pattern_name].regex_str
            grok = pygrok.Grok(p, custom_patterns_dir=self.custom_patterns_dir)
            v = grok.match(string)
            return v
        return v
