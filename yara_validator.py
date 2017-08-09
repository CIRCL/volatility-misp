# -*- coding: utf-8 -*-

import six
import yara
import os
import hashlib
import shutil
import re


YARA_VERSION = 'v'+yara.__version__+' -- library: '+yara.__file__


class YaraValidator:

    STATUS_VALID = 0
    STATUS_BROKEN = 1

    def __init__(self, allow_includes=True, temp_folder='.', keep_temp=False):
        if os.path.exists(temp_folder) and os.listdir(temp_folder):
            self.__temp_folder_created = False
            raise Exception('Temporary folder {} is not empty'.format(temp_folder))
        else:
            self.__temp_folder_created = True
        self.__keep_temp = keep_temp
        self._allow_includes = allow_includes
        self._temp_folder = temp_folder
        self.__chdir_stack = []

    def __del__(self):
        if self.__temp_folder_created and not self.__keep_temp and os.path.exists(self._temp_folder):
            shutil.rmtree(self._temp_folder)

    def validate(self, rule, **kwargs):
        if six.PY2:
            rule = rule.encode('utf-8')
        namespace = kwargs['namespace'] if 'namespace' in kwargs else None
        filename = kwargs['store_as'] if 'store_as' in kwargs else None
        store_if_valid = True if 'store_as' in kwargs else False
        if self._allow_includes:
            self.__chdir(self._temp_folder, str(namespace))
        try:
            self._yara_python23_compile(rule)
            if store_if_valid:
                if not filename:
                    encoded_rule = rule if six.PY2 else rule.encode('utf-8')
                    filename = hashlib.sha256(encoded_rule).hexdigest() + '.yara'
                f = open(filename, 'w')
                f.write(rule)
                f.close()
            return self.STATUS_VALID, None
        except yara.SyntaxError as e:
            # if store_if_valid:
            #     self.__chdir('.', '__BROKEN__')
            #     if not filename:
            #         encoded_rule = rule if six.PY2 else rule.encode('utf-8')
            #         filename = hashlib.sha256(encoded_rule).hexdigest() + '.yara'
            #     f = open(filename, 'w+')
            #     offsetted_line_number = int(re.search('^line ([0-9]+).*', str(e)).group(1))
            #     offsetted_line_number += 4
            #     f.write('// -------- BROKEN -------\n// {}\n// Note: line {} taking this comment into account\n\n{}\n\n'
            #             .format(str(e), offsetted_line_number, rule))
            #     f.close()
            #     self.__chdir_revert()
            return self.STATUS_BROKEN, str(e)
        finally:
            if self._allow_includes:
                self.__chdir_revert()

    # if error_message is set, rule will not be re-compiled with yara. Therefore, the namespace will have no incidence
    def suggest_repair(self, rule, error_msg=None, namespace=None):
        if not error_msg:
            _, error_msg = self.validate(rule, namespace=namespace)
        common_misspelled_keywords = {
            u'Rule ': u'rule ',
            u'Meta:': u'meta:',
            u'Strings:': u'strings:',
            u'Condition:': u'condition:',
            u'meta=': u'meta:',
            u'strings=': u'strings:',
            u'condition=': u'condition:',
            u'“': u'"',
            u'”': u'"',
            u'″': u'"',
            u'‶': u'"'

        }
        base_modules = {
            'pe': u'import "pe"',
            'elf': u'import "elf"',
            'cuckoo': u'import "cuckoo"',
            'magic': u'import "magic"',
            'hash': u'import "hash"',
            'math': u'import "math"',
            'dotnet': u'import "dotnet"'
        }
        repaired = rule

        # FIXING COMMON ISSUE: common misspells
        #       FIXME: make precise matching to avoid replacing legit quote-like characters in unicode strings
        for misspell in common_misspelled_keywords:
            repaired = repaired.replace(misspell, common_misspelled_keywords[misspell])

        # FIXING COMMON ISSUE: missing modules imports
        for mod in base_modules:
            if 'undefined identifier "{}"'.format(mod) in error_msg:
                repaired = base_modules[mod]+'\n'+repaired

        # FIXING COMMON ISSUE:  yara bug where hex (sub)strings fail to compile when [ ] is terminating the (sub)string.
        #       example: replacing FF (FF | [2]) FF [5] with FF (FF | ?? ??) FF ?? ?? ?? ?? ??
        #       FIXME: no clean solution yet for ranges. e.g.: [3-5]
        #       FIXME: pre-fix similar issues in other hex strings potentially presenting the same issue
        bytestring_error = re.search(r"line (.*): invalid hex string \"(\$.*)\":", error_msg)
        #  r"line (.*): invalid hex string \"(\$.*)\": syntax error, unexpected '.', expecting _BYTE_ or _MASKED_BYTE_ or '.' or '.'",
        if bytestring_error:
            string_name = bytestring_error.group(2)
            regex = re.escape(string_name)+r'.*?=.*?{(.*?)}.*?$'
            hex_string = re.search(regex, repaired, re.MULTILINE | re.DOTALL)
            if hex_string:
                stripped_hex_string = hex_string.group(1)
                stripped_hex_string = re.sub(r'\s*', '', stripped_hex_string)
                fixed_hex_string = re.sub(r'\[([0-9]+)\]',
                                          lambda m: ''.join('?? '*int(s) for n, s in enumerate(m.groups())),
                                          stripped_hex_string)
                fixed_statement = string_name + ' = { ' + fixed_hex_string + '}'
                repaired = repaired.replace(hex_string.group(0), fixed_statement)

        # FIXING COMMON ISSUE: random line breaks appearing in the middle of strings or meta
        #       Make the rule a one-liner, then re-insert line breaks appropriately
        #       FIXME: write or find a proper fault-tolerant lexer for yara rules
        #       FIXME: handle multiple rules defined in a single string
        elif re.search(r'line (.*): (?:syntax error, unexpected \$end|unterminated string)', error_msg):
            repaired_without_comments = self.__strip_comments(repaired)
            repaired = repaired_without_comments.replace('\r', ' ').replace('\n', ' ')
            repaired = repaired\
                .replace('meta:', '\nmeta: ')\
                .replace('strings:', '\nstrings: ')\
                .replace('condition:', '\ncondition:\n ')
            meta_section = re.search(r'^\s*meta:\s+(.*?)$', repaired, re.MULTILINE)
            strings_section = re.search(r'^\s*strings:\s+(.*?)$', repaired, re.MULTILINE)
            # condition_section = re.search(r'^\s*condition:\s+(.*?)$', repaired, re.MULTILINE)
            if meta_section:
                meta_content = meta_section.group(1)
                meta_entries = re.findall(r'.+?\s*=\s*(?:"(?:\\.|[^"\\])*"|[0-9]+\s+)', meta_content)
                formatted_meta_entries = '\n\t'.join([entry.strip() for entry in meta_entries])
                repaired = repaired.replace(meta_section.group(0), u"meta:\n\t{}".format(formatted_meta_entries))
            if strings_section:
                strings_content = strings_section.group(1)
                strings_entries = re.findall(r'(\$[\w\s]*=\s*(?:(?:".+?").*?|(?:{.+?}).*?|(?:/.+?/).*?)(?=\$|$))',
                                             strings_content)
                formatted_strings_entries = '\n\t'.join([entry.strip() for entry in strings_entries])
                repaired = repaired.replace(strings_section.group(0), u"strings:\n\t{}"
                                            .format(formatted_strings_entries))

        # FIXING COMMON ISSUE: rule names containing spaces
        #      FIXME: handle multiple rules defined in a single string
        elif error_msg.strip() == "line 1: syntax error, unexpected _IDENTIFIER_, expecting '{'" \
                and len(repaired.splitlines()) > 1:
            lines = repaired.splitlines()
            matched_rulename = re.search(r'^\s*rule\s*(.*)\s*{$', lines[0])
            first_line_brackets = '{'
            if not matched_rulename:
                matched_rulename = re.search(r'^\s*rule\s*(.*)\s*$', lines[0])
                first_line_brackets = ''
            if matched_rulename:
                lines[0] = u'rule '+matched_rulename.group(1).replace(' ', '')+first_line_brackets
                repaired = u'\n'.join(lines)

        return repaired

    @staticmethod
    def __strip_comments(rule_string):
        regex = r"(\".*?(?<!\\)\"|\'.*?(?<!\\)\')|(/\*.*?\*/|//[^\r\n]*$)|(^\s*//.*?$)"
        comp_regex = re.compile(regex, re.MULTILINE | re.DOTALL)

        def _replacer(match):
            if match.group(2) is not None:
                return ""
            else:
                return match.group(1)

        return comp_regex.sub(_replacer, rule_string)

    def _yara_python23_compile(self, rules):
        allow_includes = self._allow_includes
        try:
            comp = yara.compile(source=rules, includes=allow_includes)
        except yara.SyntaxError as e:
            raise e
        return comp

    def __chdir(self, *dirs):
        working_dir = os.path.join(*dirs)
        self.__chdir_stack.append(os.getcwd())
        if not os.path.exists(working_dir):
            os.makedirs(working_dir)
        os.chdir(working_dir)

    def __chdir_revert(self):
        d = self.__chdir_stack.pop()
        os.chdir(d)
