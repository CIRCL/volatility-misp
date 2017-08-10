# -*- coding: utf-8 -*-

import six
import yara_validator as yaravalidator
import re

if six.PY3:
    import io
else:
    import StringIO as io

try:
    from pymisp import PyMISP, PyMISPError, MISPAttribute
    HAS_PYMISP = True
except ImportError:
    HAS_PYMISP = False


FILENAME_TAG = '@yara-filename:'


class YaraMISP:
    # Note on naming conventions: 'attribute' represents a misp attribute (object) of type 'yara'
    #                             'rule' represents a yara signature (string) or set of signatures (as a single string)

    def __init__(self, server, key, temporary_dir, keep_temp):
        if not HAS_PYMISP:
            raise Exception("PyMISP is required by this module. Try 'pip install PyMISP'")
        self._server = server
        self._key = key
        self.temporary_dir = temporary_dir
        self.keep_temp = keep_temp
        self._yara_validator = yaravalidator.YaraValidator(True, self.temporary_dir, self.keep_temp)
        self.raw_yara_attributes = []
        self.raw_yara_attributes_buffer = []
        self.valid_yara_attributes = []
        self.repaired_yara_attributes = []
        self.broken_yara_attributes = []

    def fetch_misp_rules(self, *event_ids, **kwargs):
        exclude_events = kwargs['exclude'] if 'exclude' in kwargs else []
        to_ids = kwargs['to_ids'] if 'to_ids' in kwargs else False
        misp = PyMISP(self._server, self._key, True, 'json')
        def yara_from_event(event_id):
            search_results = misp.search(controller='attributes', type_attribute='yara', eventid=event_id, to_ids=to_ids)
            if 'errors' in search_results:
                raise PyMISPError(search_results['message'])
            all_yara_attrs = search_results['response']['Attribute']
            for attr in all_yara_attrs:
                misp_attribute = MISPAttribute()
                misp_attribute.set_all_values(**attr)
                misp_attribute.yaramisp_yarainclude_name = self.__get_yara_filename(misp_attribute.comment)
                misp_attribute.yaramisp_yarainclude_namespace = misp_attribute.event_id
                if misp_attribute.event_id not in exclude_events:
                    self.raw_yara_attributes.append(misp_attribute)
                    self.raw_yara_attributes_buffer.append(misp_attribute)
        if event_ids and any(x is not None for x in event_ids):
            for event_id in list(set(event_ids)):
                yara_from_event(event_id)
        else:
            yara_from_event(None)
        return self.raw_yara_attributes_buffer

    def check_all(self):

        broken_attributes_buffer = []
        yara_validator = self._yara_validator

        # try to compile each rule separately
        for attr in self.raw_yara_attributes_buffer:
            status, message = yara_validator.validate(attr.value,
                                                      yarainclude_name=attr.yaramisp_yarainclude_name,
                                                      yarainclude_namespace=attr.yaramisp_yarainclude_namespace,
                                                      inject_in_meta={'MISP': '{}/events/view/{}'.format(self._server, attr.event_id)})
            if status == yaravalidator.YaraValidator.STATUS_VALID:
                attr.yaramisp_status = 'VALID'
                self.valid_yara_attributes.append(attr)
            else:
                attr.yaramisp_original_error = message
                attr.yaramisp_temporary_rule = attr.value
                attr.yaramisp_temporary_error = message
                broken_attributes_buffer.append(attr)
        self.raw_yara_attributes_buffer = []
        something_fixed = True
        while something_fixed:
            something_fixed = False
            for attr in broken_attributes_buffer[:]:
                original_rule = attr.value
                previous_suggestion = attr.yaramisp_temporary_rule
                previous_error = attr.yaramisp_temporary_error
                repair_suggestion = yara_validator.suggest_repair(previous_suggestion, previous_error)
                new_status, new_message = yara_validator.validate(repair_suggestion,
                                                                  # yarainclude_name=attr.yaramisp_yarainclude_name,
                                                                  yarainclude_namespace=attr.yaramisp_yarainclude_namespace)
                if new_status == yaravalidator.YaraValidator.STATUS_VALID:
                    if original_rule == repair_suggestion:  # simple missing dependency, no edit was made
                        attr.yaramisp_status = 'VALID'
                        self.valid_yara_attributes.append(attr)
                    else:  # an edit had to be made to fix the issue
                        attr.yaramisp_repaired = repair_suggestion
                        attr.yaramisp_status = 'REPAIRED'
                        self.repaired_yara_attributes.append(attr)
                    something_fixed = True
                    broken_attributes_buffer.remove(attr)
                else:  # issue not fully fixed
                    if new_message != previous_error:
                        something_fixed = True
                    attr.yaramisp_temporary_rule = repair_suggestion
                    attr.yaramisp_temporary_error = new_message
        for attr in broken_attributes_buffer:
            attr.yaramisp_best_repair = attr.yaramisp_temporary_rule
            attr.yaramisp_best_failure = attr.yaramisp_temporary_error
            attr.yaramisp_status = 'BROKEN'
            self.broken_yara_attributes.append(attr)

        valid = '\n\n\n'.join([self.__format_valid_rule(r) for r in self.valid_yara_attributes])
        invalid = '\n\n\n'.join([self.__format_broken_rule(r) for r in self.broken_yara_attributes])
        repaired = '\n\n\n'.join([self.__format_repaired_rule(r) for r in self.repaired_yara_attributes])
        summary = 'Total rules: '+str(len(self.raw_yara_attributes)) \
                  + ' Valid: '+str(len(self.valid_yara_attributes))\
                  + ' Malformed: '+str(len(self.broken_yara_attributes))\
                  + ' Repaired: '+str(len(self.repaired_yara_attributes))
        return valid, invalid, repaired, summary

    @staticmethod
    def __add_line_numbers(string):
        output = ''
        s = io.StringIO(string)
        line_number = 1
        for line in s:
            output += str(line_number)+'\t'+line
            line_number += 1
        return output

    @staticmethod
    def __indent(string, indent):
        output = ''
        s = io.StringIO(string)
        for line in s:
            output += '\t'*indent + line
        return output

    @staticmethod
    def __get_yara_filename(comment_string):
        if not comment_string:
            return None
        regex = re.compile(r'^\s*'+FILENAME_TAG+'(.*)$', re.MULTILINE)
        match = regex.search(comment_string)
        return match.group(1).strip() if match else None

    @staticmethod
    def __format_rule(rule_string, **kwargs):
        header = kwargs['header'] if 'header' in kwargs else None
        show_yara_version = kwargs['show_yara_version'] if 'show_yara_version' in kwargs else True
        show_line_numbers = kwargs['show_line_numbers'] if 'show_line_numbers' in kwargs else False
        indent = kwargs['indent'] if 'indent' in kwargs else 0

        comment = ''
        if header:
            for line in io.StringIO(header):
                comment += '\t'*indent + '// '+line
            comment += '\n'
        if show_yara_version:
            comment += '\t'*indent + '// yara: ' + yaravalidator.YARA_VERSION + '\n'
        if show_line_numbers:
            rule_string = YaraMISP.__add_line_numbers(rule_string)
        rule_string = YaraMISP.__indent(rule_string, indent)
        return comment+rule_string

    @staticmethod
    def __format_valid_rule(rule):
        rule_str = rule.value
        return YaraMISP.__format_rule(rule_str,
                                      header='-------- VALIDATED --------\nMISP event: {} attribute: {}'
                                      .format(rule.event_id, rule.uuid),
                                      show_line_numbers=False)

    @staticmethod
    def __format_broken_rule(rule):
        rule_str = rule.value
        rule_err = rule.yaramisp_original_error
        rule_rep_str = rule.yaramisp_best_repair
        rule_rep_error = rule.yaramisp_best_failure
        original = YaraMISP.__format_rule(rule_str,
                                          header='--------- BROKEN ----------\nMISP event: {} attribute: {}\n{}'
                                          .format(rule.event_id, rule.uuid, rule_err),
                                          show_line_numbers=True)
        if rule_str != rule_rep_str:
            attempt = YaraMISP.__format_rule(rule_rep_str,
                                             header='\nAUTO-REPAIR: suggestion\n{}\n---------------------------'
                                             .format(rule_rep_error),
                                             show_yara_version=False,
                                             show_line_numbers=True,
                                             indent=2)
        else:
            attempt = YaraMISP.__format_rule('',
                                             header='\nAUTO-REPAIR: \nNo suggestion\n---------------------------',
                                             show_yara_version=False,
                                             indent=2)
        return original+'\n// ---------------------------\n'+attempt

    @staticmethod
    def __format_repaired_rule(rule):
        rule_str = rule.value
        rule_err = rule.yaramisp_original_error
        rule_rep_str = rule.yaramisp_repaired
        original = YaraMISP.__format_rule(rule_str,
                                          header='--------- REPAIRED ----------\nMISP event: {} attribute: {}\n{}'
                                          .format(rule.event_id, rule.uuid, rule_err),
                                          show_line_numbers=True)

        attempt = YaraMISP.__format_rule(rule_rep_str,
                                         header='\nAUTO-REPAIR: valid suggestion\n---------------------------',
                                         show_yara_version=False,
                                         show_line_numbers=False,
                                         indent=2)
        return original + '\n// ---------------------------\n' + attempt

