# -*- coding: utf-8 -*-

import warnings
import os.path
import volatility.plugins.malware.malfind as malfind
import volatility.debug as debug
import volatility.utils as utils
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address, Bytes

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    import yara_misp as yaramisp

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

try:
    import distorm3
    has_distorm3 = True
except ImportError:
    has_distorm3 = False


class YaraScanMulti(malfind.YaraScan):
    """
    YaraScan with support for folders containing multiple signature files
    """

    @property
    def _is_multifiles_mode(self):
        return self._config.YARA_FOLDER

    def __init__(self, config, *args, **kwargs):
        malfind.YaraScan.__init__(self, config, *args, **kwargs)
        config.add_option('YARA-FOLDER', default=None, help='Yara rules (folder and subfolders containing rules files)')

    def _compile_rules(self):

        rules = None

        try:
            if self._config.YARA_RULES:
                s = self._config.YARA_RULES
                # Don't wrap hex or regex rules in quotes
                if s[0] not in ("{", "/"): s = '"' + s + '"'
                # Option for case insensitive searches
                if self._config.CASE: s += " nocase"
                # Scan for unicode and ascii strings
                if self._config.WIDE: s += " wide ascii"
                rules = yara.compile(sources={
                    'n': 'rule r1 {strings: $a = ' + s + ' condition: $a}'
                })
            elif self._config.YARA_FILE and os.path.isfile(self._config.YARA_FILE):
                rules = yara.compile(self._config.YARA_FILE)
            elif self._config.YARA_FOLDER and os.path.isdir(self._config.YARA_FOLDER):
                rules_files_dict = {}
                for path, subdirs, files in os.walk(self._config.YARA_FOLDER):
                    for name in files:
                        full_rules_file_name = os.path.join(path, name)
                        rules_files_dict[full_rules_file_name] = full_rules_file_name
                rules = yara.compile(filepaths=rules_files_dict)
            else:
                debug.error("You must specify a string (-Y) or a rules file (-y) or a folder containing rules files (--yara-folder)")
        except yara.SyntaxError as why:
            debug.error("Cannot compile rules: {0}".format(str(why)))

        return rules

    def render_text(self, outfd, data):
        #  if not multifiles mode, delegate to yarascan module
        if not self._is_multifiles_mode:
            malfind.YaraScan.render_text(self, outfd, data)
        #  else use multifiles mode-specific output
        else:
            if self._config.DUMP_DIR and not os.path.isdir(self._config.DUMP_DIR):
                debug.error(self._config.DUMP_DIR + " is not a directory")
            for o, addr, hit, content in data:
                outfd.write("Rule: {}\nSource: {}\n".format(hit.rule, hit.namespace))
                for meta_field in hit.meta:
                    outfd.write(" ** {}:\t{}\n".format(meta_field, hit.meta[meta_field]))

                # Find out if the hit is from user or kernel mode
                if o == None:
                    outfd.write("Owner: (Unknown Kernel Memory)\n")
                    filename = "kernel.{0:#x}.dmp".format(addr)
                elif o.obj_name == "_EPROCESS":
                    outfd.write("Owner: Process {0} Pid {1}\n".format(o.ImageFileName,
                        o.UniqueProcessId))
                    filename = "process.{0:#x}.{1:#x}.dmp".format(o.obj_offset, addr)
                else:
                    outfd.write("Owner: {0}\n".format(o.BaseDllName))
                    filename = "kernel.{0:#x}.{1:#x}.dmp".format(o.obj_offset, addr)

                # Dump the data if --dump-dir was supplied
                if self._config.DUMP_DIR:
                    path = os.path.join(self._config.DUMP_DIR, filename)
                    fh = open(path, "wb")
                    fh.write(content)
                    fh.close()

                outfd.write("".join(
                    ["{0:#010x}  {1:<48}  {2}\n".format(addr + o, h, ''.join(c))
                    for o, h, c in utils.Hexdump(content)
                    ]))

                outfd.write("\n")

    def unified_output(self, data):
        #  if not multifiles mode, delegate to yarascan module
        if not self._is_multifiles_mode:
            return malfind.YaraScan.unified_output(self, data)
        #  else use multifiles mode-specific output
        return TreeGrid([("Rule", str),
                        ("Owner", str),
                        ("Source", str),
                        ("Meta", str),
                        ("Address", Address),
                        ("Data", Bytes)],
                        self.generator(data))

    def generator(self, data):
        #  if not multifiles mode, delegate to yarascan module
        if not self._is_multifiles_mode:
            yield malfind.YaraScan.generator(self, data)
        #  else use multifiles mode-specific output
        if self._config.DUMP_DIR and not os.path.isdir(self._config.DUMP_DIR):
            debug.error(self._config.DUMP_DIR + " is not a directory")
        for o, addr, hit, content in data:
            namespace = '{0}'.format(hit.namespace) if hasattr(hit, 'namespace') else 'Missing rules filename'
            meta = ' | '.join(['{}: {}'.format(meta_tag, hit.meta[meta_tag]) for meta_tag in hit.meta])
            owner = "Owner: (Unknown Kernel Memory)"
            if o == None:
                filename = "kernel.{0:#x}.dmp".format(addr)
            elif o.obj_name == "_EPROCESS":
                owner = "{0}: (Pid {1})".format(o.ImageFileName, o.UniqueProcessId)
                filename = "process.{0:#x}.{1:#x}.dmp".format(o.obj_offset, addr)
            else:
                owner = "{0}".format(o.BaseDllName)
                filename = "kernel.{0:#x}.{1:#x}.dmp".format(o.obj_offset, addr)

            # Dump the data if --dump-dir was supplied
            if self._config.DUMP_DIR:
                path = os.path.join(self._config.DUMP_DIR, filename)
                fh = open(path, "wb")
                fh.write(content)
                fh.close()

            yield (0, [str(hit.rule), owner, namespace, meta, Address(addr), Bytes(content)])


# TODO: add option to output broken and repaired rules to a folder
class MISPScan(YaraScanMulti):
    """
    YaraScan pulling yara rules from MISP
    """

    def __init__(self, config, *args, **kwargs):
        YaraScanMulti.__init__(self, config, *args, **kwargs)

        config.add_option("SERVER", help="MISP server url (including http/https prefix)",
                          default=None, action='store', type='str')
        config.add_option("KEY", help="MISP user key (can be fetched from MISP in 'Event Actions > Automation')",
                          default=None, action='store', type='str')
        config.add_option("RULESFOLDER", help="Folder for (temporary) rules storage",
                          default=None, action='store', type='str')
        config.add_option("MISP-CONFIG", help="MISP module config file",
                          default=None, action='store', type='str')
        config.add_option("KEEPTEMP", help="Do not delete temp after treating the rules",
                          default=False, action="store_true")
        config.add_option("IGNORE-IDS-FLAG", help="Fetch all yara attributes from MISP, regardless of the 'IDS' flag",
                          default=False, action="store_true")

        config.remove_option('YARA-RULES')
        config.remove_option('YARA-FILE')
        config.remove_option('YARA-FOLDER')

        self.yara_misp = None

    def calculate(self):
        try:
            server = self._config.SERVER
            key = self._config.KEY
            rulesfolder = self._config.RULESFOLDER
            keep_temp = self._config.KEEPTEMP
            ignore_ids_flag = self._config.IGNORE_IDS_FLAG

            if not server or not key or not rulesfolder:
                raise Exception('Parameters --server, --key and --rulesfolder are required, either as arguments or in the config file')

            print('Connecting to server: {}'.format(server))
            self.yara_misp = yaramisp.YaraMISP(server, key, rulesfolder, keep_temp)
            print('Fetching rules')
            self.yara_misp.fetch_misp_rules(to_ids=not ignore_ids_flag)
            print('Checking rules integrity')
            _, _, _, summary = self.yara_misp.check_all()
            print(summary)

            self._config.update('YARA_FOLDER', rulesfolder)

            res = YaraScanMulti.calculate(self)

            return res

        except Exception as e:
            print(str(e))
            exit()

    def _compile_rules(self):
        compiled_rules = YaraScanMulti._compile_rules(self)
        self.yara_misp = None  # allows deletion of the rules folder
        return compiled_rules







