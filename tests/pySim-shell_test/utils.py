#!/usr/bin/env python3

# Testsuite for pySim-shell.py
#
# (C) 2024 by sysmocom - s.f.m.c. GmbH
# All Rights Reserved
#
# Author: Philipp Maier
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import sys
import re
import unittest
import yaml
import csv
import inspect
from smartcard.CardType import ATRCardType
from smartcard.CardRequest import CardRequest
from smartcard.util import toHexString, toBytes
from smartcard.System import readers
from smartcard.scard import SCARD_SHARE_EXCLUSIVE
from string import Template
from pySim.utils import i2h, h2i, dec_iccid, boxed_heading_str
from time import sleep
from pathlib import Path

# Paths must originate at the top directory of the project repository
CONFIG_YAML="/tests/pySim-shell_test/config.yaml"
CARD_DATA_CSV="/tests/pySim-shell_test/card_data.csv"

class UnittestUtils(unittest.TestCase):

    # Set to true to regenerate .ok files during test-run
    regenerate = False

    # Set to true to keep all temporary files (.log, .tmp, and files generated from templates)
    keepfiles = False

    # Print content of files that are read and/or compared
    print_content = False

    # The absolute path to the testcase that we are executing (where we find the .ok and .script files along with the
    # concrete testcase implementation
    test_dir = None

    # The absolute path to the top level directory (where we also find pySim-shell.py)
    top_dir = None

    # All cards installed in this test-rig will get a record in this dict that will contain the data from config.toml
    # and card_data.csv.
    cards = {}

    def __init__(self, *kwargs):
        super().__init__(*kwargs)
        self.maxDiff = None
        self.__templates_generated = []

    def __search_card(self, name:str, atr:str, iccid:str, eid:str) -> int:
        """ Search a card by its ATR and ICCID/EID (name only for reference) """
        reader_list=readers()

        print("searching for card:")
        if iccid:
            print("ATR: %s" % atr)
            print("ICCID: %s" % iccid)
        elif eid:
            print("ATR: %s" % atr)
            print("EID: %s" % eid)
        else:
            raise RuntimeError("a card must be searched either by ICCID or EID")

        for i in range(len(reader_list)):

            # Connect to card reader
            try:
                reader_connection = reader_list[i].createConnection()
                reader_connection.connect(mode = SCARD_SHARE_EXCLUSIVE)
            except:
                continue

            # Match ATR
            atr_found = i2h(reader_connection.getATR())
            if atr_found.lower() != atr.lower():
                print(" found ATR: %s -> no match, next card..." % atr_found)
                reader_connection.disconnect()
                continue
            print(" found ATR: %s" % atr_found)

            reader_connection.disconnect()
            reader_connection.connect(mode = SCARD_SHARE_EXCLUSIVE)

            # Match ICCID (UICC or UICC profile on an eUICC) or EID (eUICC)
            if iccid:
                response, sw1, sw2 = reader_connection.transmit(h2i("a0a40000022fe2"))
                if sw1 != 0x9f:
                    raise RuntimeError("unable to select EF.ICCID on card %s (sw1=%02x, sw2=%02x)" % (name, sw1, sw2))
                response, sw1, sw2 = reader_connection.transmit(h2i("a0b000000a"))
                if [sw1, sw2] != [0x90, 0x00]:
                    raise RuntimeError("unable to read EF.ICCID from card %s (sw1=%02x, sw2=%02x)" % (name, sw1, sw2))
                iccid_found = dec_iccid(i2h(response))
                if iccid_found.lower() != iccid.lower():
                    print("  -> found ICCID: %s -> no match, next card..." % iccid_found)
                    reader_connection.disconnect()
                    continue
                print("  -> found ICCID: %s" % iccid_found)
            elif eid:
                response, sw1, sw2 = reader_connection.transmit(h2i("0070000100"))
                if [sw1, sw2] != [0x90, 0x00]:
                    raise RuntimeError("unable to open lchan 1 on card %s" % name)
                response, sw1, sw2 = reader_connection.transmit(h2i("01A4040410A0000005591010FFFFFFFF8900000100"))
                if sw1 != 0x61:
                    raise RuntimeError("unable to select ISD-R on card %s" % name)
                response, sw1, sw2 = reader_connection.transmit(h2i("81E2910006BF3E035C015A"))
                if [sw1, sw2] != [0x61, 0x15]:
                    raise RuntimeError("unable to retrieve EID on card %s" % name)
                response, sw1, sw2 = reader_connection.transmit(h2i("01C0000015"))
                if [sw1, sw2] != [0x90, 0x00]:
                    raise RuntimeError("unable to read EID from card %s" % name)
                eid_found = i2h(response[5:])
                if eid_found.lower() != eid.lower():
                    print("  -> found EID: %s -> no match, next card..." % eid_found)
                    reader_connection.disconnect()
                    continue
                print("  -> found EID: %s" % eid_found)

            # We found the card we were looking for!
            reader_connection.disconnect()
            return i

        raise RuntimeError("missing card %s (atr:%s, eid:%s, iccid:%s), check test setup and configuration file (%s)" %
              (name, atr, eid, iccid, CONFIG_YAML))

    def __read_card_data(self, name, iccid, eid):
        """ Find card data by EID or ICCID (name only for reference) """

        if eid:
            key = 'eid'
            value = eid
        elif iccid:
            key = 'iccid'
            value = iccid
        else:
            raise RuntimeError("iccid and eid parameter missing for card %s, check test setup and configuration file (%s)" % (name, CONFIG_YAML))

        with open(self.top_dir + CARD_DATA_CSV, newline='') as csvfile:
            csv_reader = csv.DictReader(csvfile)
            for row in csv_reader:
                if row.get(key) == value:
                    return row
        raise RuntimeError("missing data for card %s (%s:%s), check card data file (%s)" % (name, key, value, CARD_DATA_CSV))

    def setUp(self):
        """ Initialize testsuite. This method is called automatically. It reads the test configuration file, finds and
        sets the working directory of the executed testcase and ensures that the required card are present. """
        print("")

        testcasepath = inspect.getfile(self.__class__)
        testcasename = testcasepath.split("/")[-2] + "." + self._testMethodName
        print(boxed_heading_str("testcase: " + testcasename))
        self.pysim_shell_log_counter = 0

        # Find directories
        self.test_dir = os.path.dirname(testcasepath)
        print ("Test directory: " + self.test_dir)
        self.top_dir = os.path.abspath(self.test_dir + "/../../../")
        print ("Top directory: " + self.top_dir)

        # Read test config
        with open(self.top_dir + CONFIG_YAML, "r") as cfg:
            config = yaml.load(cfg, Loader=yaml.FullLoader)
        self.keepfiles = config['keepfiles']
        self.regenerate = config['regenerate']
        self.print_content = config['print_content']

        if self.keepfiles:
            print("keepfiles = True, will not delete generated files (.tmp, .log, and files generated from templates) on cleanup")
        if self.regenerate:
            print("regenerate = True, will regenerate .ok files from the .tmp that are generated during the testcase execution")

        # Search cards
        cards = config['cards']
        for card in cards:
            name = card['name']
            atr = card['atr']
            iccid = card.get('iccid', None)
            eid = card.get('eid', None)
            del card['name']
            reader = self.__search_card(name, atr, iccid, eid)
            card_data = self.__read_card_data(name, iccid, eid)
            self.cards[name] = {**{'reader':reader}, **card, **card_data}

        # Print discovered card information
        print("Cards:")
        for card in self.cards:
            print(" %s:" % card)
            for key in self.cards[card]:
                print("  %s: %s" % (key, self.cards[card][key]))

        print("initialization done -- continuing with testcase %s ..." % testcasename)
        print("----------------------------------------------------------------------")
        os.chdir(self.test_dir)

    def tearDown(self):
        """ Cleanup all temporary files (.tmp, files generated from templates and logfiles). This method is
        called automatically """

        print("----------------------------------------------------------------------")
        print("testcase execution done -- cleaning up ...")
        if not self.keepfiles:
            os.system("rm -f ./*.tmp")
            os.system("rm -f ./*.log")
            for template in self.__templates_generated:
                os.system("rm -f ./" + template)

    def runPySimShell(self, cardname:str, script:str,
                      add_adm:bool = False,
                      add_csv:bool = False,
                      no_exceptions = False):

        """ execute pySimShell.py. Each testcase should run pySim-shell at least once. The working directlry is the
        testcase directory.

        Args:
           cardname : name of the card as specified in config file (CONFIG_YAML)
           script : filename of the script file to execute.
           add_adm : use the --adm option to supply an ADM key via the commandline
           add_csv : use the --csv option to supply a CardKeyProvider file (CARD_DATA_CSV)
           no_exceptions : fail the testcase in case any exceptions occurred while running pySim_shell
        """

        logfile_name = "pySim-shell_" + self._testMethodName + "_" + str(self.pysim_shell_log_counter) + ".log"
        self.pysim_shell_log_counter+=1

        # Make sure the script file is available
        if not os.access(script, os.R_OK):
            raise RuntimeError("script file (%s) not found" % script)

        # Form basic commandline
        if cardname not in self.cards:
            raise RuntimeError("unknown cardname %s, check test setup and configuration file (%s)" % (cardname, CONFIG_YAML))
        reader = self.cards[cardname]['reader']
        cmdline = self.top_dir + "/pySim-shell.py -p " + str(reader) + " --script " + str(script) + " --noprompt"

        # Add optional arguments
        if add_adm:
            adm1 = self.cards[cardname]['adm1']
            cmdline += " --pin-adm " + str(adm1)
        if add_csv:
            adm1 = self.cards[cardname]['adm1']
            cmdline += " --csv " + self.top_dir + CARD_DATA_CSV

        # Execute commandline
        cmdline += " > " + logfile_name + " 2>&1"
        print("Executing: " + cmdline)
        rc = os.system(cmdline)
        if rc:
            raise RuntimeError("pySim-shell exits with error code %u" % rc)

        # Check for exceptions
        logfile = open(logfile_name)
        logfile_content = logfile.read()
        if self.print_content:
            print("pySim-shell logfile content: (%s)" % os.path.basename(logfile_name))
            print("-----------------------8<-----------------------")
            print(logfile_content)
            print("-----------------------8<-----------------------")
        logfile.close()
        exception_regex_compiled = re.compile('.*EXCEPTION.*')
        exceptions_strings = re.findall(exception_regex_compiled, logfile_content)
        if exceptions_strings != []:
            print("The following exceptions occurred:")
            for exceptions_string in exceptions_strings:
                print(exceptions_string)
            if no_exceptions:
                self.assertTrue(False, "Unexpected exceptions occurred!")
            else:
                print("Note: the occurrence of exceptions may be expected, the sheer presence of exceptions is not necessarly an error.")

    def __filter_lines(self, text:str, ignore_regex_list:list[str],
                    mask_regex_list:list[str], interesting_regex_list:list[str]):
        """ Filter data from text lines using regex_lists """

        # In case nor ignore or mask regexes are supplied, it makes no sense to continue. In this case, the full,
        # unmodified text is returned.
        if ignore_regex_list is None and mask_regex_list is None:
            return text

        # Compile regexes
        ignore_regex_compiled_list = []
        if ignore_regex_list:
            for regex in ignore_regex_list:
                ignore_regex_compiled_list.append(re.compile(regex))
        mask_regex_compiled_list = []
        if mask_regex_list:
            for regex in mask_regex_list:
                mask_regex_compiled_list.append(re.compile(regex))
        interesting_regex_compiled_list = []
        if interesting_regex_list:
            for regex in interesting_regex_list:
                interesting_regex_compiled_list.append(re.compile(regex))

        # Split up text into individual lines
        text_lines_filtered = []
        text_lines = text.splitlines()

        # Go through the text line by line and apply regexes
        for line in text_lines:
            # Detect interesting line, such a line must not be modified as it is deemed as interesting
            interesting_line = False
            for interesting_regex_compiled in interesting_regex_compiled_list:
                if re.findall(interesting_regex_compiled, line) != []:
                    interesting_line = True
                    break

            # Anything else that is not deemed as interesting gets the ignore+mask regexes applied
            if not interesting_line:
                for ignore_regex_compiled in ignore_regex_compiled_list:
                    line = re.sub(ignore_regex_compiled, "", line)
                for mask_regex_compiled in mask_regex_compiled_list:
                    line = re.sub(mask_regex_compiled, "*", line)

            # Add the modified line to the output (strip spaces)
            line = line.strip()
            if line != "":
                text_lines_filtered.append(line)

        return "\n".join(text_lines_filtered)

    def assertEqualFiles(self, out_file_path:str, ok_file_path:str = None,
                         ignore_regex_list:list[str] = None,
                         mask_regex_list:list[str] = None,
                         interesting_regex_list:list[str] = None):
        """ Compare an out-file against an ok-file. If differences are detected an assertion is thrown and the
        testcase fails. This method can also be used to re-generate the ok-file when self.regenerate is set to
        True.

        Args:
           out_file_path : path to the file which is generated by the testcase (e.g. test.tmp)
           ok_file_path : file to compara against (e.g. test.ok, optional when .ok and .tmp file have the same basename)
           ignore_regex_list : a list with regex strings to remove certain zones in both files before comparison.
           mask_regex_list : a list with regex strings to mask certain zones in both files before comparison.
           interesting_regex_list : a list with regex strings to select certain lines in the file that shall not be
                                    affected by ignore_regex_list.
        """

        if ok_file_path is None:
            path = Path(out_file_path)
            ok_file_path = path.with_suffix('.ok')

        # Read/regenerate files
        out_file = open(out_file_path)
        out_file_content = out_file.read()
        out_file.close()
        if self.regenerate:
            print("File comparison: regenerating (overwriting) content of %s with content of %s" %
                  (os.path.basename(out_file_path), os.path.basename(ok_file_path)))
            ok_file = open(ok_file_path, "w")
            ok_file.write(out_file_content)
            ok_file.close()
            return
        ok_file = open(ok_file_path)
        ok_file_content = ok_file.read()
        ok_file.close()

        # Apply line based filters
        out_file_content = self.__filter_lines(out_file_content, ignore_regex_list, mask_regex_list, interesting_regex_list)
        ok_file_content = self.__filter_lines(ok_file_content, ignore_regex_list, mask_regex_list, interesting_regex_list)
        if self.print_content:
            print("File comparison: the following file contents are compared with each other:")
            print("Comparing (%s)" % os.path.basename(out_file_path))
            print("-----------------------8<-----------------------")
            print(out_file_content)
            print("-----------------------8<-----------------------")
            print("With (%s)" % os.path.basename(ok_file_path))
            print("-----------------------8<-----------------------")
            print(ok_file_content)
            print("-----------------------8<-----------------------")

        # Final comparison
        if out_file_content == ok_file_content:
            print("File comparison: content of %s matches content of %s -- ok" %
                  (os.path.basename(out_file_path), os.path.basename(ok_file_path)))
            return

        # Generate test error (this assertion will always fail, we just use it to generate an error message and a diff)
        self.assertEqual(ok_file_content, out_file_content,
                         "File comparison: content %s does not match content of %s -- test failed" %
                         (os.path.basename(out_file_path), os.path.basename(ok_file_path)))


    def equipTemplate(self, output_path:str, template_path:str = None, **kwargs):
        """ Equip a template file with useful contents. A template may contain placeholders in the form of $MY_VAR (see
        also https://docs.python.org/2/library/string.html#template-strings).

        Args:
           output_path : path to the file which is generated by the from the template (e.g. test.script)
           template_path : path to the template file (e.g. test.template, optional when .template and .script file have
                           the same basename)
        """

        if template_path is None:
            path = Path(output_path)
            template_path = path.with_suffix('.template')

        print("Template: using template %s to generate file %s" % (template_path, output_path))

        template_file = open(template_path)
        template_content = template_file.read()
        template_file.close()

        output_template = Template(template_content)
        output_content = output_template.substitute(**kwargs)

        output_file = open(output_path, "w")
        output_file.write(output_content)
        output_file.close()

        self.__templates_generated.append(output_path)


    def getFileContent(self, file_path:str, substr_regex:str = None) -> str:
        """ Get contents from a file, optionally apply a regex to extract an interesting substring

        Args:
           file_path : path to the file to read (e.g. test.tmp)
           substr_regex : a regex expression to extract an interesting substring from the file content
        """

        print("File: reading content of file %s" % file_path)
        if not os.access(file_path, os.R_OK):
            self.assertTrue(False, "file (%s) not readable!" % file_path)
        file = open(file_path)
        file_content = file.read()
        file.close()
        if self.print_content:
            print("Content of File (%s):" % os.path.basename(file_path))
            print("-----------------------8<-----------------------")
            print(file_content)
            print("-----------------------8<-----------------------")

        if substr_regex:
            substr_regex_compiled = (re.compile(substr_regex))
            file_content = re.search(substr_regex_compiled, file_content).group(1)
            if self.print_content:
                print("Content of File (%s) after regex ('%s') applied:" % (os.path.basename(file_path), substr_regex))
                print("-----------------------8<-----------------------")
                print(file_content)
                print("-----------------------8<-----------------------")

        return file_content
