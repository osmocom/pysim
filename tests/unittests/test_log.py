#!/usr/bin/env python3

# (C) 2025 by sysmocom - s.f.m.c. GmbH
# All Rights Reserved
#
# Author: Philipp Maier <pmaier@sysmocom.de>
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

import unittest
import logging
from pySim.log import PySimLogger
import io
import sys
from inspect import currentframe, getframeinfo

log = PySimLogger.get(__name__)

TEST_MSG_DEBUG = "this is a debug message"
TEST_MSG_INFO = "this is an info message"
TEST_MSG_WARNING = "this is a warning message"
TEST_MSG_ERROR = "this is an error message"
TEST_MSG_CRITICAL = "this is a critical message"

expected_message = None

class PySimLogger_Test(unittest.TestCase):

    def __test_01_safe_defaults_one(self, callback, message:str):
        # When log messages are sent to an unconfigured PySimLogger class, we expect the unmodified message being
        # logged to stdout, just as if it were printed via a normal print() statement.
        log_output = io.StringIO()
        sys.stdout = log_output
        callback(message)
        assert(log_output.getvalue().strip() == message)
        sys.stdout = sys.__stdout__

    def test_01_safe_defaults(self):
        # When log messages are sent to an unconfigured PySimLogger class, we expect that all messages are logged,
        # regardless of the logging level.
        self.__test_01_safe_defaults_one(log.debug, TEST_MSG_DEBUG)
        self.__test_01_safe_defaults_one(log.info, TEST_MSG_INFO)
        self.__test_01_safe_defaults_one(log.warning, TEST_MSG_WARNING)
        self.__test_01_safe_defaults_one(log.error, TEST_MSG_ERROR)
        self.__test_01_safe_defaults_one(log.critical, TEST_MSG_CRITICAL)

    @staticmethod
    def _test_print_callback(message):
        assert(message.strip() == expected_message)

    def test_02_normal(self):
        # When the PySimLogger is set up with its default values, we expect formatted log messages on all logging
        # levels.
        global expected_message
        PySimLogger.setup(self._test_print_callback)
        expected_message = "DEBUG: " + TEST_MSG_DEBUG
        log.debug(TEST_MSG_DEBUG)
        expected_message = "INFO: " + TEST_MSG_INFO
        log.info(TEST_MSG_INFO)
        expected_message = "WARNING: " + TEST_MSG_WARNING
        log.warning(TEST_MSG_WARNING)
        expected_message = "ERROR: " + TEST_MSG_ERROR
        log.error(TEST_MSG_ERROR)
        expected_message = "CRITICAL: " + TEST_MSG_CRITICAL
        log.critical(TEST_MSG_CRITICAL)

    def test_03_verbose(self):
        # When the PySimLogger is set up with its default values, we expect verbose formatted log messages on all
        # logging levels.
        global expected_message
        PySimLogger.setup(self._test_print_callback)
        PySimLogger.set_verbose(True)
        frame = currentframe()
        expected_message = __name__ + "." + str(getframeinfo(frame).lineno + 1) + " -- DEBUG: " + TEST_MSG_DEBUG
        log.debug(TEST_MSG_DEBUG)
        expected_message = __name__ + "." + str(getframeinfo(frame).lineno + 1) + " -- INFO: " + TEST_MSG_INFO
        log.info(TEST_MSG_INFO)
        expected_message = __name__ + "." + str(getframeinfo(frame).lineno + 1) + " -- WARNING: " + TEST_MSG_WARNING
        log.warning(TEST_MSG_WARNING)
        expected_message = __name__ + "." + str(getframeinfo(frame).lineno + 1) + " -- ERROR: " + TEST_MSG_ERROR
        log.error(TEST_MSG_ERROR)
        expected_message = __name__ + "." + str(getframeinfo(frame).lineno + 1) + " -- CRITICAL: " + TEST_MSG_CRITICAL
        log.critical(TEST_MSG_CRITICAL)

    def test_04_level(self):
        # When the PySimLogger is set up with its default values, we expect formatted log messages but since we will
        # limit the log level to INFO, we should not see any messages of level DEBUG
        global expected_message
        PySimLogger.setup(self._test_print_callback)
        PySimLogger.set_level(logging.INFO)

        # We test this in non verbose mode, this will also confirm that disabeling the verbose mode works.
        PySimLogger.set_verbose(False)

        # Debug messages should not appear
        expected_message = None
        log.debug(TEST_MSG_DEBUG)

        # All other messages should appear normally
        expected_message = "INFO: " + TEST_MSG_INFO
        log.info(TEST_MSG_INFO)
        expected_message = "WARNING: " + TEST_MSG_WARNING
        log.warning(TEST_MSG_WARNING)
        expected_message = "ERROR: " + TEST_MSG_ERROR
        log.error(TEST_MSG_ERROR)
        expected_message = "CRITICAL: " + TEST_MSG_CRITICAL
        log.critical(TEST_MSG_CRITICAL)

if __name__ == '__main__':
    unittest.main()
