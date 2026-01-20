# -*- coding: utf-8 -*-

""" pySim: Logging
"""

#
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
#

import logging
from cmd2 import style

class _PySimLogHandler(logging.Handler):
    def __init__(self, log_callback):
        super().__init__()
        self.log_callback = log_callback

    def emit(self, record):
        formatted_message = self.format(record)
        self.log_callback(formatted_message, record)

class PySimLogger:
    """
    Static class to centralize the log output of PySim applications. This class can be used to print log messages from
    any pySim module. Configuration of the log behaviour (see setup and set_ methods) is entirely optional. In case no
    print callback is set (see setup method), the logger will pass the log messages directly to print() without applying
    any formatting to the original log message.
    """

    LOG_FMTSTR = "%(levelname)s: %(message)s"
    LOG_FMTSTR_VERBOSE = "%(module)s.%(lineno)d -- " + LOG_FMTSTR
    __formatter = logging.Formatter(LOG_FMTSTR)
    __formatter_verbose = logging.Formatter(LOG_FMTSTR_VERBOSE)

    # No print callback by default, means that log messages are passed directly to print()
    print_callback = None

    # No specific color scheme by default
    colors = {}

    # The logging default is non-verbose logging on logging level DEBUG. This is a safe default that works for
    # applications that ignore the presence of the PySimLogger class.
    verbose = False
    logging.root.setLevel(logging.DEBUG)

    def __init__(self):
        raise RuntimeError('static class, do not instantiate')

    @staticmethod
    def setup(print_callback = None, colors:dict = {}):
        """
        Set a print callback function and color scheme. This function call is optional. In case this method is not
        called, default settings apply.
        Args:
            print_callback : A callback function that accepts the resulting log string as input. The callback should
                             have the following format: print_callback(message:str)
            colors : An optional dict through which certain log levels can be assigned a color.
                     (e.g. {logging.WARN: YELLOW})
        """
        PySimLogger.print_callback = print_callback
        PySimLogger.colors = colors

    @staticmethod
    def set_verbose(verbose:bool = False):
        """
        Enable/disable verbose logging. (has no effect in case no print callback is set, see method setup)
        Args:
            verbose: verbosity (True = verbose logging, False = normal logging)
        """
        PySimLogger.verbose = verbose;

    @staticmethod
    def set_level(level:int = logging.DEBUG):
        """
        Set the logging level.
        Args:
            level: Logging level, valis log leves are: DEBUG, INFO, WARNING, ERROR and CRITICAL
        """
        logging.root.setLevel(level)

    @staticmethod
    def _log_callback(message, record):
        if not PySimLogger.print_callback:
            # In case no print callback has been set display the message as if it were printed trough a normal
            # python print statement.
            print(record.message)
        else:
            # When a print callback is set, use it to display the log line. Apply color if the API user chose one
            if PySimLogger.verbose:
                formatted_message = logging.Formatter.format(PySimLogger.__formatter_verbose, record)
            else:
                formatted_message = logging.Formatter.format(PySimLogger.__formatter, record)
            color = PySimLogger.colors.get(record.levelno)
            if color:
                if isinstance(color, str):
                    PySimLogger.print_callback(color + formatted_message + "\033[0m")
                else:
                    PySimLogger.print_callback(style(formatted_message, fg = color))
            else:
                PySimLogger.print_callback(formatted_message)

    @staticmethod
    def get(log_facility: str):
        """
        Set up and return a new python logger object
        Args:
            log_facility : Name of log facility (e.g. "MAIN", "RUNTIME"...)
        """
        logger = logging.getLogger(log_facility)
        handler = _PySimLogHandler(log_callback=PySimLogger._log_callback)
        logger.addHandler(handler)
        return logger
