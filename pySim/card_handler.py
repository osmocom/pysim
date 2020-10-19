#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" pySim: card handler utilities
"""

#
# (C) 2019 by Sysmocom s.f.m.c. GmbH
# All Rights Reserved
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


import subprocess
import sys
import yaml

# Manual card handler: User is prompted to insert/remove card from the reader.
class card_handler:

	sl = None

	def __init__(self, sl):
		self.sl = sl

	def get(self, first = False):
		print("Ready for Programming: Insert card now (or CTRL-C to cancel)")
		self.sl.wait_for_card(newcardonly=not first)

	def error(self):
		print("Programming failed: Remove card from reader")
		print("")

	def done(self):
		print("Programming successful: Remove card from reader")
		print("")

# Automatic card handler: A machine is used to handle the cards.
class card_handler_auto:

	sl = None
	cmds = None
	verbose = True

	def __init__(self, sl, config_file):
		print("Card handler Config-file: " + str(config_file))
		self.sl = sl
		with open(config_file) as cfg:
			self.cmds = yaml.load(cfg, Loader=yaml.FullLoader)

		self.verbose = (self.cmds.get('verbose') == True)

	def __print_outout(self,out):
		print("")
		print("Card handler output:")
		print("---------------------8<---------------------")
		stdout = out[0].strip()
		if len(stdout) > 0:
			print("stdout:")
			print(stdout)
		stderr = out[1].strip()
		if len(stderr) > 0:
			print("stderr:")
			print(stderr)
		print("---------------------8<---------------------")
		print("")

	def __exec_cmd(self, command):
		print("Card handler Commandline: " + str(command))

		proc = subprocess.Popen([command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
		out = proc.communicate()
		rc = proc.returncode

		if rc != 0 or self.verbose:
			self.__print_outout(out)

		if rc != 0:
			print("")
			print("Error: Card handler failure! (rc=" + str(rc) + ")")
			sys.exit(rc)

	def get(self, first = False):
		print("Ready for Programming: Transporting card into the reader-bay...")
		self.__exec_cmd(self.cmds['get'])
		self.sl.connect()

	def error(self):
		print("Programming failed: Transporting card to the error-bin...")
		self.__exec_cmd(self.cmds['error'])
		print("")

	def done(self):
		print("Programming successful: Transporting card into the collector bin...")
		self.__exec_cmd(self.cmds['done'])
		print("")
