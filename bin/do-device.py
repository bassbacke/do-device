#! /usr/bin/python
"""
	Execute a script on a network device using ssh login creating a logfile.

	Syntax: do-device.py device script

	do-device.py imports pwdecrypt.py, which in turn requires environment variables

	Copyright (c) 2017-2019 by Kostis Netzwerkberatung
	Talstr. 25, D-63322 Roedermark, Tel. +49 6074 881056
	kosta@kostis.de (Konstantinos Kostis), http://www.kostis.de/

	You may use this script free of charge at your own risk.

	History:
	  2019-08-13: V0.38 KK
	    - cosmetic changes
	  2019-07-11: V0.37 KK
	    - added DEBUG level aware output
	  2019-07-08: V0.36 KK
	    - added port number
	  2019-07-04: V0.35 KK
		- exit OOB menue before running commands
	  2019-02-19: V0.34 KK
		- cosmetic changes
	  2019-01-15: V0.33 KK
		- added 'global_delay_factor' to pwdecrypt.py (improves connectivity to distant devices)
	  2018-08-16: V0.32 KK
		- use base script filename for log filename
		- converted leading blanks to tabs
	  2018-07-01: V0.32 KK
		- cosmetic improvement
	  2018-06-06: V0.31 KK
		- cosmetic improvement for error message when not being able to send command
	  2018-05-23: V0.30 KK
		- added option to name logfile
	  2017-06-25: V0.23 KK
		- initial coding (no history before release)
"""

import os
import sys
import getopt					# cli parameters
import time						# needed for sleep()
from pathlib import Path
from netmiko import ConnectHandler, cisco

from pwdecrypt import get_credentials

import logging

""" Global variables """

DEBUG = 0						# 0 means no debugging

logfile = ''

""" Python SCRIPT basename """

SCRIPT = os.path.basename(sys.argv[0])
VERSION = 'V0.38 (2019-08-13)'

""" ERROR CODES """

ERR_NONE = 0

ERR_SYNTAX = 1
ERR_NOSCRIPT = 2				# unable to access script
ERR_LOGFILE = 3					# logfile already exists
ERR_LOGCREATE = 4				# unable to create logfile

ERR_CREDENTIALS = 11			# error retrieving credentials
ERR_CONNECT = 12

ERR_SEND_COMMAND = 42

def WhatAmI(output):
	""" Display information about this script (to output). """

	print('Copyright (c) 2017-2019 by Kostis Netzwerkberatung', file=output)
	print('Written by Konstantinos Kostis (kosta@kostis.net)', file=output)
	print('Talstr. 25, D-63322 Roedermark, Germany', file=output)
	print('', file=output)
	print(SCRIPT, VERSION, file=output)
	print('', file=output)
	print('You may use this script free of charge at your own risk.', file=output)
	print('', file=output)

def Syntax(output):
	""" Say what we are and display script command line syntax (to output). """
	
	global DEBUG
	global logfile

	WhatAmI(output)
	print('Syntax:', SCRIPT, 'device script [options]', file=output)
	print('', file=output)
	print('options are:', file=output)
	print('', file=output)
	print('  -h --help', file=output)
	print('  -d --debug="', DEBUG, '"', sep='', file=output)
	print('  -l --logfile="', logfile, '"', sep='', file=output)

def exec_cmd(ssh_conn, cmd):
	""" Execute command via ssh_conn and display output on stdout. """
	
	global DEBUG

	""" Echo cmd so we find it in the log later. """
	print(cmd)
	if DEBUG > 0:
		print(cmd, file=sys.stderr)

	try:
		output = ssh_conn.send_command(cmd)
	except Exception as ERR_MSG:
		print(ERR_MSG, file=sys.stderr)
		return(ERR_SEND_COMMAND)

	print(output + '\n')
	if DEBUG > 0:
		print(output + '\n', file=sys.stderr)

	return(ERR_NONE)

def do_device(device, script, logfile):
	""" Execute commands listed in a script on a given device and store output in logfile. """

	if logfile == '':
		logfile = device + '-' + os.path.basename(script) + '.log'

	""" If logfile is already present, complain and abort. """
	if os.path.isfile(logfile):
		print('### ERROR ', SCRIPT, ': logfile ', logfile, ' exists', sep='', file=sys.stderr)
		return(ERR_LOGFILE)

	""" Read script file first. """
	try:
		f = open(script, 'r')
	except FileNotFoundError:
		WhatAmI(sys.stderr)
		print('### ERROR ', SCRIPT,': unable to access script file ', \
			script, file=sys.stderr, sep='')
		return(ERR_NOSCRIPT)
	except Exception as ERR_MSG:
		print(ERR_MSG, file=sys.stderr)
		print('I may need to add this to specific exceptions...', file=sys.stderr)
		return(ERR_NOSCRIPT)

	lines = f.readlines()
	f.close()

	""" Get credentials for device. """
	if DEBUG > 0:
		print('### DEBUG', SCRIPT, 'getting credentials for', device, file=sys.stderr)
		
	(credentials, ssh_port) = get_credentials(device)
	if credentials == None:
		WhatAmI(sys.stderr)
		print('### ERROR ', SCRIPT,': unable to determine credentials for ', device, file=sys.stderr, sep='')
		return(ERR_CREDENTIALS)
	
	""" Create logfile. """
	try:
		flog = open(logfile, 'w')
	except PermissionError:
		WhatAmI(sys.stderr)
		print('### ERROR ', SCRIPT,': no permission to create logfile ', logfile, sep='', file=sys.stderr)
		return(ERR_LOGCREATE)
	except IOError as ERR_MSG:
		WhatAmI(sys.stderr)
		print('### ERROR ', SCRIPT,': I/O error creating logfile ', logfile, sep='', file=sys.stderr)
		print(ERR_MSG, file=sys.stderr)
		return(ERR_LOGCREATE)
	except Exception as ERR_MSG:
		print(ERR_MSG, file=sys.stderr)
		print('I may need to add this to specific exceptions...', file=sys.stderr)
		return(ERR_LOGCREATE)

	""" Connect to device. """
	if DEBUG > 0:
		print('### DEBUG', SCRIPT, 'connecting to', device, 'on port', ssh_port, file=sys.stderr)
	
	try:
		if ssh_port == 22:
			ssh_conn = ConnectHandler(**credentials)
		else:
			ssh_conn = ConnectHandler(**credentials, port=ssh_port)
	except Exception as ERR_MSG:
		WhatAmI(sys.stderr)
		print('### ERROR ', SCRIPT,': unable to connect to ', \
			device, file=sys.stderr, sep='')
		print(ERR_MSG, file=sys.stderr)
		return(ERR_CONNECT)

	""" Redirect stdout to logfile. """
	saveout = sys.stdout
	sys.stdout = flog
	
	if DEBUG > 0:
		print('### DEBUG', SCRIPT, 'connection to', device, 'established', file=sys.stderr)

	""" Execute script line by line. """
	for cmd in lines:
		curcmd = cmd.lstrip()
		curcmd = curcmd.rstrip('\n')

		"""
		Treat lines starting with '!' as comments.
		When a line starts with '!!' it may be a special command like:
			!!enable, !!disable, !!config_mode, !!exit_config_mode
		"""

		lcmd = len(curcmd)
		""" Handle specials script commands (not officially supported). """
		if curcmd == '!!enable':
			""" Enter enable mode. """
			if enable != '-':
				ssh_conn.enable()
		elif curcmd == '!!disable':
			""" Enter disable mode. """
			ssh_conn.disable()
		elif curcmd == '!!config_mode':
			""" Enter config_mode. """
			ssh_conn.config_mode()
		elif curcmd == '!!exit_config_mode':
			""" Exit config_mode. """
			ssh_conn.exit_config_mode()
		elif lcmd > 0 and curcmd.startswith('!!sleep '):
			sleep = float(curcmd.replace('!!sleep ', ''))
			time.sleep(sleep)
		elif lcmd > 0 and not curcmd.startswith('!'):
			""" Handle regular script commands. """
			if DEBUG > 0:
				print('### DEBUG', SCRIPT, 'sending command', curcmd, file=sys.stderr)
			rc = exec_cmd(ssh_conn, curcmd)
			if (rc):
				sys.stdout = saveout
				flog.close()
				WhatAmI(sys.stderr)
				print('### ERROR ', SCRIPT,': error sending command "', curcmd, '" to device ', device, sep='', file=sys.stderr)
				return(rc)
		else:
			""" Echo empty and comment lines. """
			print(curcmd)

	""" Restore stdout to original value and close logfile. """
	sys.stdout = saveout
	flog.close()

	return(ERR_NONE)

def main():
	global DEBUG
	global logfile
	
	""" Check syntax and get options """
	try:
		opts, args = getopt.getopt(sys.argv[1:], \
			'hv:d:l:', \
			['help', 'debug=', 'logfile='])
	except getopt.GetoptError as err:
		Syntax(sys.stderr)
		return(1)
	
	""" Process options """
	for o, a in opts:
		if o in ('-h', '--help'):
			Syntax(sys.stderr)
			return(1)
		elif o in ('-d', '--debug'):
			DEBUG = int(a)
			print(SCRIPT, '### DEBUG', SCRIPT, 'DEBUG level', DEBUG, file=sys.stderr)
		elif o in ('-l', '--logfile'):
			logfile = a
		else:
			assert False, 'unhandled option'

	if len(args) < 2 or len(args) > 3:
		WhatAmI(sys.stderr)
		print('Syntax:', SCRIPT, 'device script [log]', file=sys.stderr)
		return(ERR_SYNTAX)

	device = args[0]
	script = args[1]
	logfile = ''
	if len(args) == 3:
		logfile = args[2]

	rc = do_device(device, script, logfile)

	return(rc)

if __name__ == '__main__':
	rc = main()
	sys.exit(rc)
