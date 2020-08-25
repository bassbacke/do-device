#! /usr/bin/python
"""
	Execute a script on a network device using ssh login creating a logfile.
	Special edition for oob routers.

	Syntax: do-oob-device.py device script

	do-oob-device.py imports pwdecrypt.py, which in turn requires environment variables

	Copyright (c) 2019 by Kostis Netzwerkberatung
	Talstr. 25, D-63322 Roedermark, Tel. +49 6074 881056
	kosta@kostis.de (Konstantinos Kostis), http://www.kostis.de/

	You may use this script free of charge at your own risk.
	
	Useful links:
		- List of control codes: http://ascii-table.com/control-chars.php
"""

import os
import sys
import getopt					# cli parameters
import time						# needed for time.sleep()
from pathlib import Path
from netmiko import ConnectHandler, cisco
import paramiko

from pwdecrypt import get_credentials

import logging

""" Global variables """

DEBUG = 0						# 0 means no debugging

ignore = 0
logfile = ''

""" Python SCRIPT basename """

SCRIPT = os.path.basename(sys.argv[0])
VERSION = 'V0.21 (2019-08-07)'

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
	""" Display information about this script (to stderr). """

	print('Copyright (c) 2019 by Kostis Netzwerkberatung', file=output)
	print('Written by Konstantinos Kostis (kosta@kostis.net)', file=output)
	print('Talstr. 25, D-63322 Roedermark, Germany', file=output)
	print('', file=output)
	print(SCRIPT, VERSION, file=output)
	print('', file=output)
	print('You may use this script free of charge at your own risk.', file=output)
	print('', file=output)

def Syntax(output):
	""" Say what we are and display script command line syntax """
	global ignore
	global DEBUG
	global logfile

	WhatAmI(output)
	print('Syntax:', SCRIPT, 'device [options]', file=output)
	print('', file=output)
	print('options are:', file=output)
	print('', file=output)
	print('  -h --help', file=output)
	print('  -i --ignore', file=output)
	print('  -d --debug="', DEBUG, '"', sep='', file=output)
	print('  -l --logfile="', logfile, '"', sep='', file=output)
	
def receive(channel, command, password):
	""" Send command and get banner then device (login) prompt. """

	channel.send(command + '\n')
	banner = ''
	for i in range(3):
		time.sleep(1)
		if channel.recv_ready():
			buffer = channel.recv(9999)
			buffer = str(buffer.decode('utf-8'))
			if 'Connection' in buffer:
				return(buffer)
			banner = banner + buffer
			if 'assword:' in buffer:
				channel.send(password + '\n')
				time.sleep(1)
				if channel.recv_ready():
					buffer = channel.recv(9999)
					buffer = str(buffer.decode('utf-8'))
					banner = banner + buffer

	print(banner)

#	if 'assword' in banner:
#		if not 'assword OK' in banner:
#			return(banner)

	if banner == '':
		print('!!! no banner')
		return('')
	
	tries = 0
	output = ''
	while tries < 6 and output == '':
		print('*** sending CR/LF try', tries)
		channel.send('\n')
		for i in range(3):
			time.sleep(2)
			if channel.recv_ready():
				buffer = channel.recv(9999)
				try:
					buffer = str(buffer.decode('utf-8'))
				except:
					buffer = '!!! error non-Unicode character in output'
				if output == '':
					output = buffer
				else:
					output = output + buffer
				print(buffer)
			if 'ogin:' in output:
				return(output)
		tries += 1

	return(output)
	
def connect(hostname, username, password, line):
	""" Connect to a device console. """
	
	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	ssh.connect(hostname, port=22, username=username, password=password)

	channel = ssh.invoke_shell()

	command = 'ssh -p ' + line + ' ' + hostname
	print(command)
	output = receive(channel, command, password)
	print(output)
	
	if output == '':
		print('!!!', 'inactive line', line)
	elif not 'Connection' in output:
		channel.send('\036x')	# [Ctrl]^ x
		time.sleep(1)
		print('$ disco 1')
		channel.send('disco 1\n')
		prompt = ''
		for i in range(2):
			if channel.recv_ready():
				buffer = channel.recv(9999)
				buffer = str(buffer.decode('utf-8'))
				prompt = prompt + buffer
			time.sleep(1)
		print(prompt)
		if '[confirm]' in prompt:
			channel.send('\n')
			time.sleep(2)
			if channel.recv_ready():
				buffer = channel.recv(9999)
				buffer = str(buffer.decode('utf-8'))
				print(buffer)
	
	ssh.close()
	
	return(output)
	
def do_oob_device(device, logfile):
	""" Execute commands on a given OOB RTA device. """

	if logfile == '':
		logfile = device + '-' + os.path.basename(script) + '.log'

	""" If logfile is already present, complain and abort. """
	if os.path.isfile(logfile):
		print('*** ERROR ', SCRIPT, ': logfile ', logfile, ' exists', sep='', file=sys.stderr)
		return(ERR_LOGFILE)

	""" Get credentials for device. """
	(credentials, ssh_port) = get_credentials(device)
	if credentials is None:
		WhatAmI(sys.stderr)
		print('*** ERROR ', SCRIPT,': unable to determine credentials for ', \
			device, sep='', file=sys.stderr)
		return(ERR_CREDENTIALS)

	ipaddr = credentials['ip']
	username = credentials['username']
	password = credentials['password']
	
	""" Create logfile. """
	try:
		flog = open(logfile, 'w')
	except PermissionError:
		WhatAmI(sys.stderr)
		print('*** ERROR ', SCRIPT,': no permission to create logfile ', \
			logfile, sep='', file=sys.stderr)
		return(ERR_LOGCREATE)
	except IOError as ERR_MSG:
		WhatAmI(sys.stderr)
		print('*** ERROR ', SCRIPT,': I/O error creating logfile ', \
			logfile, sep='', file=sys.stderr)
		print(ERR_MSG, file=sys.stderr)
		return(ERR_LOGCREATE)
	except Exception as ERR_MSG:
		print(ERR_MSG, file=sys.stderr)
		print('I may need to add this to specific exceptions...', file=sys.stderr)
		return(ERR_LOGCREATE)

	""" Redirect stdout to logfile. """
	saveout = sys.stdout
	sys.stdout = flog
	
	""" Connect to device. """
	try:
		ssh_client = paramiko.SSHClient()
		ssh_client.load_system_host_keys()
		ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		ssh_client.connect(ipaddr, port=22, username=username, password=password)
	except Exception as ERR_MSG:
		WhatAmI(sys.stderr)
		print('$$$ ERROR ', SCRIPT,': unable to connect to ', \
			device, file=sys.stderr, sep='')
		print(ERR_MSG, file=sys.stderr)
		return(ERR_CONNECT)

	""" figure out lines and interfaces on device """
	command = 'show line'
	print(device + '$ ' + command)
	stdin, stdout, stderr = ssh_client.exec_command(command)
	buffer = str(stdout.read().decode('utf-8'))
	output = buffer
	
	ssh_client.close()

	offset = 2000
	lines = {}
	for txtline in output.splitlines():
		if 'TTY' in txtline:
			txtline = txtline.lstrip()
			if txtline.startswith('*'):
				txtline = txtline.replace('*', '')
			while '  ' in txtline:
				txtline = txtline.replace('  ', ' ')
			data = txtline.split()
			n_cols = len(data)
			col_roty = n_cols - 7	# handle speed 115200/115200 and no ' ' before next column
			interface = 'As' + data[0]	# column Tty
			line = data[1]	# column Line
			roty = data[col_roty]	# column Roty
			if roty == '-':
				roty = line
			rotynum = int(roty)	# column Roty
			line = str(offset + rotynum)
			if '/' in interface:
				lines[line] = interface

	""" walk through interfaces """
	print(device + '$', len(lines), 'lines', file=saveout)
	print(device + '$', len(lines), 'lines')
	for line in lines:
		interface = lines[line]
		print(device + '$ port ' + line + '=' + interface, file=saveout)
		print(device + '$ port ' + line + '=' + interface)
		output = connect(ipaddr, username, password, line)
		
	""" Restore stdout to original value and close logfile. """
	sys.stdout = saveout
	flog.close()

	return(ERR_NONE)

def main():
	global ignore
	global logfile
	
	""" Check syntax and get options """
	try:
		opts, args = getopt.getopt(sys.argv[1:], \
			'hv:id:l:', \
			['help', 'ignore', 'debug=', 'logfile='])
	except getopt.GetoptError as err:
		Syntax(sys.stderr)
		return(1)
	
	""" Process options """
	for o, a in opts:
		if o in ('-h', '--help'):
			Syntax(sys.stderr)
			return(1)
		elif o in ('-i', '--ignore'):
			ignore = 1
		elif o in ('-d', '--debug'):
			DEBUG = int(a)
		elif o in ('-l', '--logfile'):
			logfile = a
		else:
			assert False, 'unhandled option'

	if len(sys.argv) < 3 or len(sys.argv) > 4:
		WhatAmI(sys.stderr)
		print('Syntax:', SCRIPT, 'device [log]', file=sys.stderr)
		return(ERR_SYNTAX)

	device = sys.argv[1]
	logfile = ''
	if len(sys.argv) == 3:
		logfile = sys.argv[2]

	rc = do_oob_device(device, logfile)

	return(rc)

if __name__ == '__main__':
	rc = main()
	sys.exit(rc)
