#! /usr/bin/python
"""
Decrypt SNMP credentials for a given device.

SNMP-pwdecrypt.py uses environment variable DO_DEVICE.

DO_DEVICE - directory containing two files:

	SNMP-credentials.txt	contains account information /using realms)
	SNMP-deviceinfo.txt		contains device information

Copyright (c) 2020 by Kostis Netzwerkberatung
Talstr. 25, D-63322 Roedermark, Tel. +49 6074 881056
kosta@kostis.de (Konstantinos Kostis), http://www.kostis.de/

You may use this script free of charge at your own risk.

History:
  2020-08-18: V0.10 KK
	- initial coding (no history before release)
"""

import os
import sys
from cryptography.fernet import Fernet

SCRIPT = os.path.basename(sys.argv[0])

DEBUG = 0

def decrypt_password(crypted):
	""" Return decrypted password. """

	enc = crypted.encode('utf-8')

	""" The same CRYPTKEY must have been used for encryption. """

	CRYPTKEY = b'Vn3x5ZiaL8Tg7NU1f3TlZRYXHnVslrgQUISQIa8n5Bg='

	f = Fernet(CRYPTKEY)
	decrypt = f.decrypt(enc)

	decrypted = decrypt.decode('utf-8')

	return(decrypted)

def read_credentials(DO_DEVICE):
	""" Return dictionary of realms, return None if any error. """

	global DEBUG

	filename = os.path.join(DO_DEVICE, 'SNMP-credentials.txt')

	try:
		f = open(filename, 'r')
	except Exception as ERR_MSG:
		print('### ERROR read_credentials(): unable to file', filename, file=sys.stderr)
		print('### DEBUG:', ERR_MSG, file=sys.stderr)
		return(None)
	
	lines = f.readlines()
	f.close()

	realms = {}
	for line in lines:
		curline = line.lstrip()
		curline = curline.rstrip('\n')
		if len(curline) > 0 and not curline.startswith('#'):
			if curline.count(';') == 2:
				(myrealm, community, port) = curline.split(';')
				community = decrypt_password(community)
				if port == '*':
					port = '161'
				realm_data = {
					'community': community,
					'port': port
				}
				realms[myrealm] = realm_data
				
	if realms == {}:
		if DEBUG:
			print('### DEBUG read_credentials(): read no realms', file=sys.stderr)
		return(None)
		
	if DEBUG:
		print('### DEBUG read_credentials(): read', len(realms), 'realms', file=sys.stderr)
		print('### DEBUG read_credentials(): realms', realms, file=sys.stderr)

	return(realms)

def read_deviceinfo (DO_DEVICE, realms, device):
	""" Return credentials for given device, return None if any error. """

	filename = os.path.join(DO_DEVICE, 'SNMP-deviceinfo.txt')

	try:
		f = open(filename, 'r')
	except Exception as ERR_MSG:
		print('### ERROR read_deviceinfo (): unable to access', filename, file=sys.stderr)
		print('### DEBUG:', ERR_MSG, file=sys.stderr)
		return(None)

	lines = f.readlines()
	f.close()

	for line in lines:
		curline = line.lstrip()
		curline = curline.rstrip('\n')

		""" Skip comment lines and lines not following syntax. """

		if len(curline) > 0 and not curline.startswith('#'):
			if curline.count(';') != 3:
				continue

			if DEBUG:
				print('### DEBUG read_deviceinfo():', curline, file=sys.stderr)

			(curdevice, ipaddr, community, port) = curline.split(';')

			if len(community) > 0 and community.startswith('*'):
				my_realm = realms[community]
				community = my_realm['community']
			elif len(community) > 0:
				community = decrypt_password(community)
			if len(port) > 0 and port.startswith('*'):
				my_realm = realms[port]
				port = my_realm['port']

			if curdevice == device:
				if community == '' and username == '':
					print('### ERROR read_deviceinfo(): empty user credentials for', device, file=sys.stderr)
					return(None)
				if not port.isnumeric():
					print('### ERROR read_deviceinfo(): invalid port', port, file=sys.stderr)
					return(None)

				device_credentials = {
					'hostname': curdevice,
					'ipaddr': ipaddr,
					'community': community,
					'port': port
				}

				return(device_credentials)

	return(None)

def get_credentials(device):
	""" Return credentials ans ssh port for a given device. """

	DO_DEVICE = ''
	if 'DO_DEVICE' in os.environ:
		DO_DEVICE = os.environ['DO_DEVICE']
	else:
		print('### ERROR get_credentials(): environment variable DO_DEVICE must be set', file=sys.stderr)
		return(None)

	if not os.path.isdir(DO_DEVICE):
		print('### ERROR get_credentials(): unable to access directory', DO_DEVICE, file=sys.stderr)
		return(None)

	realms = read_credentials(DO_DEVICE)
	if realms is None:
		return(None)

	device_credentials = read_deviceinfo(DO_DEVICE, realms, device)

	return(device_credentials)

if __name__ == '__main__':
	if len(sys.argv) != 2:
		print ('### ERROR', SCRIPT, '- this module must be imported!')
		sys.exit(1)
	else:
		encoded = sys.argv[1]
		decoded = decrypt_password(encoded)
		print(decoded)