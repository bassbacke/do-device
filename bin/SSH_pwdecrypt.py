#! /usr/bin/python
"""
Decrypt credentials for a given device.

SSH_pwdecrypt.py uses environment variable DO_DEVICE.

DO_DEVICE - directory containing two files:

	credentials.txt		contains account information /using realms)
	deviceinfo.txt		contains device information

Copyright (c) 2017-2020 by Kostis Netzwerkberatung
Talstr. 25, D-63322 Roedermark, Tel. +49 6074 881056
kosta@kostis.de (Konstantinos Kostis), http://www.kostis.de/

You may use this script free of charge at your own risk.

History:
  2020-08-25: V0.16 KK
    - renamed from pwdecrypt.py to SSH_pwdecrypt.py
	- more error checking for realms
	- added DEBUG parameter
  2019-08-13: V0.15 KK
    - cosmetic changes
  2019-07-08: V0.14 KK
    - added optional port number
  2019-01-15: V0.13 KK
	- added 'global_delay_factor' for longer timeout for distant devices
  2017-06-25: V0.12 KK
	- initial coding (no history before release)
"""

import os
import sys
from cryptography.fernet import Fernet

SCRIPT = os.path.basename(sys.argv[0])

def decrypt_password(crypted):
	""" Return decrypted password. """

	enc = crypted.encode('utf-8')

	""" The same CRYPTKEY must have been used for encryption. """

	CRYPTKEY = b'Vn3x5ZiaL8Tg7NU1f3TlZRYXHnVslrgQUISQIa8n5Bg='
	
	f = Fernet(CRYPTKEY)
	decrypt = f.decrypt(enc)
	
	decrypted = decrypt.decode('utf-8')

	return(decrypted)

def read_credentials(DEBUG, DO_DEVICE):
	""" Return dictionary of realms, return None if any error. """

	filename = os.path.join(DO_DEVICE, 'SSH-credentials.txt')

	try:
		f = open(filename, 'r')
	except Exception as ERR_MSG:
		print('### ERROR read_credentials (): unable to access credentials file', \
			filename, file=sys.stderr)
		print('### DEBUG:', ERR_MSG, file=sys.stderr)
		return(None)
	
	lines = f.readlines()
	f.close()

	realms = {}
	for line in lines:
		curline = line.lstrip()
		curline = curline.rstrip('\n')
		if len (curline) > 0 and not curline.startswith('#'):
			if curline.count(';') == 3:
				(myrealm, username, password, secret) = curline.split(';')
				password = decrypt_password(password)
				if secret == '*':
					secret = password
				else:
					secret = decrypt_password(secret)
				if username == '' or password == '' or secret == '':
					continue
				realm_data = {
					'username': username,
					'password': password,
					'secret': secret
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

def read_deviceinfo (DEBUG, DO_DEVICE, realms, device):
	""" Return credentials and sshh port for given device, return None and ssh port if any error. """

	ssh_port = 22	# default ssh port
	filename = os.path.join(DO_DEVICE, 'SSH-deviceinfo.txt')

	if DEBUG:
		print('### DEBUG read_deviceinfo(): device ', device, sep='', file=sys.stderr)

	try:
		f = open(filename, 'r')
	except Exception as ERR_MSG:
		print('### ERROR read_deviceinfo (): unable to access deviceinfo file', \
			  filename, file=sys.stderr)
		print('### DEBUG:', ERR_MSG, file=sys.stderr)
		return(None, ssh_port)

	lines = f.readlines()
	f.close()

	for line in lines:
		curline = line.lstrip()
		curline = curline.rstrip('\n')

		""" Skip comment lines and lines not following syntax. """

		if len(curline) > 0 and not curline.startswith('#'):
			if curline.count(';') != 5 and curline.count(';') != 6:
				if DEBUG:
					print('### DEBUG ', SCRIPT, ': invalid line ', curline, sep='', file=sys.stderr)
				continue

			if DEBUG:
				print('### DEBUG read_deviceinfo():', curline, file=sys.stderr)

			ssh_port = 22
			n_semicolon = curline.count(';')
			if n_semicolon == 5:
				(curdevice, ip, device_type, username, password, secret) = curline.split(';')
			elif n_semicolon == 6:
				(curdevice, ip, device_type, username, password, secret, ssh_port) = curline.split(';')
				ssh_port = int(ssh_port)

			if ip == '':
				ip = curdevice

			if len(username) > 0 and username.startswith('*'):
				if username in realms:
					my_realm = realms[username]
					username = my_realm['username']
				else:
					print('### WARNING ', SCRIPT, ': username realm ', username, ' for ', curdevice,' unknown', sep='', file=sys.stderr)
					username = ''
			if len(password) > 0 and password.startswith('*'):
				if password in realms:
					my_realm = realms[password]
					password = my_realm['password']
				else:
					print('### WARNING ', SCRIPT, ': password realm ', password, ' for ', curdevice,' unknown', sep='', file=sys.stderr)
					password = ''
			elif len(password) > 0:
				password = decrypt_password(password)

			if len(secret) > 0 and secret.startswith('*'):
				if secret in realms:
					my_realm = realms[secret]
					secret = my_realm['secret']
				else:
					print('### WARNING ', SCRIPT, ': secret realm ', secret, ' for ', curdevice,' unknown', sep='', file=sys.stderr)
					secret = ''
			elif len(secret) > 0:
				secret = decrypt_password(secret)

			if curdevice == device:
				if username == '' or password == '' or secret == '':
					return('', ssh_port)

				device_credentials = {
					'ip': ip,
					'global_delay_factor': 3,	# reach devices around the globe
					'device_type': device_type,
					'username': username,
					'password': password,
					'secret': secret
				}
				return(device_credentials, ssh_port)

	return(None, ssh_port)

def get_credentials(DEBUG, device):
	""" Return credentials ans ssh port for a given device. """

	ssh_port = 22
	DO_DEVICE = ''
	if 'DO_DEVICE' in os.environ:
		DO_DEVICE = os.environ['DO_DEVICE']
	else:
		print('### ERROR get_credentials (): environment variable DO_DEVICE must be set', file=sys.stderr)
		return(None, ssh_port)

	if not os.path.isdir(DO_DEVICE):
		print('### ERROR get_credentials (): unable to access directory', DO_DEVICE, file=sys.stderr)
		return(None, ssh_port)

	realms = read_credentials(DEBUG, DO_DEVICE)
	if realms is None:
		return(None, ssh_port)

	(device_credentials, ssh_port) = read_deviceinfo(DEBUG, DO_DEVICE, realms, device)

	return(device_credentials, ssh_port)

if __name__ == '__main__':
	if len(sys.argv) != 2:
		print ('### ERROR', SCRIPT, '- this module must be imported!')
		sys.exit(1)
	else:
		encoded = sys.argv[1]
		decoded = decrypt_password(encoded)
		print(decoded)
		sys.exit(0)
