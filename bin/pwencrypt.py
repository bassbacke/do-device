#! /usr/bin/python
"""
Encrypt a password given interactively.

	return 0 if all went well
	return 1 for syntax error
	return 2 if password repetition didn't match
	return 3 if password was empty

Copyright (c) 2017-2019 by Kostis Netzwerkberatung
Talstr. 25, D-63322 Roedermark, Tel. +49 6074 881056
kosta@kostis.de (Konstantinos Kostis), http://www.kostis.de/

You may use this script free of charge at your own risk.

History:
  2019-08-13: V0.12 KK
    - cosmetic changes
  2017-06-21: V0.11 KK
    - initial coding (no history before release)
"""

import os
import sys
import getpass
from pathlib import Path
from cryptography.fernet import Fernet

SCRIPT = os.path.basename(sys.argv[0])

def WhatAmI():
	""" display information about script (to STDERR) """

	print('Copyright (c) 2017-2019 by Kostis Netzwerkberatung', file=sys.stderr)
	print('Written by Konstantinos Kostis (kosta@kostis.net)', file=sys.stderr)
	print('Talstr. 25, 63322 Rödermark, Germany', file=sys.stderr)
	print('', file=sys.stderr)
	print(SCRIPT, 'V0.12 (2017-08-13)', file=sys.stderr)
	print('', file=sys.stderr)
	print('You may use this script free of charge at your own risk.', file=sys.stderr)
	print('', file=sys.stderr)

def encrypt_password(password):
	""" Return encrypted password. """
	
	""" the same CRYPTKEY must be used for decryption """
	
	CRYPTKEY = b'Vn3x5ZiaL8Tg7NU1f3TlZRYXHnVslrgQUISQIa8n5Bg='

	f = Fernet(CRYPTKEY)
	token = f.encrypt(password.encode('utf-8'))
	
	return(token)

def main():
	if len(sys.argv) != 1:
		WhatAmI()
		print('Syntax:', SCRIPT) 
		return(1)
	
	WhatAmI()
	
	password = getpass.getpass()
	if password == "":
		print('### ERROR ', SCRIPT, ': password empty', file=sys.stderr, sep='')
		return(3)
		
	chkpass = getpass.getpass('Repeat password:')

	if password != chkpass:
		print('### ERROR ', SCRIPT, ': passwords do not match', file=sys.stderr, sep='')
		return(2)

	token = encrypt_password(password)
	print(token.decode('utf-8'))

	return(0)

if __name__ == '__main__':
	rc = main()
	sys.exit(rc)
