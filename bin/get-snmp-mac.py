#! /usr/bin/python3
"""
Copyright(c) 2020 by Kostis Netzwerkberatung
Talstr. 25. D-63322 Roedermark
kosta@kostis.de(Konstantinos Kostis). http://www.kostis.de/
You may use this script free of charge at your own risk.

get-snmp-mac.py

get mac to interface (vlan) data from a device using snmp

output format:
	mac,interface,vlan
		mac is in IEEE XX-XX-XX-XX-XX-XX format
		interface (local, short for Cisco)
		vlan is in decimal format

inspired by cammer.pl 2.0

2020-08-25: V0.11 KK
	- added DEBUG for get_credentials()
2020-08-18: V0.10 KK
	- initial encoding
"""

import os
import sys
import getopt
import time
import re
import ipaddress
import binascii
from pathlib import Path
from easysnmp import Session
from SNMP_pwdecrypt import get_credentials

SCRIPT = os.path.basename(sys.argv[0])
VERSION = 'V0.11 (2020-08-25)'

DEBUG = 0						# 0 means no debugging

HOME = os.environ['HOME']
DO_DEVICE = ''

OID = {\
	'ifName': 'iso.3.6.1.2.1.31.1.1.1.1',
	'dot1qTpFdbEntry': 'iso.3.6.1.2.1.17.7.1.2.2.1.2',
	'dot1dTpFdbPort': 'iso.3.6.1.2.1.17.4.3.1.2',
	'entLogicalDescr': 'iso.3.6.1.2.1.47.1.2.1.1.2',
	'vtpVlanState': 'iso.3.6.1.4.1.9.9.46.1.3.1.1.2',
	'dot1dBasePortIfIndex': 'iso.3.6.1.2.1.17.1.4.1.2'
}

def WhatAmI(output):
	""" Display information about this script (to output). """

	print('Copyright (c) 2020 by Kostis Netzwerkberatung', file=output)
	print('Written by Konstantinos Kostis (kosta@kostis.net)', file=output)
	print('Talstr. 25. D-63322 Roedermark. Germany',file=output)
	print('', file=output)
	print(SCRIPT, VERSION, file=output)
	print('', file=output)
	print('You may use this script free of charge at your own risk.', file=output)
	print('', file=output)

def Syntax(output):
	""" Say what we are and display script command line syntax (to output). """
	
	global DEBUG

	WhatAmI(output)
	print('Syntax:', SCRIPT, 'device', file=output)
	print('', file=output)
	print('options are:', file=output)
	print('', file=output)
	print('  -h --help', file=output)
	print('  -d --debug="', DEBUG, '"', sep='', file=output)

def short_ifName(ifName):
	""" Return short format ifName. """

	# handle Cisco IOS/NXOS devices
	ifName = ifName.replace('TenGigabitEthernet', 'Te')
	ifName = ifName.replace('GigabitEthernet', 'Gi')
	ifName = ifName.replace('FastEthernet', 'Fa')
	ifName = ifName.replace('Ethernet', 'Et')
	ifName = ifName.replace('Management', 'Ma')
	ifName = ifName.replace('Port-channel', 'Po')
	ifName = ifName.replace('port-channel', 'Po')

	# handle Cisco 31000 and such
	ifName = ifName.replace('switch', 'Et')

	# handle Ubiquiti Edge Switches
	ubiquiti_match = re.match('^0/\d+$', ifName)
	if ubiquiti_match:
		ifName = 'Et' + ifName
	ubiquiti_match = re.match('^3/\d+$', ifName)
	if ubiquiti_match:
		ifName = ifName.replace('3/', 'Po')

	# handle vlan interfaces
	if ifName.lower().startswith('vl'):
		ifName = ifName.replace('Vlan', '')	# take care of Cisco NXOS
		ifName = ifName.replace('Vl', '')	# take care of Cisco IOS
		ifName = ifName.replace('VLAN- ', '')	# take care of Ubiquiti ES
	elif ifName.lower().startswith('br-vlan'):
		ifName = ifName.replace('br-vlan', '')	# take care of Devolo

	return(ifName)

def dotted2ieee(mac):
	""" Convert dotted decimal format to IEEE (XX-XX-XX-XX-XX-XX). """

	# input format is dd.dd.dd.dd.dd.dd
	octets = mac.split('.')
	n_oct = len(octets)
	if n_oct != 6:
		return('')

	ieee = ''
	for i in range(0, n_oct):
		if i > 0:
			ieee = ieee + '-'
		ieee = ieee + format('%02X' % int(octets[i]))

	return(ieee)	# XX-XX-XX-XX-XX-XX

def read_int2vlan(filename):
	""" Read hostname;interface to vlan association. """

	if not os.path.isfile(filename):
		print('### WARNING ', SCRIPT, ': unable to access file ', filename, sep='', file=sys.stderr)
		return({})

	if DEBUG:
		print('### DEBUG ', SCRIPT, ': reading file ', filename, sep='', file=sys.stderr)

	int2vlan = {}		# key is hostname;interface, val is vlan
	with open(filename, 'r') as file:
		lines = file.readlines()

	for line in lines:
		curline = line.rstrip()
		if not curline.startswith('#') and curline.count(';') == 2:
			(hostname, interface, vlan) = curline.split(';')
			key = hostname + ';' + interface
			int2vlan[key] = vlan

	if DEBUG:
		print('### DEBUG ', SCRIPT, ': found ', len(int2vlan), ' entries', sep='', file=sys.stderr)

	return(int2vlan)

def SNMP_walk_ifName(session, hostname, int2vlan):
	""" Read ifNames from established session. """

	ifNames = {}	# key is ifIndex, val is ifName or vlan
	dot_num = re.compile('\.\d+')

	if DEBUG:
		print('### DEBUG ', SCRIPT, ': walking ifName', sep='', file=sys.stderr)

	try:
		result = session.walk(OID['ifName'])
	except Exception as ERR_MSG:
		WhatAmI(sys.stderr)
		print(ERR_MSG, file=sys.stderr)
		return({})

	for data in result:
		""" octet after OID is ifIndex """
		ifIndex = data.oid.replace(OID['ifName'] + '.', '')

		""" Handle ifName with '.vlan' (e. g. eth0.42) - used often on firewalls. """
		ifName = data.value
		ifName = short_ifName(ifName)
		vlan = ''
		match = dot_num.match(ifName)
		if match:
			dot = ifName.find('.')
			if dot > 0:
				vlan = ifName[dot + 1:]

		key = hostname + ';' + ifName

		""" use provided interface to vlan association if provided. """
		if key in int2vlan:
			vlan = int2vlan[key]
			if DEBUG:
				print('### DEBUG ', SCRIPT, ': detected vlan ', vlan, ' on interface ', ifName, sep='', file=sys.stderr)
			ifNames[ifIndex] = vlan
		elif vlan:
			""" handle vlan interface (digits only) """
			if int(vlan) > 0 and int(vlan) < 4096:
				ifNames[ifIndex] = vlan
				key = hostname + ';' + ifName
				if key in int2vlan:
					ifNames[ifIndex] = int2vlan[key]
				else:
					ifNames[ifIndex] = vlan
		else:
			""" handle all other ifName """
			ifNames[ifIndex] = ifName

	if DEBUG:
		print('### DEBUG ', SCRIPT, ': found ', len(ifNames), ' ifNames', sep='', file=sys.stderr)

	return(ifNames)

def SNMP_walk_dot1qTpFdbEntry(session, ifNames):
	""" Retrieve mac;ifName;vlan from hostname. """

	"""
		The OID used is tested on devices from:
			PLANET (WGSW-28040)
			Ubiquiti (ES-16-XG, US-8-60W)
		
		This will not work on devices from:
			Cisco (has proprietary OIDs)
	"""		
	mac2ifName = {}	# key mac;vlan, val ifName

	if DEBUG:
		print('### DEBUG ', SCRIPT, ': walking dot1qTpFdbEntry', sep='', file=sys.stderr)

	try:
		result = session.walk(OID['dot1qTpFdbEntry'])
	except Exception as ERR_MSG:
		WhatAmI(sys.stderr)
		print(ERR_MSG, file=sys.stderr)
		return(mac2ifName)

	if len(result) == 0:
		if DEBUG:
			print('### DEBUG ', SCRIPT, ': dot1qTpFdbEntry yielded no result.', sep='', file=sys.stderr)
		return(mac2ifName)

	for data in result:
		ifIndex = data.value
		vlanmac = data.oid.replace(OID['dot1qTpFdbEntry'] + '.', '')
		delim = vlanmac.find('.')
		vlan = vlanmac[:delim]
		mac = vlanmac[delim + 1:]
		mac = dotted2ieee(mac)
		key = mac + ';' + vlan
		ifName = ''
		if ifIndex in ifNames:
			ifName = ifNames[ifIndex]
		if DEBUG:
			print('### DEBUG ', SCRIPT, ': key ', key, 'ifIndex ', ifIndex, ' ifName ', ifName, sep='', file=sys.stderr)

		"""
			CPU - Ubiquiti
			lo - JUNOS false positve
		"""
		if not ifName.startswith('CPU') and not ifName.startswith('lo'):
			mac2ifName[key] = ifName

	if DEBUG:
		print('### DEBUG ', SCRIPT, ': found ', len(mac2ifName), ' mac2ifName', sep='', file=sys.stderr)

	return(mac2ifName)

def SNMP_walk_activevlans(session):
	""" Return activevlans. """

	""" Try Cisco first. """
	activevlans = {}

	try:
		result = session.walk(OID['vtpVlanState'])
	except Exception as ERR_MSG:
		WhatAmI(sys.stderr)
		print(ERR_MSG, file=sys.stderr)
		return(activevlans)

	if len(result) > 0:
		if DEBUG:
			print('### DEBUG ', SCRIPT, ': walking vtpVlanState', sep='', file=sys.stderr)

		for data in result:
			active = data.value
			if active == '1':
				vlan = int(data.oid.replace(OID['vtpVlanState'] + '.1.', ''))
				""" skip specials Cisco vlans """
				if vlan < 1002 or vlan > 1005:
					activevlans[vlan] = True
					if DEBUG:
						print('### DEBUG ', SCRIPT, ': active vlan ', vlan, sep='', file=sys.stderr)

		return(activevlans)

	if DEBUG:
		print('### DEBUG ', SCRIPT, ': vtpVlanState yielded no results.', sep='', file=sys.stderr)

	if DEBUG:
		print('### DEBUG ', SCRIPT, ': walking entLogicalDescr', sep='', file=sys.stderr)

	try:
		result = session.walk(OID['entLogicalDescr'])
	except Exception as ERR_MSG:
		WhatAmI(sys.stderr)
		print(ERR_MSG, file=sys.stderr)
		return(activevlans)

	if len(result) > 0:
		for data in result:
			vlan = data.result
			if vlan.lower().startswith('vlan'):
				vlan = vlan.lower().replace('vlan', '')
				activevlans[vlan] = True
				if DEBUG:
					print('### DEBUG ', SCRIPT, ': active vlan ', vlan, sep='', file=sys.stderr)

	if DEBUG:
		print('### DEBUG ', SCRIPT, ': found ', len(activevlans), ' vlans', sep='', file=sys.stderr)

	return(activevlans)

def SNMP_port2ifIndex(session, port):
	""" Map port to ifIndex. """

	ifIndex = ''

	port_OID = OID['dot1dBasePortIfIndex'] + '.' + port

	if DEBUG:
		print('### DEBUG ', SCRIPT, ': getting dot1dBasePortIfIndex.', port, sep='', file=sys.stderr)

	try:
		result = session.get(port_OID)
	except Exception as ERR_MSG:
		WhatAmI(sys.stderr)
		print(ERR_MSG, file=sys.stderr)
		return(activevlans)

	return(result.value) # ifIndex

def SNMP_mac2ifName2vlan(session, vlan, ifNames):
	""" Map mac;vlan to ifName. """

	mac2ifName = {}	# key is mac;vlan, val is ifName

	if DEBUG:
		print('### DEBUG ', SCRIPT, ': walking dot1dTpFdbPort', sep='', file=sys.stderr)

	try:
		result = session.walk(OID['dot1dTpFdbPort'])
	except Exception as ERR_MSG:
		WhatAmI(sys.stderr)
		print(ERR_MSG, file=sys.stderr)
		return(mac2ifName)

	if len(result) > 0:
		for data in result:
			mac = data.oid.replace(OID['dot1dTpFdbPort'] + '.', '')
			mac = dotted2ieee(mac)
			port = data.value
			ifIndex = SNMP_port2ifIndex(session, port)
			ifName = ''
			if ifIndex in ifNames:
				ifName = ifNames[ifIndex]
			if ifName != '':
				key = mac + ';' + str(vlan)
				mac2ifName[key] = ifName

	return(mac2ifName)

def SNMP_Cisco(host, port, session, ifNames, community):
	""" Retrieve information using Cisco OIDs. """

	mac2ifName = {}	# key is mac;vlan, val is ifName

	activevlans = SNMP_walk_activevlans(session)
	if len(activevlans) > 0:
		for vlan in activevlans:
			vlan_community = community + '@' + str(vlan)

			try:
				vlan_session = Session(hostname=host, community=vlan_community, version=2, remote_port=port)
			except Exception as ERR_MSG:
				print(ERR_MSG, file=sys.stderr)
				return(mac2ifName)

			mac2ifNamevlan = SNMP_mac2ifName2vlan(vlan_session, vlan, ifNames)
			mac2ifName.update(mac2ifNamevlan)

	return(mac2ifName)

def get_snmp_mac(community, hostname, ipaddr, port):
	""" Retrieve mac table from hostname using SNMP. """

	global DEBUG

	int2vlan = {}
	DO_DEVICE = ''
	if 'DO_DEVICE' in os.environ:
		DO_DEVICE = os.environ['DO_DEVICE']
		FN_INT2VLAN = DO_DEVICE + '/int2vlan' + '.csv'
		if os.path.isfile(FN_INT2VLAN):
			int2vlan = read_int2vlan(FN_INT2VLAN)
			if DEBUG:
				print('### DEBUG ', SCRIPT, ': read ', len(int2vlan), ' interfaces from ', FN_INT2VLAN, sep='', file=sys.stderr)

	vlan = ''
	dot_num = re.compile('\.\d+')

	""" override hostname if ipaddr is explictely given. """
	host = hostname
	if ipaddr != '':
		host = ipaddr

	try:
		session = Session(hostname=host, community=community, version=2, remote_port=port)
	except Exception as ERR_MSG:
		print(ERR_MSG, file=sys.stderr)
		return(0)

	if DEBUG:
		print('### DEBUG ', SCRIPT, ': session to ', community, '@', hostname, ' open.', sep='', file=sys.stderr)

	ifNames = SNMP_walk_ifName(session, hostname, int2vlan)
	if len(ifNames) == 0:
		if DEBUG:
			print('### DEBUG ', SCRIPT, ': no ifNames read.', sep='', file=sys.stderr)
		return(0)

	if DEBUG:
		for ifIndex in ifNames:
			ifName = ifNames[ifIndex]
			print('### DEBUG ', SCRIPT, ': ifNames[', ifIndex, ']=', ifName, sep='', file=sys.stderr)

	""" Try ISO OID first. """
	n_mac = 0
	mac2ifName = SNMP_walk_dot1qTpFdbEntry(session, ifNames)
	n_mac = len(mac2ifName)
	if n_mac == 0:
		""" ISO didn't work, try Cisco. """
		mac2ifName = SNMP_Cisco(host, port, session, ifNames, community)
		n_mac = len(mac2ifName)

	for key in sorted(mac2ifName):
		(mac, vlan) = key.split(';')
		ifName = mac2ifName[key]
		if ifName != '':
			print(mac, ';', ifName, ';', vlan, sep='')

	return(n_mac)

def main():
	""" """

	global DEBUG

	try:
		opts, args = getopt.getopt(sys.argv[1:], \
			'hd:', \
			['help', 'debug='])
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
			print('### DEBUG ', SCRIPT, ': DEBUG level ', DEBUG, sep='', file=sys.stderr)
		else:
			assert False, 'unhandled option'

	argc = len(args)
	if argc != 1:
		Syntax(sys.stderr)
		return(1)

	hostname = args[0]
	if DEBUG:
		print('### DEBUG ', SCRIPT, ': trying to determine credentials for ', hostname, sep='', file=sys.stderr)

	credentials = get_credentials(DEBUG, hostname)
	if credentials == None:
		print('### ERROR ', SCRIPT,': unable to determine credentials for ', hostname, file=sys.stderr, sep='')
		return(3)

	ipaddr = credentials['ipaddr']
	community = credentials['community']
	port = int(credentials['port'])

	n_mac = get_snmp_mac(community, hostname, ipaddr, port)
	if DEBUG:
		print('### DEBUG ', SCRIPT, ': read ', n_mac, ' mac entries', sep='', file=sys.stderr)

	return(0)

if __name__ == '__main__':
	rc = main()
	sys.exit(rc)
