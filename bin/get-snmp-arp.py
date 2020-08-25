#! /usr/bin/python3
"""
Copyright(c) 2020 by Kostis Netzwerkberatung
Talstr. 25. D-63322 Roedermark
kosta@kostis.de(Konstantinos Kostis). http://www.kostis.de/
You may use this script free of charge at your own risk.

get-snmp-arp.py

get arp cache data from a device using snmp

output format:
	mac;ipaddr;vlan
		mac is in IEEE XX-XX-XX-XX-XX-XX format
		ipaddr is in dotted-decimal(IPV4)
		vlan is in decimal format

inspired by cammer.pl 2.0

2020-08-18: V0.11 KK
	- add some Juniper support
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
VERSION = 'V0.11 (2020-08-19)'

DEBUG = 0						# 0 means no debugging

OID = {\
	'ifName': 'iso.3.6.1.2.1.31.1.1.1.1',
	'ipNetToMediaIfIndex': 'iso.3.6.1.2.1.4.22.1.1',
	'ipNetToMediaPhysAddress': 'iso.3.6.1.2.1.4.22.1.2'
}

ignore_ifNames = {\
	'bme0', 'Juniper',
	'jsrv', 'Juniper',
	'lo0', 'Juniper'
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

def ignore_ifName(ifName):
	""" True if ifName should be ignored else False. """

	for ignore in ignore_ifNames:
		if ifName.startswith(ignore):
			return(True)

	return(False)

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
		if ifName.startswith('vlan.'):
			# this may potentially be a Juniper device
			if DEBUG:
				print('### DEBUG ', SCRIPT, ': found vlan. ifName', sep='', file=sys.stderr)
	elif ifName.lower().startswith('br-vlan'):
		ifName = ifName.replace('br-vlan', '')	# take care of Devolo

	if ignore_ifName(ifName):
		ifName = ''

	return(ifName)

def bin2ieee(mac):
	""" Convert bin values in string into IEEE mac address. """

	n_oct = len(mac)
	if n_oct != 6:
		return('')

	ieee = ''
	for i in range(0, n_oct):
		if i > 0:
			ieee = ieee + '-'
		octet = ord(mac[i])
		ieee = ieee + format('%02X' % octet)

	return(ieee)	# XX-XX-XX-XX-XX-XX-XX

def is_valid_hostname(hostname):
	""" Check if given hostname is valid [RFC952/RFC1123] without dots. """

	""" This will not catch a trailing '-'. """
	host_match = re.match('^[0-9a-zA-Z][-0-9a-zA-Z]*$', hostname)
	if host_match:
		return(True)

	return(False)


def is_valid_ipaddr(ipaddr):
	""" Check if given ipaddr is valid IPv4 address. """

	try:
		ipcheck = ipaddress.IPv4Address(ipaddr)
	except:
		return(False)

	return(True)

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

def map_ipaddr2interface(ipaddr, ifNames, ipaddr2ifIndex):
	""" Associate ipaddr with ifIndex (vlan). """

	if ipaddr in ipaddr2ifIndex:
		ifIndex = ipaddr2ifIndex[ipaddr]
		if ifIndex in ifNames:
			return(ifNames[ifIndex])

	return('')

def get_snmp_arp(community, hostname, ipaddr, port):
	""" Retrieve ARP cache from hostname using SNMP. """
	
	global DEBUG

	vlan = ''
	int2vlan = {}

	DO_DEVICE = ''
	if 'DO_DEVICE' in os.environ:
		DO_DEVICE = os.environ['DO_DEVICE']
		FN_INT2VLAN = DO_DEVICE + '/int2vlan' + '.csv'
		if os.path.isfile(FN_INT2VLAN):
			int2vlan = read_int2vlan(FN_INT2VLAN)

	""" If ipaddr is given use instead of hostname (e.g. no DNS/hosts) """
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

	ipaddr2ifIndex = {}	# key is ipaddr, val is ifIndex
	result = session.walk(OID['ipNetToMediaIfIndex'])
	for data in result:
		ifIndex = data.value

		""" octet after OID is ifIndex.ipaddrr """
		ipaddr = data.oid
		ipaddr = ipaddr.replace(OID['ipNetToMediaIfIndex'] + '.', '')
		delim = ipaddr.find('.')
		ipaddr = ipaddr[delim + 1:]

		ipaddr2ifIndex[ipaddr] = ifIndex
		if DEBUG:
			print('### DEBUG ', SCRIPT, ': ipaddr2ifIndex[', ipaddr, ']=', ifIndex, sep='', file=sys.stderr)

	mac2ipaddr = {}	# key is mac, val is ipaddr[;ipaddr]
	result = session.walk(OID['ipNetToMediaPhysAddress'])
	for data in result:
		""" octet after OID is ifIndex.ipaddrr """
		ipaddr = data.oid
		ipaddr = ipaddr.replace(OID['ipNetToMediaPhysAddress'] + '.', '')
		delim = ipaddr.find('.')
		ifIndex = ipaddr[:delim]
		ipaddr = ipaddr[delim + 1:]

		mac = bin2ieee(data.value)
		if not mac in mac2ipaddr:
			mac2ipaddr[mac] = ipaddr
		else:
			mac2ipaddr[mac] = mac2ipaddr[mac] + ';' + ipaddr

	n_arp = 0
	for mac in sorted(mac2ipaddr):
		ips = mac2ipaddr[mac]
		for ipaddr in ips.split(';'):
			vlan = map_ipaddr2interface(ipaddr, ifNames, ipaddr2ifIndex)
			if vlan != '':
				print(mac, ';', ipaddr, ';', vlan, sep='')
				n_arp += 1

	return(n_arp)

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

	credentials = get_credentials(hostname)
	if credentials == None:
		print('### ERROR ', SCRIPT,': unable to determine credentials for ', hostname, file=sys.stderr, sep='')
		return(3)

	ipaddr = credentials['ipaddr']
	community = credentials['community']
	port = int(credentials['port'])

	n_arp = get_snmp_arp(community, hostname, ipaddr, port)
	if DEBUG:
		print('### DEBUG ', SCRIPT, ': read ', n_arp, ' arp entries', sep='', file=sys.stderr)

	return(0)

if __name__ == '__main__':
	rc = main()
	sys.exit(rc)
