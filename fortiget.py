#!/usr/bin/python
'''
## fortiget.py ##
This is to be a CLI quiery toolset for Fortinet Fortigate firewalls. 
Now it only lists status, routes and policies for specified port(s) 

==== Changes you might wanna make to get it to work====

I use ANSI colours here and there in the output. 
You might want to change them if your terminal emulator window is not dark like mine.

USER_NAME - user to use with your Fortigate box.
pxssh method I use to connect to the device requires a recognizable prompt.
Mine looks like "blah blah FW01 #". Change the global PROMPT_REGEX if yours does not end with "FW\d+ #"

'''


import re
import sys
import prettytable
import pxssh
import getpass


ARGV = sys.argv
USAGE = ARGV[0] + ' <Firewall hostname or IP> <port(s) or VPN interface(s)>' + '''

  To query several ports use:
\tport1 port2 port3
  Or the following BASH wildcards:
\tport{12..15} == port12 port13 port14 port15
\tport{2..3}{0..2} == port20 port21 port22 port30 port31 port32

''' + 'Type "' + ARGV[0] + ' help" to see this message\n'

# prompt for the pxssh to look for
PROMPT_REGEXP = 'FW\d+ # '
# script will use this username to login
USER_NAME = 'admin' 

def FwConnection(ip):
	'''
	Gets a pxssh connection to a Fortigate unit.
	Args:
		ip = ip address of a Fortigate unit. Hostname should do perfectly well too.
	Returns:
		ssh - an established pxssh connection
	'''
	ssh = pxssh.pxssh()
	password = getpass.getpass('password: ')
	username = USER_NAME
	# Set the output not to use pager like "more" or "less"
	nomore = 'config system console\n' + 'set output standard\n' + 'end'
	ssh.PROMPT = PROMPT_REGEXP
	try:
		ssh.login(ip, username, password, auto_prompt_reset=False, original_prompt=' # ')
		ssh.sendline(nomore)
		ssh.prompt()
	except pxssh.ExceptionPxssh as e:
		print("Login failed")
		print(e)
	return ssh


def GetSystemInterface(ssh, port):
	'''
	Gets interface status and settings.
	Args:
		ssh - established pxssh connection
		port - interface name 
	Returns:
		port_data = {'ip': <ip address>, 'mask': <mask>, 'status': <link up/down>}
	'''
	ssh.sendline('get system interface | grep -f ' + port)
	ssh.prompt()
	raw_out = ssh.before

	re_port = re.compile('.*' + port + '\s*\w*\:*\s*\w*\s*ip\:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+status\:\s+(\w+).*', re.DOTALL)
	port_data_tuple = re_port.match(raw_out)
	port_data = {}
	if port_data_tuple:
		 port_data = {'ip': port_data_tuple.groups()[0],
		 			  'mask': port_data_tuple.groups()[1],
		 			  'status': port_data_tuple.groups()[2]}
	if len(port_data) == 0:
		print '\033[1m' + port + '\033[0m was not found on this device'
		raise SystemExit(10)

	return port_data


def GetRoutes(ssh, port):
	'''
	Gets routes for a given port.
	Args:
		ssh - established pxssh connection
		port - interface name 
	Returns:
		routes = {'type': <C/S/B...>, 'gw': <gw ip>, 'dst': <destination>}
	'''
	routes = []
	ssh.sendline('get router info routing-table all | grep ' + port)
	ssh.prompt()
	raw_out = ssh.before

	raw_out_list = raw_out.split('\n')
	re_routes = re.compile('(.*)' + port + '\W+(.*)\r')
	re_dst = re.compile('.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2})\D.*')
	re_gw = re.compile('.*via\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\D.*')
	re_direct = re.compile('.*is (directly connected).*')
	re_type = re.compile('^(\w)\W.*')
	for line in raw_out_list:
		route_match = re_routes.match(line)
		if route_match:
			route = {}
			type_match = re_type.match(line)
			if type_match:
				route['type'] = type_match.groups()[0]
			dst_match = re_dst.match(line)
			if dst_match:
				route['dst'] = dst_match.groups()[0]
			gw_match = re_gw.match(line)
			if gw_match:
				route['gw'] = gw_match.groups()[0]
			else:
				direct_match = re_direct.match(line)
				if direct_match:
					route['gw'] = direct_match.groups()[0]
			if route:
				routes.append(route)
	if len(routes) == 0:
			print 'no routes found for this inteface'

	return routes


def GetPortPolicies(ssh, port):
	'''
	Gets policies for a given port.
	Args:
		ssh - established pxssh connection
		port - interface name 
	Returns:
		policies = {'number': <policy id>,
				    'srcintf': [<source interface>, ...], 
				    'dstintf': [<destination interface>, ...],
				    'srcaddr': [<source ip>, ...],
				    'dstaddr': [<destination ip>, ...],
				    'service': [<service>, ...],
				    'action': <action>}
	'''
	policies = []
	ssh.sendline('show firewall policy | grep -f ' + port + '\\"')
	ssh.prompt()
	raw_out = ssh.before

	raw_out_list = raw_out.split('\n')

	re_edit = re.compile('\s+edit (\d{1,3}).*')
	re_next = re.compile('\s+next')
	re_dstintf = re.compile('\s+set dstintf \"(.+)\".*')
	re_srcintf = re.compile('\s+set srcintf \"(.+)\".*')
	re_dstaddr = re.compile('\s+set dstaddr \"(.+)\".*')
	re_srcaddr = re.compile('\s+set srcaddr \"(.+)\".*')
	re_service = re.compile('\s+set service \"(.+)\".*')
	re_action = re.compile('\s+set action (.+)\r.*')
	re_nat = re.compile('\s+set nat enable')
	re_natpool = re.compile('\s+set poolname "(.+)"')

	policy = {}
	for line in raw_out_list:
		match_next = re_next.match(line)
		if match_next:

			# Setting direction
			if port in policy['srcintf']:
				policy['direction'] = "from"
			elif port in policy['dstintf']:
				policy['direction'] = "to"
			else:
				policy['direction'] = "none"

			# If SSL-VPN - there is no service
			if policy['action'] == 'ssl-vpn':
				policy['service'] = ['n/a']

			policies.append(policy)
			policy = {}
			continue
		else:
			edit_match = re_edit.match(line)
			if edit_match:
				policy['number'] = int(edit_match.groups()[0])
				# Se NAT to false until we prove opposite
				policy['nat'] = False
			
			srcintf_match = re_srcintf.match(line)
			if srcintf_match:
				policy['srcintf'] = srcintf_match.groups()[0].split('\" \"')

			dstintf_match = re_dstintf.match(line)
			if dstintf_match:
				policy['dstintf'] = dstintf_match.groups()[0].split('\" \"')

			srcaddr_match = re_srcaddr.match(line)
			if srcaddr_match:
				policy['srcaddr'] = srcaddr_match.groups()[0].split('\" \"')

			dstaddr_match = re_dstaddr.match(line)
			if dstaddr_match:
				policy['dstaddr'] = dstaddr_match.groups()[0].split('\" \"')

			service_match = re_service.match(line)
			if service_match:
				policy['service'] = service_match.groups()[0].split('\" \"')

			action_match = re_action.match(line)
			if action_match:
				policy['action'] = action_match.groups()[0]

			nat_match = re_nat.match(line)
			if nat_match:
				policy['nat'] = True

			natpool_match = re_natpool.match(line)
			if natpool_match:
				policy['natpool'] = natpool_match.groups()[0]

	return policies


def GetUnderline(text_to_underline, char):
	'''
	Gets a line of "char" with length of a given string.
	Args:
		text_to_underline - string to count the length from
		char - character to repeat len(text_to_underline) times
	Returns:
		underline - line of char repeated len(text_to_underline) times
	'''
	underline = ''
	for i in range(0,len(text_to_underline)):
		underline += char
	return underline


def ParseArgs(ARGV):
	'''
	More as a placeholder to parse arguments than really a parser
	'''
	if len(ARGV) < 3:
		print USAGE
		raise SystemExit(1)

	params = ' '.join(ARGV[1:])
	re_param = re.compile('(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) .+')
	param_match = re_param.match(params)

	# if no ip address followed by some text found
	if (not param_match) or (ARGV[1] == 'help'):
		print USAGE
		raise SystemExit(0)

	port_list = ARGV[2:]

	return port_list


def uniq(input):
	'''Builds list of uniq items from a list where there might be duplicates
	Args:
		input - list with duplicates
	Returns:
		output - list with no duplicates'''
	output = []
	for x in input:
		if x not in output:
			output.append(x)
  	return output


def dec2cidr(dec_netmask):
	'''
	Converts dot decimal netmask notation to cidr
	Args:
		dec_netmask - dot decimal netmask like 255.255.255.0
	Returns:
		cidr, e.g 24
	'''
	cidr = 0
	octet_len = {'0': 0,
				 '128': 1,
				 '196': 2,
				 '224': 3,
				 '240': 4,
				 '248': 5,
				 '252': 6,
				 '254': 7,
				 '255': 8}

	octets = dec_netmask.split('.')
	for octet in octets:
		try:
			cidr += octet_len[octet]
		except KeyError:
			print 'Weird mask ' + dec_netmask
	
	return cidr


def GetIpPools(ssh):
	'''
	Gets full list of al registered IP pools with there names, start and end ip.
	Args:
		ssh - established pxssh connection
	Returns:
		ip_pools = {pool_name: [start_ip, end_ip]}
	'''
	ssh.sendline('show firewall ippool')
	ssh.prompt()
	raw_out = ssh.before

	raw_out_list = raw_out.split('\n')

	re_edit = re.compile('\s+edit "(.+)"')
	re_startip = re.compile('\s+set startip (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
	re_endip = re.compile('\s+set endip (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

	ip_pools = {}

	for line in raw_out_list:
		edit_match = re_edit.match(line)
		startip_match = re_startip.match(line)
		endip_match = re_endip.match(line)

		if edit_match:
			curr_pool = edit_match.groups()[0]
			ip_pools[curr_pool] = {}
		if startip_match:
			ip_pools[curr_pool]['start'] = startip_match.groups()[0]
		if endip_match:
			ip_pools[curr_pool]['end'] = endip_match.groups()[0]

	return ip_pools	


def GetAddrGroups(ssh):
	'''
	Gets all the Address Group objects and their members.
	Args:
		ssh - established pxssh connection
	Returns:
		grp_members = {Grp_obj: [addr_obj1, ...]}
	'''
	ssh.sendline('show firewall addrgrp')
	ssh.prompt()
	raw_out = ssh.before

	raw_out_list = raw_out.split('\n')

	re_edit = re.compile('\s+edit "(.+)"')
	re_members = re.compile('\s+set member "(.+)"')

	# Build full dict of groups {grp: [addr1, ...]}
	grp_members = {}

	for line in raw_out_list:
		edit_match = re_edit.match(line)
		members_match = re_members.match(line)

		if edit_match:
			curr_grp = edit_match.groups()[0]
		if members_match:
			grp_members[curr_grp] = members_match.groups()[0].split('" "')

	return grp_members


def ResolveAddrGroups(policies, grp_members):
	'''
	Swaps Address/VIP Group objects with a list of all the address/VIP objects led by group address.
	Args:
		policies = {'number': <policy id>,
				    'srcintf': [<source interface>, ...], 
				    'dstintf': [<destination interface>, ...],
				    'srcaddr': [<source ip>, ...],
				    'dstaddr': [<destination ip>, ...],
				    'service': [<service>, ...],
				    'action': <action>}
		grp_members = {Grp_obj: [addr_obj1, ...]} - groups and their members
	Returns:
		policies with the {src|dst}addr swapped as follows:
		original = [ Addr1, Addr2, GRPaddr1, Addr4]
		result = [ Addr1, Addr2, ~GRP~ GRPaddr1:, subaddr1, subaddr2 ..., Addr4]
	'''
	for policy in policies:
		srcaddr_list = policy['srcaddr']
		dstaddr_list = policy['dstaddr']
		for addr in srcaddr_list:
			if addr in grp_members:
				# insert the list of addresses instead of Group Addr
				ind = policy['srcaddr'].index(addr)
				policy['srcaddr'][ind + 1:ind + 1] = ['\033[1m~GRP~ ' + addr + ':\033[0m'] + grp_members[addr] + ['\033[1m~end~\033[0m']
				del policy['srcaddr'][ind]

		for addr in dstaddr_list:
			if addr in grp_members:
				# insert the list of addresses instead of Group Addr
				ind = policy['dstaddr'].index(addr)
				policy['dstaddr'][ind + 1:ind + 1] = ['\033[1m~GRP~ ' + addr + ':\033[0m'] + grp_members[addr] + ['\033[1m~end~\033[0m']
				del policy['dstaddr'][ind]

	return policies


def GetVIPGroups(ssh):
	'''
	Gets all the VIP Group objects and their members.
	Args:
		ssh - established pxssh connection
	Returns:
		grp_members = {Grp_obj: [vip_obj1, ...]}
	'''
	ssh.sendline('show firewall vipgrp')
	ssh.prompt()
	raw_out = ssh.before

	raw_out_list = raw_out.split('\n')

	re_edit = re.compile('\s+edit "(.+)"')
	re_members = re.compile('\s+set member "(.+)"')

	# Build full dict of groups {grp: [addr1, ...]}
	grp_members = {}

	for line in raw_out_list:
		edit_match = re_edit.match(line)
		members_match = re_members.match(line)

		if edit_match:
			curr_grp = edit_match.groups()[0]
		if members_match:
			grp_members[curr_grp] = members_match.groups()[0].split('" "')

	return grp_members


def GetServiceGroups(ssh):
	'''
	Gets all the Address Group objects and their members.
	Args:
		ssh - established pxssh connection
	Returns:
		grp_members = {Srv_GRP_obj: [srv_obj1, ...]}
	'''
	ssh.sendline('show firewall service group' )
	ssh.prompt()
	raw_out = ssh.before

	raw_out_list = raw_out.split('\n')

	re_edit = re.compile('\s+edit "(.+)"')
	re_members = re.compile('\s+set member "(.+)"')

	# Build full dict of groups {grp: [addr1, ...]}
	grp_members = {}

	for line in raw_out_list:
		edit_match = re_edit.match(line)
		members_match = re_members.match(line)

		if edit_match:
			curr_grp = edit_match.groups()[0]
		if members_match:
			grp_members[curr_grp] = members_match.groups()[0].split('" "')

	return grp_members


def ResolveSrvGroups(policies, grp_members):
	'''
	Swaps Service Group objects with a list of all the services objects led by group name.
	Args:
		policies = {'number': <policy id>,
				    'srcintf': [<source interface>, ...], 
				    'dstintf': [<destination interface>, ...],
				    'srcaddr': [<source ip>, ...],
				    'dstaddr': [<destination ip>, ...],
				    'service': [<service>, ...],
				    'action': <action>}
		grp_members = {Grp_obj: [srv_obj1, ...]} - groups and their members
	Returns:
		policies with the services swapped as follows:
		original = [ Srv1, Srv2, GRPsrv1, Srv4]
		result = [ Srv1, Srv2, ~GRP~ GRPsrv1:, subsrv1, subsrv2 ..., Srv4]
	'''
	for policy in policies:
		srvlist = policy['service']

		for srv in srvlist:
			if srv in grp_members:
				# insert the list of services instead of Service group
				ind = policy['service'].index(srv)
				policy['service'][ind + 1:ind + 1] = ['\033[1m~GRP~ ' + srv + ':\033[0m'] + grp_members[srv] + ['\033[1m~end~\033[0m']
				del policy['service'][ind]

	return policies


def GetSRVsFromPolicies(ssh, policies):
	'''
	Gets the numeric TCP/UDP port numbers instead of their names for all SRV objects in policies.
	Args:
		ssh - established pxssh connection
		policies = {'number': <policy id>,
				    'srcintf': [<source interface>, ...], 
				    'dstintf': [<destination interface>, ...],
				    'srcaddr': [<source ip>, ...],
				    'dstaddr': [<destination ip>, ...],
				    'service': [<service>, ...],
				    'action': <action>}
	Returns:
		srvs = {<SRV object name>: <numeric TCP and/or UDP port/range>, }
	'''
	# Get list of Services in policies
	srv_list_dups = []
	for policy in policies:
		srv_list_dups += policy['service']

	srv_list = uniq(srv_list_dups)

	ssh.sendline('config firewall service custom\nshow full-configuration\nend' )
	ssh.prompt()
	raw_out = ssh.before

	raw_out_list = raw_out.split('\n')

	re_edit = re.compile('\s+edit "(.+)"')
	re_tcp = re.compile('\s+set tcp-portrange (\d.*\d).*')
	re_udp = re.compile('\s+set udp-portrange (\d.*\d).*')

	srvs = {}

	tcp = ''
	udp = ''
	to_add = 0

	for line in raw_out_list:
		edit_match = re_edit.match(line)
		tcp_match = re_tcp.match(line)
		udp_match = re_udp.match(line)

		if edit_match:
			# We hit a new service clause - let's add the current one
			if tcp and udp and to_add:
				srvs[curr_srv] = tcp + ' ' + udp
			elif tcp and to_add:
				srvs[curr_srv] = tcp
			elif udp and to_add:
				srvs[curr_srv] = udp

			to_add = 0
			tcp = ''
			udp = ''
			# if what we found is in our policies
			if edit_match.groups()[0] in srv_list:
				curr_srv = edit_match.groups()[0]
				to_add = 1
		if tcp_match and to_add:
			tcp = 'TCP/' + tcp_match.groups()[0]
		if udp_match and to_add:
			udp = 'UDP/' + udp_match.groups()[0]
	# This is the last found. I know it's ugly, but I'm tired and want to go home
	if tcp and udp and to_add:
		srvs[curr_srv] = tcp + ' ' + udp
	elif tcp and to_add:
		srvs[curr_srv] = tcp
	elif udp and to_add:
		srvs[curr_srv] = udp

	return srvs


def GetIPsFromPolicies(ssh, policies):
	'''
	Gets the numeric IPs instead of their names for all IP objects in policies.
	I'm only having subnets and ipranges as address objects, so add yours here if needed. 
	Args:
		ssh - established pxssh connection
		policies = {'number': <policy id>,
				    'srcintf': [<source interface>, ...], 
				    'dstintf': [<destination interface>, ...],
				    'srcaddr': [<source ip>, ...],
				    'dstaddr': [<destination ip>, ...],
				    'service': [<service>, ...],
				    'action': <action>}
	Returns:
		ips = {<IP object name>: <numeric IP subnet/range>, }
			where subnet is like 10.11.12.0/24
			and range is like 10.11.12.1-10.11.12.5
	'''
	ip_list_dups = []
	for policy in policies:
		ip_list_dups += policy['srcaddr'] + policy['dstaddr']

	# List with uniq IP names only
	ip_list = uniq(ip_list_dups)

	ips = {}

	ssh.sendline('show firewall address')
	ssh.prompt()
	raw_out = ssh.before

	raw_out_list = raw_out.split('\n')

	re_edit = re.compile('\s+edit "(.+)"')
	re_next = re.compile('\s+next')
	re_range = re.compile('\s+set type iprange.*')
	re_end_ip = re.compile('\s+set end-ip (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*')
	re_start_ip = re.compile('\s+set start-ip (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*')
	re_subnet = re.compile('\s+set subnet (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*')

	# Flag indicating that we are in a clause containing an address we want
	to_add = 0
	# Flag indicating that this object is an ip range rather then subnet
	is_range = 0
	ip = ''
	start_ip = ''
	end_ip = ''
	curr_ip = ''

	for line in raw_out_list:
		edit_match = re_edit.match(line)
		range_match = re_range.match(line)
		start_ip_match = re_start_ip.match(line)
		end_ip_match = re_end_ip.match(line)
		subnet_match = re_subnet.match(line)

		if edit_match:
			if edit_match.groups()[0] in ip_list:
				curr_ip = edit_match.groups()[0]
				to_add = 1
			else:
				to_add = 0
		if range_match:
			is_range = 1
		if start_ip_match and to_add and is_range:
			start_ip = start_ip_match.groups()[0]
		if end_ip_match and to_add and is_range:
			end_ip = end_ip_match.groups()[0]
		if subnet_match and to_add:
			ip = subnet_match.groups()[0] + '/' + str(dec2cidr(subnet_match.groups()[1]))
		if is_range and start_ip and end_ip and to_add:
			ip = start_ip + '-' + end_ip
		if ip and to_add:
			ip = '\033[032m' + ip + '\033[0m'
			ips[curr_ip] = ip
			is_range = 0
			start_ip = ''
			end_ip = ''
			ip = ''
			to_add = 0
	return ips


def GetVIPsFromPolicies(ssh, policies):
	'''
	Gets the numeric VIP mappings instead of their names for all VIP objects in policies.
	Args:
		ssh - established pxssh connection
		policies = {'number': <policy id>,
				    'srcintf': [<source interface>, ...], 
				    'dstintf': [<destination interface>, ...],
				    'srcaddr': [<source ip>, ...],
				    'dstaddr': [<destination ip>, ...],
				    'service': [<service>, ...],
				    'action': <action>}
	Returns:
		vips = {<VIP object name>: <-VIP- in:mappedip
										 out:extip>, }
	'''

	ip_list_dups = []
	for policy in policies:
		ip_list_dups += policy['srcaddr'] + policy['dstaddr']

	# List with uniq IP names only
	ip_list = uniq(ip_list_dups)

	vips = {}

	ssh.sendline('show firewall vip')
	ssh.prompt()
	raw_out = ssh.before

	raw_out_list = raw_out.split('\n')

	re_edit = re.compile('\s+edit "(.+)"')
	re_extip = re.compile('\s+set extip (.+\d).*')
	re_mappedip = re.compile('\s+set mappedip (.+\d).*')

	# Flag indicating that we are in a clause containing an address we want
	to_add = 0
	# Flag indicating that this object is an ip range rather then subnet
	vip = ''
	ext_ip = ''
	mapped_ip = ''
	curr_ip = ''

	for line in raw_out_list:
		edit_match = re_edit.match(line)
		extip_match = re_extip.match(line)
		mappedip_match = re_mappedip.match(line)

		if edit_match:
			if edit_match.groups()[0] in ip_list:
				curr_ip = edit_match.groups()[0]
				to_add = 1
			else:
				to_add = 0
		if extip_match and to_add:
			ext_ip = extip_match.groups()[0]
		if mappedip_match and to_add:
			mapped_ip = mappedip_match.groups()[0]

		if ext_ip and mapped_ip and to_add:
			vip = '\033[36m' + ext_ip + '<->' + mapped_ip + '\033[0m'
			vips[curr_ip] = vip
			ext_ip = ''
			mapped_ip = ''
			vip = ''
			to_add = 0
	return vips


def main(ARGV):

	# Flags might be used with commanl line arguments in future
	# With numeric addresses
	with_addr = 1
	# With ports
	with_srv = 1
	# With Address Groups resolution
	with_grp_addr = 1
	# With Service groups resolution
	with_grp_srv = 1
	# With VIPs
	with_vip = 1
	# With VIP Groups resolution 
	with_grp_vip = 1

	port_list = ParseArgs(ARGV)

	ip = ARGV[1]
	ssh = FwConnection(ip)

	if with_grp_addr:
		addr_grp_members = GetAddrGroups(ssh)
	if with_grp_vip:
		vip_grp_members = GetVIPGroups(ssh)
	if with_grp_srv:
		srv_grp_members = GetServiceGroups(ssh)

	for port in port_list:

		port_data = GetSystemInterface(ssh, port)
		if len(port_data) == 0:
			raise SystemExit(10)
		routes = GetRoutes(ssh, port)
		policies = GetPortPolicies(ssh, port)

		if with_grp_addr:
			policies = ResolveAddrGroups(policies, addr_grp_members)
		if with_grp_vip:
			policies = ResolveAddrGroups(policies, vip_grp_members)
		if with_grp_srv:
			policies = ResolveSrvGroups(policies, srv_grp_members)

		if with_addr:
			ips = GetIPsFromPolicies(ssh, policies)

		if with_vip:
			vips = GetVIPsFromPolicies(ssh, policies)
			ips.update(vips)

		if with_srv:
			srvs = GetSRVsFromPolicies(ssh, policies)

		ip_pools = GetIpPools(ssh)
	
		caption = 'Data collected for ' + port
		print '\n' + '\033[1;36m' + GetUnderline(caption, '~')
		print caption
		print GetUnderline(caption, '~') + '\033[0m'
	
		port_status = 'Port status'
		print '\n' + '\033[1;36m' + port_status
		print GetUnderline(port_status, '=') + '\033[0m'
		status_color = ''
	
		if port_data['status'] == 'up':
			status_color = '\033[1m\033[42m'
		else:
			status_color = '\033[1m\033[41m'
		print 'Status: ' + status_color + port_data['status'] + '\033[0m' + '\t' + port_data['ip'] + '/' + port_data['mask']
	
		routes_info = 'Routes'
		print '\n' + '\033[1;36m' + routes_info
		print GetUnderline(routes_info, '=') + '\033[0m'
		rt = prettytable.PrettyTable(['\033[1mType\033[0m', '\033[1mDestination\033[0m', '\033[1mGateway\033[0m'])
		rt.hrules = prettytable.FRAME
		rt.vrules = prettytable.NONE
		rt.align['\033[1mDestination\033[0m'] = 'l'
		rt.align['\033[1mGateway\033[0m'] = 'l'
		for route in routes:
			rt.add_row([route['type'], route['dst'], route['gw']])
		print rt
	
		policies_info = 'Policies'
		print '\n' + '\033[1;36m' + policies_info
		print GetUnderline(policies_info, '=') + '\033[0m'
		pt = prettytable.PrettyTable(['\033[1mNumber\033[0m', 
									  '\033[1mDirection\033[0m', 
									  '\033[1msrcintf\033[0m', 
									  '\033[1msrcaddr\033[0m', 
									  '\033[1mdstintf\033[0m', 
									  '\033[1mdstaddr\033[0m', 
									  '\033[1mservice\033[0m', 
									  '\033[1maction\033[0m',
									  '\033[1mNAT\033[0m'])
		pt.align['\033[1msrcaddr\033[0m'] = 'l'
		pt.align['\033[1mdstaddr\033[0m'] = 'l'
		pt.align['\033[1mservice\033[0m'] = 'l'
		pt.hrules = prettytable.ALL
		pt.vrules = prettytable.NONE
	
	
		for policy in policies:
			number = str(policy['number'])
	
			if policy['direction'] == "from":
				direction = '\033[1;33m<--out--\033[0m'
			elif policy['direction'] == "to":
				direction = '\033[1;31m---in-->\033[0m'
			else:
				direction = 'n/a'
	
			srcintf = ''
			dstintf = ''
			srcaddr = ''
			dstaddr = ''
			service = ''
	
			for i in policy['srcintf']:
				srcintf += i + '\n'
			srcintf = srcintf[:-1] 
			for i in policy['dstintf']:
				dstintf += i + '\n'
			dstintf = dstintf[:-1]

			if with_addr:
				for i in policy['srcaddr']:
					try:
						srcaddr += i + '\n' + ips[i] + '\n'
					except KeyError:
						srcaddr += i + '\n'
				srcaddr = srcaddr[:-1]
				for i in policy['dstaddr']:
					try:
						dstaddr += i + '\n' + ips[i] + '\n'
					except KeyError:
						dstaddr += i + '\n'
				dstaddr =dstaddr[:-1]
			else:
				for i in policy['srcaddr']:
					srcaddr += i + '\n'
				srcaddr = srcaddr[:-1]
				for i in policy['dstaddr']:
					dstaddr += i + '\n'
				dstaddr =dstaddr[:-1]

			if with_srv:
				for i in policy['service']:
					try:
						service += i + '\n\033[33m' + srvs[i] + '\033[0m\n'
					except KeyError:
						service += i + '\n'
			service = service[:-1]
	
			action = policy['action']

			nat_info = ''

			if policy['nat']:
				if 'natpool' in policy:
					nat_pool = policy['natpool']
					nat_info = 'NAT: ' + nat_pool + '\n\033[032m' + ip_pools[nat_pool]['start'] + '-' + ip_pools[nat_pool]['end'] + '\033[0m'
				else:
					nat_info = 'NAT to port addr'

	
			pt.add_row([number, 
						direction, 
						srcintf, 
						srcaddr, 
						dstintf, 
						dstaddr, 
						service, 
						action,
						nat_info])
	
		print pt

		print '\n<END OF ' + port + ' DATA>\n'

	ssh.logout()

if __name__ == '__main__':
    main(ARGV)
