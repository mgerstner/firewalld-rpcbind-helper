#!/usr/bin/python3 -s
# vim: noet ts=8 sw=8 sts=8 :

# Author:
#
# Matthias Gerstner (matthias.gerstner@suse.de)
# Copyright (C) 2018 SUSE Linux GmbH
#
# A helper program to configure static ports for rpcbind based protocols
# like NFSv3 and ypbind/ypserv and to make them available in firewalld.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301 USA.

from __future__ import print_function
import os, sys
import argparse
import subprocess
import random
import textwrap
import errno

def error(*args, **kwargs):
	kwargs["file"] = sys.stderr
	print(*args, **kwargs)

class FirewallRPC(object):

	# the names of relevant port configuration lines.

	# this contains formatting templates for sysconfig variables that
	# require special syntax. If a variable is not present here then just
	# {port} is assumed as syntax.
	cfg_syntax = {
		"YPBIND_OPTIONS": "-p {port}",
		"YPPASSWDD_ARGS": "--port {port}",
		"YPSERV_ARGS": "-p {port}",
		"YPXFRD_ARGS": "-p {port}",
	}

	# this maps sysconfig variables to rpcbind service names (helps for
	# detecting default ports)
	cfg_service_names = {
		"LOCKD_TCPPORT": "nlockmgr",
		"LOCKD_UDPPORT": "nlockmgr",
		"MOUNTD_PORT": "mountd",
		"RQUOTAD_PORT": "rquotad",
		"STATD_PORT": "status",
		"YPBIND_OPTIONS": "ypbind",
		"YPPASSWDD_ARGS": "yppasswd",
		"YPSERV_ARGS": "ypserv",
		"YPXFRD_ARGS": "fypxfrd",
	}

	class NoArgValue(object):
		pass

	class Pattern(object):
		"""Small class that represents a service pattern like
		nfs-server. It keeps all knowledge about the involved
		variables, names and files."""

		def __init__(self, label, sysconfig_file, config_vars,
				static_ports = []):

			self.m_label = label
			self.m_sysconfig_file = "/etc/sysconfig/{}".format(
				sysconfig_file
			)
			self.m_config_vars = config_vars
			self.m_rpcbind_services = set()
			self.m_static_ports = static_ports

			cfg_service_names = FirewallRPC.cfg_service_names

			for config in self.m_config_vars:
				self.m_rpcbind_services.add(
					cfg_service_names[config]
				)
			self.m_rpcbind_services = list(self.m_rpcbind_services)

		def isInstalled(self):
			return os.path.exists(self.m_sysconfig_file)

	def __init__(self):

		self.m_used_ports = set()
		self.setupPatterns()

		self.m_parser = argparse.ArgumentParser(
			formatter_class = argparse.RawTextHelpFormatter,
			description = """This program helps with the
				configuration of static ports for dynamic
				rpcbind services like for NFSv3 or
				ypbind/ypserv on SUSE Linux.""",
			epilog = """
Usage examples:

Get easily parsable dynamic port assignment information for the mountd and
nlockmgr rpcbind services:

root # firewall_rpc.py -s mountd nlockmgr

Get easy parsable dynamic port assignment information for the rpcbind
services necessary for the nfs server pattern:

root # firewall_rpc.py -r -p nfs-server

Start interactive configuration of static ports for the rpcbind services
necessary for the nfs server pattern:

root # firewall_rpc.py --static-config -p nfs-server

Perform non-interactive configuration of static ports for the rpcbind services
necessary for the nfs server pattern:

root # firewall_rpc.py --static-config -p nfs-server --non-interactive --port-config \\
	"mountd=20100 status=20200 nlockmgr=20300 rquotad=20400"

Show information and current static port assignment for the rpcbind services
necessary for the nfs server pattern:

root # firewall_rpc.py -l -p nfs-server

Create a new firewalld service 'nfs-server-static' for the currently assigned
static ports necessary for the nfs-server pattern:

root # firewall_rpc.py -p nfs-server --create-firewalld-service nfs-server-static

"""
		)

		self.m_parser.add_argument(
			"-p", "--pattern",
			help = self.getWrapped("""Specifies a pattern to act
upon. Used with various operations as documented."""),
			metavar = ' '.join(self.getSupportedPatterns()),
			choices = self.getSupportedPatterns(),
			default = None
		)

		self.m_parser.add_argument(
			"--static-config",
			help = self.getWrapped("""This will allow you to
configure static ports for a pattern of related
rpcbind services. This causes the ports for these
services to stay the same across restarts. The ports
will be interactively queried on the terminal, if
--non-interactive is not specified. Specify a pattern
via -p."""),
			action = 'store_true'
		)

		self.m_parser.add_argument(
			"-s", "--print-services",
			help = self.getWrapped("""Print the currently assigned
ports belonging to the given rpcbind services. The
output will be a space separated list of tuples of the
form <PORT>/<PROTO>, where <PROTO> is one of tcp or
udp.  This format is compatible with firewall-cmd
syntax.  Example input: "-s ypbind rquotad"."""),
			nargs = '+',
			metavar = "SERVICE"
		)

		self.m_parser.add_argument(
			"-r", "--print-pattern",
			help = self.getWrapped("""Like --print-services but
print the ports belonging to the service pattern
specified via -p."""),
			action = 'store_true'
		)

		self.m_parser.add_argument(
			"-l", "--list-patterns",
			help = self.getWrapped("""Print information about
available service patterns. May be limited to a
specific pattern via -p."""),
			action = 'store_true'
		)

		self.m_parser.add_argument(
			"--port-config",
			help = self.getWrapped("""A space separated list of
port definitions to be used as defaults during
--static-config. Each element of the list is of the
format "<rpcservice>=<port>". You can find valid
rpcservice names via --list-patterns. Example value:
"mountd=4711 status=815"."""),
			metavar = "PORTLIST"
		)

		self.m_parser.add_argument(
			"--non-interactive",
			help = self.getWrapped("""Instead of interactively
querying ports during --static-config, use the values
provided via --port-config or otherwise automatically
determined port values.  No user interaction will be
required.  Use with care."""),
			action = 'store_true'
		)

		self.m_parser.add_argument(
			"--create-firewalld-service",
			help = self.getWrapped("""Create a new firewalld
service based on the static port configuration of the
service pattern selected via -p. This only works if
all related services have currently static ports
configured. If an argument is specified then this will
be used to name the new firewalld service. Otherwise
the name is derived from the pattern selected via
-p."""),
			metavar = "service-name",
			const = self.NoArgValue,
			nargs = '?'
		)

		self.m_parser.add_argument(
			"-v", "--verbose",
			help = self.getWrapped("""Add additional output where
applicable (currently only firewall-cmd calls)."""),
			action = 'store_true'
		)

	def checkPatternArg(self, required = True):

		if not self.m_args.pattern:
			if required:
				error("Missing pattern argument (-p)")
				sys.exit(1)
			self.m_pattern = None
			return

		self.m_pattern = self.getPatternInfo(self.m_args.pattern)

	def setupPatterns(self):

		# a list of all supported patterns
		self.m_patterns = [
			self.Pattern("nfs-server", "nfs",
				config_vars = [
					"MOUNTD_PORT", "STATD_PORT",
					"LOCKD_TCPPORT",
					"LOCKD_UDPPORT", "RQUOTAD_PORT"
				],
				static_ports = [ "2049/tcp", "2049/udp" ]
			),
			self.Pattern("nfs-client", "nfs",
				config_vars = [
					"STATD_PORT", "LOCKD_TCPPORT",
					"LOCKD_UDPPORT"
				],
				static_ports = [ "2049/tcp", "2049/udp" ]
			),
			self.Pattern("yp-server", "ypserv",
				config_vars = [
					"YPXFRD_ARGS", "YPPASSWDD_ARGS",
					"YPSERV_ARGS"
				]
			),
			self.Pattern("yp-client", "ypbind",
				config_vars = [
					"YPBIND_OPTIONS"
				]
			)
		]

		# transform into a dictionary for easy access to individual
		# patterns by name
		self.m_patterns = dict([
			(pattern.m_label, pattern) for pattern in self.m_patterns
		])

	def run(self):
		"""The main entry point of the tool."""

		self.m_args = self.m_parser.parse_args()
		# always determine the currently assigned rpc ports
		self.m_rpc_services = self.getRPCServices()

		self.parsePortConfig()

		self.m_verbose = self.m_args.verbose

		if self.m_args.static_config:
			self.checkPatternArg()
			self.configureStatic()
		elif self.m_args.create_firewalld_service:
			self.checkPatternArg()
			name = self.m_args.create_firewalld_service
			if name == self.NoArgValue:
				name = self.m_pattern.m_label
			self.createFirewallDService(name)
		elif self.m_args.print_services:
			self.printServices(self.m_args.print_services)
		elif self.m_args.print_pattern:
			self.checkPatternArg()
			self.printPatternServices()
		elif self.m_args.list_patterns:
			self.checkPatternArg(required = False)
			if self.m_pattern:
				self.listPattern(self.m_pattern)
			else:
				self.listPatterns()
		else:
			error("No command specified.")
			sys.exit(2)

	def parsePortConfig(self):
		"""Evaluates the port config command line argument and adds
		according defaults to the program state which will be used
		during static configuration."""

		# maps rpc service names to configured ports
		self.m_port_config = dict()

		if not self.m_args.port_config:
			return

		for config in self.m_args.port_config.split():
			self.parsePortConfigItem(config)

	def parsePortConfigItem(self, config):
		"""Parses a single port configuration item of the form
		rpcservice=port and stores it in m_port_config. On error
		conditions the program will be exited."""
		parts = config.split('=')
		if len(parts) != 2:
			error("Invalid port configuration encountered: '{}'. "\
				"Expected '{}'.".format(
					config,
					"<rpcservice>=<port>"
			))
			sys.exit(1)

		rpcservice, port = parts

		if rpcservice not in self.cfg_service_names.values():
			error("Unknown rpc service encountered in port "\
				"configuration: '{}'".format(rpcservice))
			sys.exit(1)

		port = self.validatePortString(port)
		if not port:
			error("Bad port encountered in port "\
				"configuration: '{}'".format(config))
			sys.exit(1)

		self.m_port_config[rpcservice] = port

	def getSupportedPatterns(self):
		"""Returns a sorted list of valid pattern names."""
		return sorted(self.m_patterns.keys())

	def getPatternInfo(self, the_pattern):
		"""Returns the Pattern object for the given label, aborts the
		program if no such pattern exists."""

		pattern = self.m_patterns.get(the_pattern, None)
		if not pattern:
			error("Unknown pattern '{}'".format(the_pattern))
			error("Supported patterns:",
				' '.join(self.getSupportedPatterns()))
			sys.exit(1)

		return pattern

	def printPatternServices(self):
		"""Prints all the services belonging to the given pattern
		name."""
		return self.printServices(self.m_pattern.m_rpcbind_services)

	def getRPCInfoOutput(self):
		"""Returns the raw output of 'rpcinfo -p'. Since no portmapper
		might be running this can also be None."""

		rpcinfo = "/sbin/rpcinfo"

		if not os.path.isfile(rpcinfo):
			error("No rpcinfo program found in {}.".format(rpcinfo))
			sys.exit(1)

		env = os.environ.copy()
		# avoid translations or special encodings
		env["LC_ALL"] = "C"

		proc = subprocess.Popen(
			[ rpcinfo, "-p" ],
			shell = False,
			close_fds = True,
			env = env,
			stdout = subprocess.PIPE,
			stderr = subprocess.STDOUT
		)

		output = proc.stdout.read().decode()

		res = proc.wait()

		if res != 0:
			# if portmapper is not running at all we have to be
			# robust
			if output.find("can't contact portmapper") != -1:
				return None

			print(output)

			raise Exception("Failed to run {}".format(rpcinfo))

		return output

	def getRPCServices(self):
		"""Returns a dictionary describing all currently assigned
		rpcbind ports.

		returns a dictionary like {
			"portmap": {
				"tcp": set(),
				"udp": set()
			}
		}
		"""

		output = self.getRPCInfoOutput()

		ports = dict()

		if output is None:
			return ports

		skipped_header = False

		for line in output.splitlines():

			if not skipped_header:
				skipped_header = True
				continue

			prog, version, proto, port, service = line.split()

			service = ports.setdefault(service, dict())
			proto = service.setdefault(proto, set())
			proto.add(int(port))

		return ports

	def printServices(self, services):
		"""Prints the ports assigned to the given rpc service
		names."""

		specs = []

		for service, protos in self.m_rpc_services.items():

			if service not in services:
				continue

			for proto, portset in protos.items():
				for port in portset:
					specs.append((proto, port))

		# filter out duplicates (can happen e.g. with nfs and nfs_acl)
		specs = list(set(specs))
		# sort by port number
		specs = sorted(specs, key = lambda s: s[1])
		tuples = [ '{}/{}'.format(port, proto) for proto, port in specs ]

		print(' '.join(tuples))

	def listPatterns(self):
		"""Print a human readable list of the available service
		patterns and related configuration information."""

		for key, pattern in sorted(self.m_patterns.items()):
			self.listPattern(pattern)
			print()

	def listPattern(self, pattern):

		self.getStaticPortConfig(pattern)

		print(pattern.m_label)
		print('-' * len(pattern.m_label))
		print()
		print("Static port configuration file:",
				pattern.m_sysconfig_file, end = '')
		if not pattern.isInstalled():
			print(" (package not installed)", end = '')
		print()
		print()

		table_rows = []

		heading_row = [
			"Configuration Variable", "Port Syntax",
			"rpcbind Service", "Static Port"
		]
		num_cols = len(heading_row)
		table_rows.append(heading_row)

		for var in pattern.m_config_vars:
			sport = self.m_static_ports.get(var)
			sport = str(sport) if sport else "unconfigured"
			row = [
				var,
				self.getPortSyntax(var),
				self.cfg_service_names[var],
				sport
			]
			table_rows.append(row)

		column_widths = []

		for column in range(len(heading_row)):
			widths = [ len(row[column]) for row in table_rows ]
			column_widths.append(max(widths))

		# heading row
		print("| ", end = '')
		for i, col in enumerate(heading_row):
			width = column_widths[i] + 1
			print(col.center(width), ' | ', sep = '', end = '')
		line_length = sum(column_widths) + (num_cols * 3) + 3
		print()
		print('|', '-' * line_length, '|', sep = '')

		# data rows
		for row in table_rows[1:]:
			print("| ", end = '')
			for i, col in enumerate(row):
				width = column_widths[i] + 1

				print(col.ljust(width), '| ', end = '')
			print()

	def configureStatic(self):
		"""Perform static port configuration for the given pattern
		name."""
		cfg = self.m_pattern.m_sysconfig_file
		lines = []

		print("Performing configuration of static ports for "
			"{} pattern".format(self.m_pattern.m_label))

		print()
		if not self.m_args.non_interactive:
			warning = self.getWrapped(
				"WARNING: This process may overwrite custom "\
				"configuration of service command line "\
				"switches in {}".format(cfg))
			print(warning)
			print()

		print("Reading current configuration from {}.".format(cfg))
		print()
		try:
			with open(cfg, 'r') as cfg_fd:
				for line in cfg_fd.readlines():
					line = self.processCfgLine(
						line,
						item_handler =
							self.processCfgItemForChange
					)
					lines.append(line)
		except OSError as e:
			if e.errno == errno.ENOENT:
				print("Error: The package necessary for this pattern does not seem to be installed")
				sys.exit(1)
			else:
				raise

		print("Writing updated configuration to {}.".format(cfg))
		with open(cfg, 'w') as cfg_fd:
			cfg_fd.write(''.join(lines))
		print()
		print("You will need to restart affected services for the "\
			"changes to take effect.")

	def isPortUsed(self, port):
		"""Returns whether the given port was already used for some
		service during the current configuration process. This is only
		for the random port selection at the moment, because otherwise
		it becomes to complex (for example LOCKD_TCPPORT and
		LOCKD_UDPPORT, differentation between protocols would be
		necessary)."""

		if port in self.m_used_ports:
			return True

		for service, prots in self.m_rpc_services.items():
			if port in prots:
				return True

		return False

	def getPortSyntax(self, config_var):
		 return self.cfg_syntax.get(config_var, "{port}")

	def getPortSuggestion(self, config_var, old_port):
		"""Returns a port suggestion for the given rpcbind service.
		The port suggestion is determined the following way:

		- if the port is configured on the command line, use that one
		- if a static port is already configured (old_port), use that
		  one
		- if the rpcbind service is running, use the currently
		  assigned port
		- otherwise choose a random port from the private port range
		"""

		# First see whether the service is currently running and
		# rpcbind has assigned a port to it. Using this one might be a
		# good suggestion.
		rpc_service = self.cfg_service_names.get(config_var, None)
		configured = self.m_port_config.get(rpc_service, None)
		current = self.m_rpc_services.get(rpc_service, None)

		if configured:
			# explicitly configured port found on command line
			return configured

		if old_port:
			return old_port

		if current:
			if "TCP" in config_var and "tcp" in current:
				proto = current["tcp"]
			elif "UDP" in config_var and "udp" in current:
				proto = current["udp"]
			else:
				# any protocol must do
				proto = list(current.values())[0]

			for port in proto:
				# return the first port (usually only one)
				return port

		while True:
			# choose a random port from the private/dynamic port
			# range
			randport = random.randint(49152, 65535)
			if self.isPortUsed(randport):
				continue
			return randport

	def processCfgLine(self, line, item_handler):
		"""Processes a single line from a sysconfig file. The
		item_handler is called for each identifier "key=value" pair
		and is passed a key and value variable, respectively. The
		item_handler is responsible to transform or parse the
		key=value pair. It should return a replacement line, if
		applicable.

		The function returns the line that should be written out to
		the new configuration file in the end.
		"""

		stripped = line.strip()

		if not stripped:
			# empty line
			return line
		elif stripped.startswith('#'):
			# comment
			return line

		parts = stripped.split('=')
		if len(parts) != 2:
			# no key/value pair
			return line

		key, val = parts

		new_line = item_handler(key, val)

		return new_line if new_line != None else line

	def processCfgItemForChange(self, key, val):
		"""This item_handler for processCfgLine queries new port
		values if key is a known configuration item for the currently
		active pattern."""

		if key not in self.m_pattern.m_config_vars:
			# unknown key
			return None

		# try to suggest an already configured port
		port = self.scanPort(val)
		port = self.getPortSuggestion(key, port)

		if self.m_args.non_interactive:
			print("Using port", port, "for", key)
		else:
			port = self.queryPort(key, port)
		self.m_used_ports.add(port)

		# use a special template for the variable value, if necessary
		template = self.getPortSyntax(key)

		return '{}="{}"\n'.format(key, template.format(port = port))

	def scanPort(self, value):
		"""Converts the given port string value (from the config file)
		into an integer. If this is not possible, returns None."""

		value = value.strip('"')

		# we need to support things like "-l 4711"
		for part in value.split():
			if part.isdigit():
				return int(part)

	def queryPort(self, key, port):
		"""interactively queries a new value for the given
		configuration key, offering the given port as a default.

		returns the chosen port.
		"""

		query = "Please enter the port number for {} or press "\
			"ENTER for accepting the suggested port in [].".format(
				key
			)
		query = self.getWrapped(query)
		print(query)
		print()

		rpc_service = self.cfg_service_names[key]

		while True:
			print("{} ({}) [{}] > ".format(key, rpc_service, port), end = '')
			sys.stdout.flush()
			reply = sys.stdin.readline()
			print()
			if not reply:
				raise EOFError()
			elif reply.strip() == "":
				if self.validatePortString(port):
					break
				continue

			reply = self.validatePortString(reply)

			if reply:
				port = reply
				break
			else:
				continue

		return port

	def validatePortString(self, port):
		"""This fucntion validates the string port specification and
		returns the correctly converted integer, if possible.
		Otherwise None."""
		try:
			port = int(port)
		except ValueError:
			print("Invalid port number '{}' encountered".format(
				port
			))
			print()
			return None

		if port not in range(1, 2 ** 16):
			print("Port number '{}' is out of range".format(port))
			return None

		return port

	def getWrapped(self, text):
		"""Returns a wrapped version of the input text."""
		return '\n'.join(textwrap.wrap(text))

	def getStaticPortConfig(self, pattern):
		"""Returns the static port definitions for the given pattern.
		Returns is a dictionary like {
			"<cfgentry>": <port>
		}.

		These definitions are parsed from the associated sysconfig
		file. If no static ports are configured then none are
		returned.
		"""
		import functools

		if not isinstance(pattern, self.Pattern):
			pattern = self.getPatternInfo(pattern)

		self.m_pattern = pattern

		self.m_static_ports = {}
		cfg = pattern.m_sysconfig_file

		try:
			with open(cfg, 'r') as cfg_fd:
				for line in cfg_fd.readlines():
					self.processCfgLine(
						line,
						self.processCfgItemForParsing
					)
		except OSError as e:
			if e.errno == errno.ENOENT:
				# probably not installed
				pass

	def processCfgItemForParsing(self, key, val):

		if key not in self.m_pattern.m_config_vars:
			# unknown key
			return

		port = self.scanPort(val)

		if port:
			self.m_static_ports[key] = port

	def callFirewallCmd(self, args, permanent = True, discard = True):

		env = os.environ.copy()
		# avoid translations or special encodings
		env["LC_ALL"] = "C"

		if not isinstance(args, list):
			args = [args]

		cmdline = ["/usr/bin/firewall-cmd"]
		if permanent:
			cmdline.append("--permanent")
		cmdline += args

		if self.m_verbose:
			print(">", ' '.join(cmdline))

		with open("/dev/null", 'w') as null:

			return subprocess.call(
				cmdline,
				shell = False,
				close_fds = True,
				env = env,
				stdout = null if discard else None,
				stderr = null if discard else None
			)

	def checkCallFirewallCmd(self, args, permanent = True):

		res = self.callFirewallCmd(args, permanent)

		if res != 0:
			error("Failed to call firewall-cmd",  ' '.join(args))
			sys.exit(3)

	def checkStaticPortsConfigured(self, pattern):

		self.getStaticPortConfig(pattern)

		missing = []

		for cvar in pattern.m_config_vars:
			if cvar not in self.m_static_ports:
				missing.append(cvar)

		if not missing:
			return

		error("Error: not all services belonging the the {} "\
			"pattern have been assigned static ports.\n\n"\
			"Missing configuration items:\n".format(
				pattern.m_label
			)
		)

		for missed in missing:
			error("-", missed)
			sys.exit(1)


	def createFirewallDService(self, name):

		self.checkStaticPortsConfigured(self.m_pattern)

		if self.callFirewallCmd("--state", permanent = False) != 0:
			error("firewalld is not running or firewall-cmd "
				"was not found")
			sys.exit(1)

		if self.callFirewallCmd(["--info-service", name]) == 0:
			error("A firewalld service named '{}' "
				"is already existing".format(name))
			sys.exit(1)

		# create a new empty service under the given name
		self.checkCallFirewallCmd(["--new-service", name])

		port_args = []

		for port in self.m_static_ports.values():
			# for now assume we always need tcp and udp ports
			port_args.append("--add-port")
			port_args.append("{}/udp".format(port))
			port_args.append("--add-port")
			port_args.append("{}/tcp".format(port))

		for port in self.m_pattern.m_static_ports:
			port_args.append("--add-port")
			port_args.append(port)

		self.checkCallFirewallCmd(["--service", name] + port_args)

		print("Successfully created new firewalld service '{}':".format(
			name
		))

		self.callFirewallCmd(["--info-service", name], discard = False)

try:
	# make sure we use a sane umask. as long as we don't process sensitive
	# files, the group/world read permissions on new files are okay.
	os.umask(0o022)
	firewall_rpc = FirewallRPC()
	firewall_rpc.run()
except Exception as e:
	error("Exception occured:", e)
	raise
except EOFError:
	error("EOF encountered")
	sys.exit(2)
