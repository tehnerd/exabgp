# encoding: utf-8
"""
operational/__init__.py

Created by Thomas Mangin on 2013-09-01.
Copyright (c) 2009-2013 Exa Networks. All rights reserved.
"""

from struct import pack,unpack

from exabgp.protocol.family import AFI,SAFI
from exabgp.bgp.message.open.routerid import RouterID
from exabgp.bgp.message import Message

# =================================================================== Operational

MAX_ADVISORY = 2048  # 2K

class Type (int):
	def pack (self):
		return pack('!H',self)

	def extract (self):
		return [pack('!H',self)]

	def __len__ (self):
		return 2

	def __str__ (self):
		pass

class OperationalType:
	# ADVISE
	ADM  = 0x01  # 01: Advisory Demand Message
	ASM  = 0x02  # 02: Advisory Static Message
	# STATE
	RPCQ = 0x03  # 03: Reachable Prefix Count Request
	RPCP = 0x04  # 04: Reachable Prefix Count Reply
	APCQ = 0x05  # 05: Adj-Rib-Out Prefix Count Request
	APCP = 0x06  # 06: Adj-Rib-Out Prefix Count Reply
	LPCQ = 0x07  # 07: BGP Loc-Rib Prefix Count Request
	LPCP = 0x08  # 08: BGP Loc-Rib Prefix Count Reply
	SSQ  = 0x09  # 09: Simple State Request
	# DUMP
	DUP  = 0x0A  # 10: Dropped Update Prefixes
	MUP  = 0x0B  # 11: Malformed Update Prefixes
	MUD  = 0x0C  # 12: Malformed Update Dump
	SSP  = 0x0D  # 13: Simple State Response
	# CONTROL
	MP   = 0xFFFE  # 65534: Max Permitted
	NS   = 0xFFFF  # 65535: Not Satisfied

class Operational (Message):
	TYPE = chr(0x06)  # next free Message Type, as IANA did not assign one yet.
	has_family = False
	is_fault = False

	__sequence_number = {}
	__router_index = {}

	def __init__ (self,what,sequence=None,data=None):
		Message.__init__(self)
		self.what = Type(what)
		self.sequence = sequence
		self.data = data
		self.routerid = None

	def __sequence (self,routerid):
		if self.sequence:
			return pack ('!L',self.sequence)

		packed = routerid.pack()
		idx = self.__router_index[packed] if packed in self.__router_index else len(self.__router_index)
		seq = self.sequence if self.sequence else (self.__sequence_number.get(packed,0) + 1) % 0xFFFF
		self.__sequence_number[packed] = seq
		return pack('!H',idx) + pack('!H',seq)

	def _message (self,routerid,data):
		data = self.data if data is None else "%s%s" % (data,self.data)

		return Message._message(self,"%s%s%s%s" % (
			self.what.pack(),
			pack('!H',len(data)+4),
			self.__sequence(routerid),
			data
		))

	def message (self,negotiated,data=''):
		return self._message(negotiated.sent_open.router_id,data)

	def __str__ (self):
		return self.extensive()

	def extensive (self):
		return 'operational %s' % self.name


class OperationalFamily (Operational):
	has_family = True

	def __init__ (self,what,afi,safi,sequence=None,data=None):
		Operational.__init__(self,what,sequence,data)
		self.afi = AFI(afi)
		self.safi = SAFI(afi)

	def family (self):
		return (self.afi,self.safi)

	def _message (self,routerid,data=''):
		return Operational._message(self,routerid,"%s%s%s" % (
			self.afi.pack(),
			self.safi.pack(),
			data
		))


class NS:
	MALFORMED   = 0x01  # Request TLV Malformed
	UNSUPPORTED = 0x02  # TLV Unsupported for this neighbor
	MAXIMUM     = 0x03  # Max query frequency exceeded
	PROHIBITED  = 0x04  # Administratively prohibited
	BUSY        = 0x05  # Busy
	NOTFOUND    = 0x06  # Not Found

	class _NS (Operational):
		is_fault = True

		def __init__ (self,sequence=None):
			Operational.__init__(
				self,
				OperationalType.NS,
				self.ERROR_SUBCODE,
				sequence
			)

		def extensive (self):
			return 'operational NS %s' % (self.name)


	class Malformed (_NS):
		name = 'NS malformed'
		ERROR_SUBCODE = '\x00\x01'  # pack('!H',MALFORMED)

	class Unsupported (_NS):
		name = 'NS unsupported'
		ERROR_SUBCODE = '\x00\x02'  # pack('!H',UNSUPPORTED)

	class Maximum (_NS):
		name = 'NS maximum'
		ERROR_SUBCODE = '\x00\x03'  # pack('!H',MAXIMUM)

	class Prohibited (_NS):
		name = 'NS prohibited'
		ERROR_SUBCODE = '\x00\x04'  # pack('!H',PROHIBITED)

	class Busy (_NS):
		name = 'NS busy'
		ERROR_SUBCODE = '\x00\x05'  # pack('!H',BUSY)

	class NotFound (_NS):
		name = 'NS notfound'
		ERROR_SUBCODE = '\x00\x06'  # pack('!H',NOTFOUND)


class Advisory:
	class _Advisory (Operational):
		def extensive (self):
			return 'operational %s "%s"' % (self.name,self.data)

		# This is a BIG cheat as everyone speaks IPv4 unicast
		def family (self):
			return (AFI(AFI.ipv4),SAFI(SAFI.unicast))

	class ADM (_Advisory):
		name = 'ADM'

		def __init__ (self,advisory,sequence=None):
			utf8 = advisory.encode('utf-8')
			if len(utf8) > MAX_ADVISORY:
				utf8 = utf8[:MAX_ADVISORY-3] + '...'.encode('utf-8')
			Operational.__init__(
				self,
				OperationalType.ADM,
				sequence,
				utf8
			)

	class ASM (_Advisory):
		name = 'ASM'

		def __init__ (self,advisory,sequence=None):
			utf8 = advisory.encode('utf-8')
			if len(utf8) > MAX_ADVISORY:
				utf8 = utf8[:MAX_ADVISORY-3] + '...'.encode('utf-8')
			Operational.__init__(
				self,
				OperationalType.ASM,
				sequence,
				utf8
			)

# a = Advisory.ADM(1,1,'string 1')
# print a.extensive()
# b = Advisory.ASM(1,1,'string 2')
# print b.extensive()


class Query:
	class _Query (OperationalFamily):
		name = None
		code = None

		def __init__ (self,afi,safi,sequence=None,data=None):
			OperationalFamily.__init__(
				self,
				self.code,
				afi,safi,
				sequence,
				data
			)

		def extensive (self):
			if self.sequence:
				return 'operational %s afi %s safi %s sequence %d' % (
					self.name,
					self.afi,self.safi,
					self.sequence
				)
			return 'operational %s afi %s safi %s' % (self.name,self.afi,self.safi)

	class RPCQ (_Query):
		name = 'RPCQ'
		code = OperationalType.RPCQ

	class APCQ (_Query):
		name = 'APCQ'
		code = OperationalType.APCQ

	class LPCQ (_Query):
		name = 'LPCQ'
		code = OperationalType.LPCQ

class Response:
	class _Counter (OperationalFamily):
		def __init__ (self,afi,safi,sequence,counter):
			self.counter = counter
			OperationalFamily.__init__(
				self,
				self.code,
				afi,safi,
				sequence,
				pack('!L',counter)
			)

		def extensive (self):
			if self.sequence:
				return 'operational %s afi %s safi %s sequence %d counter %d' % (
					self.name,
					self.afi,self.safi,
					self.sequence,
					self.counter
				)
			return 'operational %s afi %s safi %s counter %d' % (self.name,self.afi,self.safi,self.counter)

	class RPCP (_Counter):
		name = 'RPCP'
		code = OperationalType.RPCP

	class APCP (_Counter):
		name = 'RPCP'
		code = OperationalType.APCP

	class LPCP (_Counter):
		name = 'RPCP'
		code = OperationalType.LPCP

# c = State.RPCQ(1,1,'82.219.0.1',10)
# print c.extensive()
# d = State.RPCP(1,1,'82.219.0.1',10,10000)
# print d.extensive()

class Dump:
	pass

OperationalGroup = {
	OperationalType.ADM: ('advisory', Advisory.ADM),
	OperationalType.ASM: ('advisory', Advisory.ASM),

	OperationalType.RPCQ: ('query', Query.RPCQ),
	OperationalType.RPCP: ('counter', Response.RPCP),

	OperationalType.APCQ: ('query', Query.APCQ),
	OperationalType.APCP: ('counter', Response.APCP),

	OperationalType.LPCQ: ('query', Query.LPCQ),
	OperationalType.LPCP: ('counter', Response.LPCP),
}

def OperationalFactory (data):
	what = Type(unpack('!H',data[0:2])[0])
	length = unpack('!H',data[2:4])[0]
	sequence = unpack('!L',data[4:8])[0]

	decode,klass = OperationalGroup.get(what,('unknown',None))

	if decode == 'advisory':
		data = data[8:length+4]
		return klass(data)
	elif decode == 'query':
		afi = unpack('!H',data[8:10])[0]
		safi = ord(data[10])
		return klass(afi,safi,sequence)
	elif decode == 'counter':
		afi = unpack('!H',data[8:10])[0]
		safi = ord(data[10])
		counter = unpack('!L',data[11:15])[0]
		return klass(afi,safi,counter,sequence)
	else:
		print 'ignoring ATM this kind of message'
