#!/usr/bin/python3

"""
	This is a simple dnsclient that supports A, AAAA, MX, SOA, NS and CNAME
	queries written in python.
"""

import asyncio
import socket
from random import randrange

from query import create_dns_query
from reply import parse_dns_reply, get_serial


class SyncResolver:
	def __init__(self):
		self.server = [('127.0.0.53', 53)]
	
	def resolve(self, name, type_):
		serial = randrange(2**16)
		query = create_dns_query(name, type_, serial)
		self.sock.sendto(query, self.server[0])
		reply, l = self.sock.recvfrom(1024)
		result = parse_dns_reply(reply)
		if result.header.x_id != serial:
			raise ValueError
		
		for answer in result.answer:
			if answer.name == name and answer.x_type == type_:
				return answer.rdata
		else:
			raise ValueError
	
	def __enter__(self):
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		return self
	
	def __exit__(self, *args):
		self.sock.close()
		del self.sock


class AsyncResolver:
	def __init__(self):
		self.timeout = 5
		self.server = [('127.0.0.53', 53)]
		self.waiting = {}
	
	def protocol(self):
		return self
	
	def connection_made(self, transport):
		self.transport = transport
	
	def datagram_received(self, reply, addr):
		serial = get_serial(reply)
		
		if serial not in self.waiting:
			print(f"serial {serial} not in waiting")
			return # warning
		
		try:
			self.waiting[serial].set_result(parse_dns_reply(reply))
		except Exception as error:
			self.waiting[serial].set_exception(error)
	
	def error_received(self, exc):
		if exc:
			print(exc) # TODO: warning
	
	def connection_lost(self, exc):
		if exc:
			print(exc) # TODO: warning
	
	async def resolve(self, name, type_):
		serial = randrange(2**16)
		while serial in self.waiting:
			serial = randrange(2**16)
		
		query = create_dns_query(name, type_, serial)
		self.waiting[serial] = self.loop.create_future()
		self.transport.sendto(query, self.server[0])
		
		try:
			result = await asyncio.wait_for(self.waiting[serial], timeout=self.timeout)
		finally:
			del self.waiting[serial]
		
		for answer in result.answer:
			if answer.name == name and answer.x_type == type_:
				return answer.rdata
		else:
			raise ValueError
	
	async def __aenter__(self):
		self.loop = asyncio.get_running_loop()
		await self.loop.create_datagram_endpoint(self.protocol, remote_addr=self.server[0])
		return self
	
	async def __aexit__(self, *args):
		self.transport.close()
		del self.loop


if __name__ == "__main__":
	with SyncResolver() as resolver:
		print(resolver.resolve('www.google.pl', 'AAAA'))
		print(resolver.resolve('hotmail.com', 'MX'))
		print(resolver.resolve('wp.pl', 'A'))
	
	async def main():
		async with AsyncResolver() as resolver:
			google = resolver.resolve('www.google.pl', 'AAAA')
			hotmail = resolver.resolve('hotmail.com', 'MX')
			wp = resolver.resolve('wp.pl', 'A')
			print(await asyncio.gather(google, hotmail, wp))
	
	asyncio.run(main())










