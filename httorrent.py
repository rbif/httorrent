#!/usr/bin/python3
import urllib
import os
import bencodepy
import socket
import struct
import asyncio
from aiohttp import web
import aiohttp

# /announce?info_hash=%BF%DBFvk%D0%E3%22%5C%25%99%E4%3B%23R%B2%F2%92%E3%DB&peer_id=-lt0D20-%7E%19%B6%CA%C9P%14%EDY%1A%97%A9&key=0e1d2537&compact=1&port=6966&uploaded=0&downloaded=0&left=740105370&event=started

# rtorrent headers:
# GET /announce?info_hash=%BF%DBFvk%D0%E3%22%5C%25%99%E4%3B%23R%B2%F2%92%E3%DB&peer_id=-lt0D20-%7E%19%B6%CA%C9P%14%EDY%1A%97%A9&key=0e1d2537&compact=1&port=6966&uploaded=0&downloaded=0&left=740105370&event=started HTTP/1.1
# User-Agent: rtorrent/0.9.2/0.13.2
# Host: tracker.aletorrenty.pl:2710
# Accept: */*
# Accept-Encoding: deflate, gzip

class TorrentException(Exception):
    pass

class TorrentWantData(Exception):
    pass

class TorrentHandshook(Exception):
    pass

def unpack(fmt, message):
    return struct.unpack_from(fmt, message) + ( message[struct.calcsize(fmt):], )

def decode_peers(peers):
    _peers = []
 
    if len(peers) % 6:
        return

    while peers:
        ip, port, peers = peers[:4], peers[4:6], peers[6:]
        _peers.append({
            'ip': socket.inet_ntoa(ip),
            'port': unpack('>H', port)[0]
        })

    return _peers

def encode_peers(peers):
    encoded = b''

    for peer in peers:
        encoded += socket.inet_aton(peer['ip']) + struct.pack('>H', peer['port'])

    return encoded

def do(func):
    def func_wrapper(self, *args):
        for index, message_type in enumerate(TorrentProtocol.messages):
            if 'do_' + message_type[0] == func.__name__:
                break


        if len(message_type) < 3:
            data = func(self)
        elif len(args) != message_type[2]:
            raise TorrentException('Invalid number of arguments supplied.')
        else:
            data = func(self, *args)

        if not data:
            data = ''

        return struct.pack('>IB', index, len(data) + 1) + data

    return func_wrapper

class TorrentProtocol:
    messages = [
        ('choke', 0), ('unchoke', 0), ('interested', 0), ('uninterested', 0),
        ('have', 4, 1), ('bitfield', '?'), ('request', 12, 3), ('piece', '?', 3),
        ('cancel', 12, 3)
    ]

    def __init__(self, ip, port):
        self.peer_id = os.urandom(20)
        self.ip = ip
        self.port = port
        self.info_hash = b''

        self.remote_choked = False
        self.remote_interested = False
        self.local_choked = False
        self.local_interested = False
        self.got_handshake = False

    def handshake(self):
        return struct.pack('>B19s8s20s20s', 19, 'BitTorrent protocol', '',
            self.info_hash, self.peer_id)

    def decode_handshake(self, message):
        proto_len, proto, _, info_hash, peer_id, message = unpack('B19s8s20s20s', message)
        # print(proto_len == 19, proto, info_hash, peer_id, message)

        if proto_len != 19:
            raise TorrentException('Invalid protocol length in handshake.')

        if proto != b'BitTorrent protocol':
            raise TorrentException('Invalid protocol length in handshake.')

        self.info_hash = info_hash
        #if info_hash != self.info_hash:
        #    raise TorrentException('Info hash does not match in handshake.')

        self.peer_id = peer_id
        self.got_handshake = True
        return message

    def decode_message(self, message):
        if not self.got_handshake:
            return self.decode_handshake(message)

        length, message_id, message = unpack('>IB', message)
        length -= 1

        if len(message) < length:
            raise TorrentWantData()

        if message_id > len(self.messages):
            raise TorrentException('Invalid message id specified.')

        message_type = self.messages[message_id]

        if message_type[1] != '?' and message_type[1] != length:
            raise TorrentException('Invalid message id and length.')

        payload, message = message[:length], message[length:]
        print('[*] Got message type %s.' % message_type[0])
        getattr(self, 'message_' + message_type[0])(payload)
        return message

    def message_choke(self, payload):
        self.remote_choked = True

    def message_unchoke(self, payload):
        self.remote_choked = False

    def message_interested(self, payload):
        self.remote_interested = True

    def message_uninterested(self, payload):
        self.remote_interested = False

    def message_have(self, payload):
        piece = unpack('>I', payload)[0]
        print(piece, self.pieces[piece])

    def message_bitfield(self, payload):
        self.pieces = []

        payload = ''.join(format(ord(x), '08b') for x in payload)

        for piece in payload:
            self.pieces.append({ 'has': piece == '1', 'downloaded': False })

    def message_request(self, payload):
        piece, block_offset, block_length, payload = unpack('>III', payload)

    def message_piece(self, payload):
        piece, block_offset, payload = unpack('>II', payload)

    def message_cancel(self, payload):
        piece, block_offset, block_length, payload = unpack('>III', payload)

    @do
    def do_choke(self):
        self.local_choked = True

    @do
    def do_unchoke(self):
        self.local_choked = False

    @do
    def do_interested(self):
        self.local_interested = True

    @do
    def do_uninterested(self):
        self.local_uninterested = True

    @do
    def do_have(self, piece):
        return struct.pack('>I', piece)

    @do
    def do_bitfield(self):
        pass

    @do
    def do_request(self, piece, block_offset, block_length):
        return struct.pack('>III', piece, block_offset, block_length)

    @do
    def do_piece(self, piece, block_offset, block_data):
        return struct.pack('>II', piece, block_offset) + block_data

    @do
    def do_cancel(self, piece, block_offset, block_length):
        return struct.pack('>III', piece, block_offset, block_length)

class TorrentProxy(asyncio.Protocol):
    def __init__(self, peer):
        self.peer = peer
        self.data = b''
        self.torrent = TorrentProtocol(self.peer['ip'], self.peer['port'])
        super().__init__()

    def connection_made(self, transport):
        print('Connecting to {}'.format(self.peer))
        class TorrentClient(asyncio.Protocol):
            def connection_made(self, transport):
                print('ayy lmao')
                self.transport = transport

            def data_received(self, data):
                pass

        self.transport = transport
        self.client, self.client_transport = loop.create_task(loop.create_connection(
            TorrentClient, self.peer['ip'], self.peer['port']))
    
    def data_received(self, data):
        self.data += data

        try:
            self.client_transport.write(data)
            self.data = self.torrent.decode_message(self.data)
        except TorrentWantData:
            print('[*] Data wanted.')
        except TorrentException as e:
            print('[!] %s' % e)
            self.transport.close()
        except struct.error:
            print('[!] Not enough data received.')
            self.transport.close()

@asyncio.coroutine
def handle(request):
    print('[*] Tracker connection received!')

    uri = request.match_info.get('uri')
    r = yield from aiohttp.get('http://tracker.aletorrenty.pl:2710' + request.path_qs)
    data = yield from r.read()
    yield from r.release()

    torrent = bencodepy.decode(data)
    proxied_peers = []

    for peer in decode_peers(torrent[b'peers']):
        server = yield from loop.create_server(lambda: TorrentProxy(peer),
            '127.0.0.1', 0)

        port = server.sockets[0].getsockname()[1]
        proxied_peers.append({ 'ip': '127.0.0.1', 'port': port })

        print('[*] Opened listener on {}'.format(port))

    torrent[b'peers'] = encode_peers(proxied_peers)

    return web.Response(body=bencodepy.encode(torrent))

@asyncio.coroutine
def init(loop):
    app = web.Application(loop=loop)
    app.router.add_route('GET', '/{uri}', handle)

    srv = yield from loop.create_server(app.make_handler(), '127.0.0.1', 8080)
    print("[*] Server started at http://127.0.0.1:8080")
    return srv

loop = asyncio.get_event_loop()
loop.run_until_complete(init(loop))
loop.run_forever()
