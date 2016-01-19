#!/usr/bin/python3
import os
import bencodepy
import sys
import socket
import struct
import asyncio
from aiohttp import web
import aiohttp
import logging
logging.basicConfig(level=logging.INFO,
    format='%(asctime)-15s %(filename)s:%(funcName)s:%(lineno)s: %(message)s')

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

def ip2int(ip):
    return struct.unpack('>I', socket.inet_aton(ip))[0]

def int2ip(_num):
    return socket.inet_ntoa(struct.pack('>I', _num))

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
        for index, message_type in TorrentProtocol.messages.iteritems():
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
    messages = {
        0: ('choke', 0), 1: ('unchoke', 0), 2: ('interested', 0), 3: ('uninterested', 0),
        4: ('have', 4, 1), 5: ('bitfield', '?'), 6: ('request', 12, 3), 
        7: ('piece', '?', 3), 8: ('cancel', 12, 3), 20: ('extended', '?')
    } 

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

    def decode_handshake(self, message):
        proto_len, proto, _, info_hash, peer_id, message = unpack('B19s8s20s20s', message)
        # print(proto_len == 19, proto, info_hash, peer_id, message)

        if proto_len != 19:
            raise TorrentException('Invalid protocol length in handshake.')

        if proto != b'BitTorrent protocol':
            raise TorrentException('Invalid protocol length in handshake.')

        self.info_hash = info_hash
        self.peer_id = peer_id
        #if info_hash != self.info_hash:
        #    raise TorrentException('Info hash does not match in handshake.')

        logging.info('Handshake completed with peer.')
        self.peer_id = peer_id
        self.got_handshake = True
        return message, ( self.info_hash, self.peer_id )

    def decode_message(self, message):
        if not self.got_handshake:
            message, handshake = self.decode_handshake(message)
            return message, 'handshake', handshake

        length, message_id, message = unpack('>IB', message)
        if not length:
            return message, 'ping', (,)

        length -= 1

        if len(message) < length:
            raise TorrentWantData()

        if message_id not in self.messages:
            raise TorrentException('Invalid message id specified.')

        message_type = self.messages[message_id]

        if message_type[1] != '?' and message_type[1] != length:
            raise TorrentException('Invalid message id and length.')

        payload, message = message[:length], message[length:]
        logging.info('Got message type %s.' % message_type[0])
        ret = getattr(self, 'message_' + message_type[0])(payload)
        return message, message_type[0], ret

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
        logging.debug(piece, self.pieces[piece])
        return piece

    def message_bitfield(self, payload):
        pieces = []

        payload = ''.join(format(x, '08b') for x in payload)

        for piece in payload:
            pieces.append({ 'has': piece == '1', 'downloaded': False })

        return pieces

    def message_request(self, payload):
        piece, block_offset, block_length, payload = unpack('>III', payload)
        return piece, block_offset, block_length

    def message_piece(self, payload):
        piece, block_offset, payload = unpack('>II', payload)
        return piece, block_offset, payload

    def message_cancel(self, payload):
        piece, block_offset, block_length, payload = unpack('>III', payload)
        return piece, block_offset, block_length

    def message_extended(self, payload):
        extension, payload = unpack('>B', payload)
        payload = bencodepy.decode(payload)
        logging.info('Extension {}: {}'.format(extension, payload))
        return extension, payload

    def do_handshake(self, info_hash, peer_id):
        return struct.pack('>B19s8s20s20s', 19, 'BitTorrent protocol', '',
            info_hash, peer_id)

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
        self.local_interested = True

    @do
    def do_have(self, piece):
        return struct.pack('>I', piece)

    @do
    def do_bitfield(self, pieces):
        bitfield = ''
        for piece in pieces:
            bitfield += '1' if piece['has'] else '0'

        if len(bitfield) % 8:
            bitfield += '0' * (8 - len(bitfield) % 8)

        return int(bitfield, 2).to_bytes(len(bitfield) / 8, byteorder='big')

    @do
    def do_request(self, piece, block_offset, block_length):
        return struct.pack('>III', piece, block_offset, block_length)

    @do
    def do_piece(self, piece, block_offset, block_data):
        return struct.pack('>II', piece, block_offset) + block_data

    @do
    def do_cancel(self, piece, block_offset, block_length):
        return struct.pack('>III', piece, block_offset, block_length)

    @do
    def do_extended(self, extension_id, payload):
        return struct.pack('>B', extension_id) + bencodepy.encode(payload)

class TorrentProxy(asyncio.Protocol):
    def __init__(self, peer, callback=None, peer_handler=None, peer_wanted=None):
        self.peer_handler = peer_handler
        self.callback = callback

        # debug hax
        peer['ip'] = '127.0.0.1'

        self.closed = False
        self.peer = peer
        self.waiting = (,)

        self.wanted = {}
        self.peer_wanted = peer_wanted
        self.data = b''
        self.proxy_data = b''

        self.hooks = [ 'request', 'piece', 'cancel', 'extended', 'handshake' ]

        self.torrent = TorrentProtocol(self.peer['ip'], self.peer['port'])
        super().__init__()

    def connection_made(self, transport):
        logging.warning('Connecting to {}'.format(self.peer))
        self.transport = transport

        if not self.callback:
            loop.create_task(loop.create_connection(lambda: TorrentProxy(self.peer,
                self.peer_connnected, self.handle_message, self.peer_wanted),
                 self.peer['ip'], self.peer['port']))
        else:
            self.callback(self.handle_message)

    def peer_connected(self, peer_handler, peer_wanted):
        self.peer_handler = peer_handler
        self.peer_wanted = peer_wanted

        if self.waiting:
            logging.debug('Flushing waiting data!')

            for message_type, ret in self.waiting:
                loop.create_task(self.peer_handler(message_type, ret))

            self.waiting = (,)

    def data_received(self, data):
        if not data:
            logging.warning('Connection closed.')
            return

        self.data += data

        while self.data:
            try:
                self.data, message_type, ret = self.torrent.decode_message(self.data)
            except TorrentWantData:
                logging.debug('Data wanted.')
                break
            except TorrentException as e:
                logging.warning('Error: %s' % e)
                break
            except struct.error:
                logging.debug('Not enough data received.')
                break

            if not self.peer_handler:
                self.waiting.append(message_type, ret)
            else:
                loop.create_task(self.peer_handler(message_type, ret))

    @asyncio.coroutine
    def handle_message(self, message_type, ret):
        if message_type in self.hooks:
            data = yield from getattr(self, 'do_' + message_type)(*ret)
        else:
            data = yield from getattr(self.torrent, 'do_' + message_type)(*ret)

        if not data:
            return

        self.transport.write(data)

    @asyncio.coroutine
    def do_handshake(self, info_hash, peer_id):
        pass

    @asyncio.coroutine
    def do_extended(self, extension_id, payload):
        logging.info('payload: {}'.format(payload))
        return yield from self.torrent.do_extended(extension_id, payload)
        
    @asyncio.coroutine
    def do_request(self, piece, block_offset, block_length):
        r = yield from aiohttp.get('http://127.0.0.1:8080/piece/{}/{}/{}/{}'.format(
            self.torrent.peer_id, piece, block_offset, block_length))
        data = yield from r.read()
        yield from r.release()

        yield from self.peer_handler('piece', (piece, block_offset, data))

    @asyncio.coroutine
    def do_piece(self, *args):
        key = args[:2] + len(args[2])
        if key not in self.wanted:
            return

        self.wanted[key].result(args[2])
        del self.wanted[key]

    @asyncio.coroutine
    def do_cancel(self, args):
        if args not in self.wanted:
            return

        self.wanted[key].exception(TorrentException())
        del self.wanted[key]

    @asyncio.coroutine
    def get_piece(self, piece, block_offset, block_length):
        f = Future()
        self.peer_wanted[piece, block_offset, block_length] = f

        yield from self.peer_handler('request', (piece, block_offset, block_length))
        return yield from f

    def connection_lost(self, exc):
        logging.warning('Server disconnected.')

@asyncio.coroutine
def handle(request):
    logging.warning('Tracker connection received!')

    uri = request.match_info.get('uri')
    r = yield from aiohttp.get(sys.argv[1] + request.path_qs)
    data = yield from r.read()
    yield from r.release()

    torrent = bencodepy.decode(data)
    proxied_peers = []

    base_ip = ip2int('127.13.37.0')
    for index, peer in enumerate(decode_peers(torrent[b'peers'])):
        ip = int2ip(base_ip + index)

        def cb(_peer):
            return lambda: TorrentProxy(_peer)

        server = yield from loop.create_server(cb(peer), ip, 0)

        port = server.sockets[0].getsockname()[1]
        proxied_peers.append({ 'ip': ip, 'port': port })

        logging.info('Opened listener on {}'.format(port))

    torrent[b'peers'] = encode_peers(proxied_peers)

    return web.Response(body=bencodepy.encode(torrent))

@asyncio.coroutine
def handle_piece(request):
    logging.warning('Got piece request!')

    source_peer_id = request.match_info.get('source_peer_id')
    peer_id = request.match_info.get('peer_id')
    piece = request.match_info.get('piece')
    block_offset = request.match_info.get('block_offset')
    block_length = request.match_info.get('block_length')

@asyncio.coroutine
def init(loop):
    app = web.Application(loop=loop)
    app.router.add_route('GET', '/{uri}', handle)
    app.router.add_route('GET', '/piece/{source_peer_id}/{peer_id}/{piece}/{block_offset}/{block_length}', handle_piece)

    srv = yield from loop.create_server(app.make_handler(), '127.0.0.1', int(sys.argv[2]))
    logging.warning("Server started at http://127.0.0.1:{}".format(sys.argv[2]))
    return srv

if len(sys.argv) != 3:
    logging.error('Usage: {} <tracker> <http listen port>'.format(sys.argv[0]))
    quit()

loop = asyncio.get_event_loop()
loop.run_until_complete(init(loop))
loop.run_forever()
