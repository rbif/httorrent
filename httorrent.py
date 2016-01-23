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
import binascii
logging.basicConfig(level=logging.WARNING,
    format='%(asctime)-15s %(filename)s:%(funcName)s:%(lineno)s: %(message)s')

# /announce?info_hash=%BF%DBFvk%D0%E3%22%5C%25%99%E4%3B%23R%B2%F2%92%E3%DB&peer_id=-lt0D20-%7E%19%B6%CA%C9P%14%EDY%1A%97%A9&key=0e1d2537&compact=1&port=6966&uploaded=0&downloaded=0&left=740105370&event=started

# rtorrent headers:
# GET /announce?info_hash=%BF%DBFvk%D0%E3%22%5C%25%99%E4%3B%23R%B2%F2%92%E3%DB&peer_id=-lt0D20-%7E%19%B6%CA%C9P%14%EDY%1A%97%A9&key=0e1d2537&compact=1&port=6966&uploaded=0&downloaded=0&left=740105370&event=started HTTP/1.1
# User-Agent: rtorrent/0.9.2/0.13.2
# Host: tracker.aletorrenty.pl:2710
# Accept: */*
# Accept-Encoding: deflate, gzip

# keys: (from_peer, to_peer)
active = {}

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
        for index, message_type in TorrentProtocol.messages.items():
            if 'do_' + message_type[0] == func.__name__:
                break

        if len(message_type) < 3:
            data = func(self)
        elif len(args) != message_type[2]:
            raise TorrentException('Invalid number of arguments supplied.')
        else:
            data = func(self, *args)

        if not data:
            data = b''

        return struct.pack('>IB', len(data) + 1, index) + data

    return func_wrapper

class TorrentProtocol:
    messages = {
        0: ('choke', 0), 1: ('unchoke', 0), 2: ('interested', 0), 3: ('uninterested', 0),
        4: ('have', 4, 1), 5: ('bitfield', '?', 1), 6: ('request', 12, 3), 
        7: ('piece', '?', 3), 8: ('cancel', 12, 3), 20: ('extended', '?', 2)
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
        proto_len, proto, reserved, info_hash, peer_id, message = unpack('B19s8s20s20s',
             message)
        # print(proto_len, proto_len == 19, proto, info_hash, peer_id, message)

        if proto_len != 19:
            raise TorrentException('Invalid protocol length in handshake.')

        if proto != b'BitTorrent protocol':
            raise TorrentException('Invalid protocol length in handshake.')

        self.info_hash = info_hash
        self.peer_id = binascii.hexlify(peer_id).decode()
        #if info_hash != self.info_hash:
        #    raise TorrentException('Info hash does not match in handshake.')

        logging.info('Handshake completed with peer.')
        self.got_handshake = True
        return message, ( reserved, self.info_hash, self.peer_id )

    def decode_message(self, message):
        if not self.got_handshake:
            message, handshake = self.decode_handshake(message)
            return message, 'handshake', handshake

        if len(message) < 4:
            raise TorrentWantData()

        length, message = unpack('>I', message)
        if len(message) < length:
            raise TorrentWantData()

        if not length:
            return message, 'ping', ()

        length -= 1
        message_id, message = unpack('>B', message)

        if message_id not in self.messages:
            raise TorrentException('Invalid message id specified.')

        message_type = self.messages[message_id]

        if message_type[1] != '?' and message_type[1] != length:
            raise TorrentException('Invalid message id and length.')

        payload, message = message[:length], message[length:]
        logging.info('Got message type %s.' % message_type[0])
        ret = getattr(self, 'message_' + message_type[0])(payload)

        if not isinstance(ret, tuple):
            ret = (ret, )

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
        logging.debug(piece)
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

    def do_handshake(self, reserved, info_hash, peer_id):
        return struct.pack('>B19s8s20s20s', 19, b'BitTorrent protocol', reserved,
            info_hash, bytes.fromhex(peer_id))

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

        return int(bitfield, 2).to_bytes(int(len(bitfield) / 8), byteorder='big')

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

    def do_ping(self):
        return b'\x00\x00\x00\x00'

class TorrentProxy(asyncio.Protocol):
    def __init__(self, peer, callback=None, peer_handler=None, peer_wanted=None):
        self.peer_handler = peer_handler
        self.callback = callback

        # debug hax
        peer['ip'] = '127.0.0.1'

        self.closed = False
        self.peer = peer
        self.waiting = []

        self.wanted = {}
        self.peer_wanted = peer_wanted
        self.data = b''
        self.proxy_data = b''

        self.peer_peer_id = None
        self.my_peer_id = None

        self.pre_hook = [ 'handshake' ]
        self.hooks = [ 'request', 'piece', 'cancel', 'extended', 'handshake' ]

        self.torrent = TorrentProtocol(self.peer['ip'], self.peer['port'])
        super().__init__()

    @asyncio.coroutine
    def create_connection(self):
        try:
            yield from loop.create_connection(lambda: TorrentProxy(self.peer,
                self.peer_connected, self.handle_message, self.wanted), self.peer['ip'],
                self.peer['port'])
        except ConnectionRefusedError:
            logging.debug('Connection refused.')

    def connection_made(self, transport):
        self.transport = transport
        self.log('Connection received! Connecting to {}'.format(self.peer),
            logging.INFO, out=False)

        if not self.callback:
            loop.create_task(self.create_connection())
        else:
            self.callback(self.handle_message, self.wanted)

    def peer_connected(self, peer_handler, peer_wanted):
        self.peer_handler = peer_handler
        self.peer_wanted = peer_wanted

        if self.waiting:
            logging.debug('Flushing waiting data!')

            for message_type, ret in self.waiting:
                loop.create_task(self.peer_handler(message_type, ret))

            self.waiting = []

    def data_received(self, data):
        if not data:
            self.log('Connection closed.', logging.WARNING, False)
            return

        self.data += data
        self.log('Received: {}'.format(data), out=False)

        while self.data:
            try:
                self.data, message_type, ret = self.torrent.decode_message(self.data)
            except TorrentWantData:
                self.log('Data wanted.', logging.DEBUG, False)
                break
            except TorrentException as e:
                self.log('Error: %s' % e, logging.WARNING, False)
                break
            except struct.error:
                self.log('Not enough data received.', logging.DEBUG, False)
                break

            if message_type in self.pre_hook:
                loop.create_task(getattr(self, 'do_pre_' + message_type)(*ret))

            if not self.peer_handler:
                self.waiting.append((message_type, ret))
            else:
                loop.create_task(self.peer_handler(message_type, ret))

    @asyncio.coroutine
    def handle_message(self, message_type, ret, skip_hooks=False):
        data = None
        if message_type in self.hooks and not skip_hooks:
            data = yield from getattr(self, 'do_' + message_type)(*ret)

        if message_type not in self.hooks or data or skip_hooks:
            data = getattr(self.torrent, 'do_' + message_type)(*ret)

        if not data:
            return

        self.log('Sending: {}'.format(data))
        self.transport.write(data)

    @asyncio.coroutine
    def do_pre_handshake(self, reserved, info_hash, peer_id):
        self.my_peer_id = peer_id
        self.info_hash = info_hash
        self.add_to_active()

    @asyncio.coroutine
    def do_handshake(self, reserved, info_hash, peer_id):
        self.peer_peer_id = peer_id
        self.add_to_active()
        return True

    @asyncio.coroutine
    def do_extended(self, extension_id, payload):
        self.log('payload: {}'.format(payload), logging.INFO)
        return True
        
    # proxy side
    @asyncio.coroutine
    def do_request(self, piece, block_offset, block_length):
        if not self.my_peer_id or not self.peer_peer_id:
            return True

        r = yield from aiohttp.get('http://127.0.0.1:{}/piece/{}/{}/{}/{}/{}'.format(
            sys.argv[3], self.my_peer_id, self.peer_peer_id, piece, block_offset,
            block_length))
        data = yield from r.read()
        yield from r.release()

        yield from self.peer_handler('piece', (piece, block_offset, data))

    @asyncio.coroutine
    def do_piece(self, *args):
        if not self.my_peer_id or not self.peer_peer_id:
            return True

        key = args[:2] + (len(args[2]), )
        if key not in self.wanted:
            return True

        self.wanted[key].set_result(args[2])
        del self.wanted[key]

    @asyncio.coroutine
    def do_cancel(self, args):
        if not self.my_peer_id or not self.peer_peer_id:
            return True

        if args not in self.wanted:
            return True

        self.wanted[key].set_exception(TorrentException())
        del self.wanted[key]

    # proxy side
    @asyncio.coroutine
    def get_piece(self, piece, block_offset, block_length):
        f = asyncio.Future()
        self.peer_wanted[piece, block_offset, block_length] = f

        yield from self.peer_handler('request', (piece, block_offset, block_length), True)
        data = yield from f
        return data

    # proxy side
    def add_to_active(self):
        if not self.my_peer_id or not self.peer_peer_id:
            return

        active[self.my_peer_id, self.peer_peer_id] = self.get_piece

    def remove_from_active(self):
        if not self.my_peer_id or not self.peer_peer_id:
            return

        if (self.my_peer_id, self.peer_peer_id) in active:
            del active[self.my_peer_id, self.peer_peer_id]

    def connection_lost(self, exc):
        self.log('Server disconnected.', logging.WARNING)
        self.remove_from_active()

    def log(self, message, level=logging.DEBUG, out=True):
        if out:
            dst_ip, dst_port = self.transport.get_extra_info('peername')
            src_ip, src_port = self.transport.get_extra_info('sockname')
        else:
            dst_ip, dst_port = self.transport.get_extra_info('sockname')
            src_ip, src_port = self.transport.get_extra_info('peername')

        logging.log(level, '{}:{} -> {}:{}: {}'.format(src_ip, src_port,
            dst_ip, dst_port, message))

@asyncio.coroutine
def handle(request):
    logging.warning('Tracker connection received!')

    def create_sock(_peer, ip):
        server = yield from loop.create_server(lambda: TorrentProxy(_peer), ip, 0)
        port = server.sockets[0].getsockname()[1]
        return port

    port = yield from create_sock({ 
        'ip': request.GET['ip'],
        'port': request.GET['port'] 
    }, '127.0.0.1')

    path = request.path_qs.replace('port={}'.format(request.GET['port']),
        'port={}'.format(port))

    r = yield from aiohttp.get(sys.argv[1] + path)
    data = yield from r.read()
    yield from r.release()

    torrent = bencodepy.decode(data)
    proxied_peers = []

    base_ip = ip2int('127.13.37.0')
    for index, peer in enumerate(decode_peers(torrent[b'peers'])):
        ip = int2ip(base_ip + index)
        port = yield from create_sock(peer, ip) 
        proxied_peers.append({ 'ip': ip, 'port': port })
        logging.info('Opened listener on {}'.format(port))

    torrent[b'peers'] = encode_peers(proxied_peers)

    return web.Response(body=bencodepy.encode(torrent))

@asyncio.coroutine
def handle_piece(request):
    logging.warning('Got piece request!')

    source_peer_id = request.match_info.get('source_peer_id')
    peer_id = request.match_info.get('peer_id')
    piece = int(request.match_info.get('piece'))
    block_offset = int(request.match_info.get('block_offset'))
    block_length = int(request.match_info.get('block_length'))

    if (source_peer_id, peer_id) not in active:
        return web.Response(body=b'no such peers')

    try:
        data = yield from active[source_peer_id, peer_id](piece, block_offset, block_length)
    except TorrentException as e:
        return web.Response(body=e.encode())
    
    return web.Response(body=data)

@asyncio.coroutine
def init(loop):
    app = web.Application(loop=loop)
    app.router.add_route('GET', '/{uri}', handle)
    app.router.add_route('GET', '/piece/{source_peer_id}/{peer_id}/{piece}/{block_offset}/{block_length}', handle_piece)

    srv = yield from loop.create_server(app.make_handler(), '127.0.0.1', int(sys.argv[2]))
    logging.warning("Server started at http://127.0.0.1:{}".format(sys.argv[2]))
    return srv

if len(sys.argv) != 4:
    logging.error('Usage: {} <tracker> <http listen port> <http peer port>'.format(sys.argv[0]))
    quit()

loop = asyncio.get_event_loop()
loop.run_until_complete(init(loop))
loop.run_forever()
