import socket
import threading
import logging
import json
import signal
import util

UDP_SERVER = None
MD5_PK = {}
MD5_SOCKET = {}


def quit(signum, frame):
    global UDP_SERVER
    UDP_SERVER.close()
    logging.info('close udp server')
    exit()


def listener():
    host = '0.0.0.0'
    port = 12131
    bufsize = 1024
    global UDP_SERVER
    logging.info('create socket')
    udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_server.bind((host, port))
    UDP_SERVER = udp_server
    logging.info('start listener')
    while True:
        bytecode, addr = udp_server.recvfrom(bufsize)
        try:
            _data = util.decode(bytecode)
            op = _data['op']
            data = _data.get('data')
        except:
            source = '{}:{}'.format(addr[0], addr[1])
            logging.warning('unknown request from {}'.format(source))
            continue
        if op == 'gns':
            get_nat_socket(data, addr, udp_server)
        elif op == 'gpk':
            get_public_key(data, addr, udp_server)
        elif op == 'spk':
            save_public_key(data, addr, udp_server)
        elif op == 'ges':
            get_encrypted_socket(data, addr, udp_server)
        elif op == 'ses':
            save_encrypted_socket(data, addr, udp_server)
        else:
            source = '{}:{}'.format(addr[0], addr[1])
            logging.warning('unknown operation from {}'.format(source))


def get_nat_socket(data, addr, udp_server):
    _socket = '{}:{}'.format(addr[0], addr[1])
    data = {'op': 'gns', 'data': {'ip': addr[0], 'port': str(addr[1])}}
    udp_server.sendto(util.encode(data), addr)
    logging.info(data)


def get_public_key(data, addr, udp_server):
    global MD5_PK
    try:
        pkm = data['pkm']
        pk = MD5_PK.get(pkm) or 'NULL'
        data = {'op': 'gpk', 'data': {'pkm': pkm, 'pk': pk}}
        udp_server.sendto(util.encode(data), addr)
        logging.info(data)
    except:
        source = '{}:{}'.format(addr[0], addr[1])
        logging.warning('unknown args from {}'.format(source))


def save_public_key(data, addr, udp_server):
    global MD5_PK
    try:
        public_key_md5 = data['pkm']
        public_key = data['pk']
        MD5_PK[public_key_md5] = public_key
        data = {'op': 'spk', 'data': {'pkm': public_key_md5}}
        udp_server.sendto(util.encode(data), addr)
        logging.info(data)
    except:
        source = '{}:{}'.format(addr[0], addr[1])
        logging.warning('unknown args from {}'.format(source))


def get_encrypted_socket(data, addr, udp_server):
    global MD5_SOCKET
    try:
        pkm = data['pkm']
        es = MD5_SOCKET.get(pkm) or 'NULL'
        data = {'op': 'ges', 'data': {'pkm': pkm, 'es': es}}
        udp_server.sendto(util.encode(data), addr)
        logging.info(data)
    except:
        source = '{}:{}'.format(addr[0], addr[1])
        logging.warning('unknown args from {}'.format(source))


def save_encrypted_socket(data, addr, udp_server):
    global MD5_SOCKET
    try:
        pkm = data['pkm']
        es = data['es']
        MD5_SOCKET[pkm] = es
        _data = MD5_SOCKET.get(pkm)
        data = {'op': 'ses', 'data': {'pkm': pkm, 'es': es}}
        udp_server.sendto(util.encode(data), addr)
        logging.info(data)
    except:
        source = '{}:{}'.format(addr[0], addr[1])
        logging.warning('unknown args from {}'.format(source))


if __name__ == '__main__':
    '''
    nohup python3 server.py >> log &
    '''
    _format = '%(levelname)s: %(message)s'
    logging.basicConfig(level=logging.INFO, format=_format)
    signal.signal(signal.SIGINT, quit)
    signal.signal(signal.SIGTERM, quit)
    listener()
