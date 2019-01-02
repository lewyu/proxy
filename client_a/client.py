import logging
import base64
import configparser
import signal
import socket
import threading
import time

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

import util


class Client(object):
    def __init__(self, host, port, ID):
        self.server = (host, port)

        self.receiver_public_key_md5 = ID
        self.receiver_public_key = ''
        self.receiver = ('', 0)

        self.public_key_md5 = ''
        self.public_key = ''
        self.private_key = ''
        self.socket = ('', 0)
        self.udp_client = None
        self.__bufsize = 1024
        self.__init_rsa()
        self.__init_udp_client()
        self.ack = 0

    def __init_udp_client(self):
        """
        init self.udp_client
        """
        self.udp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def __init_rsa(self):
        """
        init self.public_key_md5, self.public_key, self.private_key
        """
        try:
            with open('public.pem', 'rb') as f:
                self.public_key = f.read().decode()
                self.public_key_md5 = util.md5sum(self.public_key)
            with open('private.pem', 'rb') as f:
                self.private_key = f.read().decode()
        except:
            rsa = RSA.generate(1024)
            raw_private_pem = rsa.exportKey()
            raw_public_pem = rsa.publickey().exportKey()
            self.private_key = raw_private_pem.decode()
            self.public_key = raw_public_pem.decode()
            self.public_key_md5 = util.md5sum(self.public_key)
            with open('public.pem', 'wb') as f:
                f.write(raw_public_pem)
            with open('private.pem', 'wb') as f:
                f.write(raw_private_pem)
            exit()
        finally:
            log = 'your id is {}'.format(self.public_key_md5)
            logging.info(log)
            print(log)

    def request_update_receiver_public_key(self):
        rpkm = self.receiver_public_key_md5
        _data = {"op": "gpk", "data": {"pkm": rpkm}}
        self.udp_client.sendto(util.encode(_data), self.server)
        log = 'request receiver public key'
        logging.info(log)
        print(log)

    def __handle_update_receiver_public_key(self, data):
        """
        init self.receiver_public_key
        """
        _public_key = data.get('pk')
        _md5 = util.md5sum(_public_key)
        condition = (_md5 == self.receiver_public_key_md5)
        if condition:
            self.receiver_public_key = _public_key
            log = 'receiver public key updated {}'.format(_md5)
        elif _public_key == 'NULL':
            log = 'receiver public key does not being uploaded'
        else:
            log = 'receiver public key does not match md5 code'
        logging.info(log)
        print(log)

    def request_save_public_key(self):
        pkm = self.public_key_md5
        pk = self.public_key
        _data = {"op": "spk", "data": {"pkm": pkm, "pk": pk}}
        self.udp_client.sendto(util.encode(_data), self.server)
        log = 'request saving public key'
        logging.info(log)
        print(log)

    def request_update_socket(self):
        _data = {'op': 'gns'}
        self.udp_client.sendto(util.encode(_data), self.server)
        log = 'request socket'
        logging.info(log)
        print(log)

    def __handel_update_socket(self, data):
        ip = data.get('ip')
        port = data.get('port')
        self.socket = (ip, int(port))
        log = 'nat socket updated {}:{}'.format(ip, port)
        logging.info(log)
        print(log)

    def __encrypt(self, plain, public_key):
        """
        both input and output are string
        """
        rsakey = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(rsakey)
        _ciphertext = cipher.encrypt(plain.encode())
        ciphertext = base64.b64encode(_ciphertext)
        return ciphertext.decode()

    def __decrypt(self, ciphertext, private_key):
        """
        both input and output are string
        """
        rsakey = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(rsakey)
        _ciphertext = ciphertext.encode()
        _ciphertext = base64.b64decode(_ciphertext)
        plaintext = cipher.decrypt(_ciphertext)
        return plaintext.decode()

    def request_save_encrypted_socket(self):
        try:
            plain_socket = '{}:{}'.format(self.socket[0], str(self.socket[1]))
            _rpl = self.receiver_public_key
            pkm = self.public_key_md5
            es = self.__encrypt(plain_socket, _rpl)
            _data = {"op": "ses", "data": {"pkm": pkm, "es": es}}
            self.udp_client.sendto(util.encode(_data), self.server)
            log = 'request saving encrypted socket'
            logging.info(log)
            print(log)
        except:
            log = 'an error occurred during encryption and re-request the receiver public key'
            self.request_update_receiver_public_key()
            logging.info(log)
            print(log)
            time.sleep(1)
            self.request_save_encrypted_socket()

    def request_update_encrypted_socket(self):
        times = 1
        flag = 1
        while flag:
            try:
                pkm = self.receiver_public_key_md5
                _data = {"op": "ges", "data": {"pkm": pkm}}
                self.udp_client.sendto(util.encode(_data), self.server)
                log = 'request receiver encrypted socket'
                logging.info(log)
                print(log)
                flag = 0
            except:
                log = 'an error occurred during decryption ,re-uploading the public key'
                logging.info(log)
                print(log)
                self.request_save_public_key()
                time.sleep(times)
                times = min(120, times*2)

    def __handle_update_encrypted_socket(self, data):
        socket = self.__decrypt(data.get('es'), self.private_key)
        ip = str(socket).split(':')[0]
        port = int(str(socket).split(':')[1])
        self.receiver = (ip, port)
        log = 'receiver updated to {}:{}'.format(ip, port)
        logging.info(log)
        print(log)

    def sync(self):
        while self.ack < 10:
            time.sleep(1)
            if self.receiver == ('', 0):
                log = 'waiting for update receiver'
                self.request_update_encrypted_socket()
                continue
            if self.ack == 0:
                self.request_save_encrypted_socket()
                self.request_update_encrypted_socket()
            _data = {"op": "syn", "data": {"ack": self.ack}}
            self.udp_client.sendto(util.encode(_data), self.receiver)
            _rpkm = self.receiver_public_key_md5
            log = 'send ack={} to {}'.format(self.ack, _rpkm)
            logging.info(log)
            print(log)

        _rpkm = self.receiver_public_key_md5
        log = 'the connection to {} has been established '.format(_rpkm)
        logging.info(log)
        print(log)

    def __handle_sync(self, data, addr):
        if self.receiver == addr:
            self.ack = data.get('ack') + 1
        else:
            self.ack = 0
            self.receiver = addr

    def handle(self, op, data, addr):
        if op == 'syn':
            self.__handle_sync(data, addr)
        elif op == 'gns':
            self.__handel_update_socket(data)
        elif op == 'spk':
            pass
        elif op == 'gpk':
            self.__handle_update_receiver_public_key(data)
        elif op == 'ses':
            pass
        elif op == 'ges':
            self.__handle_update_encrypted_socket(data)

    def start(self):
        while True:
            bytecode, addr = self.udp_client.recvfrom(self.__bufsize)
            try:
                _data = util.decode(bytecode)
                op = _data['op']
                data = _data.get('data')
                self.handle(op, data, addr)
            except Exception:
                print(bytecode)


if __name__ == "__main__":
    _config = configparser.ConfigParser()
    _config.read('conf.ini')
    host = _config.get("default", "host")
    port = _config.get("default", "port")
    ID = _config.get("default", "ID")
    client = Client(host, int(port), ID)
    threading.Thread(target=client.start).start()
    client.request_save_public_key()
    client.request_update_receiver_public_key()
    client.request_update_socket()
    client.request_save_encrypted_socket()
    client.request_update_encrypted_socket()
    client.sync()
