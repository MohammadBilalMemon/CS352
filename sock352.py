import binascii
import socket as syssock
import struct
import sys
import time
import random

# encryption libraries 
import nacl.utils
import nacl.secret
import nacl.utils
from nacl.public import PrivateKey, Box

# the public and private keychains in hex format 
global publicKeysHex
global privateKeysHex

# the public and private keychains in binary format 
global publicKeys
global privateKeys

# the encryption flag 
global ENCRYPT

publicKeysHex = {}
privateKeysHex = {}
publicKeys = {}
privateKeys = {}

# this is 0xEC
ENCRYPT = 236

# Defined the variables that'll be constant throughout packets
# Calculated by adding number of bits in header and dividing it by 8
# because header length is in terms of bytes
# 8 + 8 + 8 + 8 + 16 + 16 + 32 + 32 + 64 + 64 + 32 + 32 = 320/8 = 40
SOCK352_SYN = 0x01
SOCK352_FIN = 0x02
SOCK352_ACK = 0x04
SOCK352_RESET = 0x08
SOCK352_HAS_OPT = 0xA0
version = 1
opt_ptr = 0
protocol = 0
header_len = 40
checksum = 0
source_port = 0
dest_port = 0
window = 0


# these functions are global to the class and
# define the UDP ports all messages are sent
# and received from
def init(UDPportTx, UDPportRx):  # initialize your UDP socket here
    global Tx, Rx, s, connections
    Tx = int(UDPportTx)
    Rx = int(UDPportRx)
    s = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)
    s.bind(('localhost', Rx))
    connections = []
    return


# read the keyfile. The result should be a private key and a keychain of
# public keys
def readKeyChain(filename):
    global publicKeysHex
    global privateKeysHex
    global publicKeys
    global privateKeys
    if (filename):
        try:
            keyfile_fd = open(filename, "r")
            for line in keyfile_fd:
                words = line.split()
                # check if a comment
                # more than 2 words, and the first word does not have a
                if ((len(words) >= 4) and (words[0].find("#") == -1)):
                    host = words[1]
                    port = words[2]
                    print((host, port))
                    keyInHex = words[3]
                    if (words[0] == "private"):
                        privateKeysHex[(host, port)] = keyInHex
                        privateKeys[(host, port)] = nacl.public.PrivateKey(keyInHex, nacl.encoding.HexEncoder)
                    elif (words[0] == "public"):
                        publicKeysHex[(host, port)] = keyInHex
                        publicKeys[(host, port)] = nacl.public.PublicKey(keyInHex, nacl.encoding.HexEncoder)
        except Exception, e:
            print("error: opening keychain file: %s %s" % (filename, repr(e)))
    else:
        print("error: No filename presented")

    return (publicKeys, privateKeys)


class socket:

    def __init__(self):
        self.receivedACK = []
        self.receivedSeq_no = []
        self.encrypt = False
        return

    def bind(self, address):
        return

    def connect(self, *args):

        # Check for encryption
        global ENCRYPT, privateKeys, publicKeys
        if (len(args) >= 1):
            address = args[0]
        if (len(args) >= 2):
            if (args[1] == ENCRYPT):
                self.encrypt = True
                self.box = Box(privateKeys[('*', '*')], publicKeys[(address[0], str(Tx))])

        # Fill in header values
        global version, opt_ptr, protocol, header_len, checksum, source_port, dest_port, window
        flags = SOCK352_SYN
        sequence_no = random.random()
        ack_no = 0
        payload_len = 0

        # Pack the data
        sock352PktHdrData = '!BBBBHHLLQQLL'
        udpPkt_hdr_data = struct.Struct(sock352PktHdrData)
        header = udpPkt_hdr_data.pack(version, flags, opt_ptr, protocol, header_len, checksum,
                                      source_port, dest_port, sequence_no, ack_no, window,
                                      payload_len)

        # Connect with the server
        destination = address[0]
        s.connect((destination, Tx))
        print('Trying to connect w/ server..')

        # Encrypt message if encrypt is enabled
        if self.encrypt:
            nonce = nacl.utils.random(Box.NONCE_SIZE)
            header = self.box.encrypt(header, nonce)

        # Send SYN flagged header to server and receive the server's response and check to see if SYN/ACK
        # If the server had another response, resend the packet
        while flags != SOCK352_SYN + SOCK352_ACK:
            s.send(header)
            receivedHeader = ''
            # Check for encrypion before receiving
            if self.encrypt:
                receivedHeader = s.recv(header_len + 40)
                receivedHeader = self.box.decrypt(receivedHeader)
            else:
                receivedHeader = s.recv(header_len)

            (version, flags, opt_ptr, protocol, header_len, checksum,
             source_port, dest_port, sequence_no, ack_no, window,
             payload_len) = udpPkt_hdr_data.unpack(receivedHeader)

        # Record received ACK/seq_no
        self.receivedACK.append(ack_no)
        self.receivedSeq_no.append(sequence_no)

        # After receiving SYN/ACK from server, send ACK
        flags = SOCK352_ACK
        temp = sequence_no
        sequence_no = ack_no
        ack_no = temp + 1
        header = udpPkt_hdr_data.pack(version, flags, opt_ptr, protocol, header_len, checksum,
                                      source_port, dest_port, sequence_no, ack_no, window,
                                      payload_len)

        # Encrypt message if encrypt is enabled
        if self.encrypt:
            nonce = nacl.utils.random(Box.NONCE_SIZE)
            header = self.box.encrypt(header, nonce)

        s.send(header)
        return

    def listen(self, backlog):
        return

    def accept(self, *args):
        # Wait to receive header data
        print('waiting for connection...')

        # Check for encryption
        if (len(args) >= 1):
            if (args[0] == ENCRYPT):
                self.encrypt = True

        (clientsocket, address) = self.__sock352_get_packet()
        print(address)
        return (clientsocket, address)

    def close(self):  # fill in your code here
        # Fill in header values, make sure flags is FIN
        global version, opt_ptr, protocol, header_len, checksum, source_port, dest_port, window
        flags = SOCK352_FIN
        sequence_no = 0
        ack_no = 0
        payload_len = 0

        # Pack the data
        sock352PktHdrData = '!BBBBHHLLQQLL'
        udpPkt_hdr_data = struct.Struct(sock352PktHdrData)
        header = udpPkt_hdr_data.pack(version, flags, opt_ptr, protocol, header_len, checksum,
                                      source_port, dest_port, sequence_no, ack_no, window,
                                      payload_len)

        # Encrypt message if encrypt is enabled
        if self.encrypt:
            nonce = nacl.utils.random(Box.NONCE_SIZE)
            header = self.box.encrypt(header, nonce)

            # Send header and close the socket
        s.send(header)
        s.close()
        return

    def send(self, buffer):  # fill in your code here
        # Fill in header values: sequence_no will be the last receivedACK, and ack_no
        # will be the last received sequence_no + 1
        global version, opt_ptr, protocol, header_len, checksum, source_port, dest_port, window
        flags = SOCK352_ACK
        sequence_no = self.receivedACK[-1]
        ack_no = self.receivedSeq_no[-1] + 1

        # Hard-coded fragmentsize because can't handle it dynamically :(
        # This is the max # of bytes that the server can receive
        # as defined in server1
        index = 0;
        FRAGMENTSIZE = 4096
        fragment = ''

        while (index != len(buffer)):
            if (len(buffer) - index > FRAGMENTSIZE):
                payload_len = FRAGMENTSIZE

                # Pack the header data and send it to server
                sock352PktHdrData = '!BBBBHHLLQQLL'
                udpPkt_hdr_data = struct.Struct(sock352PktHdrData)
                header = udpPkt_hdr_data.pack(version, flags, opt_ptr, protocol, header_len, checksum,
                                              source_port, dest_port, sequence_no, ack_no, window,
                                              payload_len)

                # Encrypt message if encrypt is enabled
                if self.encrypt:
                    nonce = nacl.utils.random(Box.NONCE_SIZE)
                    header = self.box.encrypt(header, nonce)

                s.send(header)

                # Send fragment to server
                fragment = buffer[index:(index + FRAGMENTSIZE)]

                # Encrypt fragment if encrypt is enabled
                if self.encrypt:
                    nonce = nacl.utils.random(Box.NONCE_SIZE)
                    fragment = self.box.encrypt(fragment, nonce)

                    # Set timeout and send fragment
                try:
                    s.settimeout(.2)
                    s.send(fragment)
                except syssock.timeout:
                    s.send(fragment)
                finally:
                    s.settimeout(None)

                print('sent packet: '), len(fragment), ('bytes')

                # TODO: receive ACK?
                # Check for encrypion before receiving
                if self.encrypt:
                    receivedHeader = s.recv(header_len + 40)
                    receivedHeader = self.box.decrypt(receivedHeader)
                else:
                    receivedHeader = s.recv(header_len)

                # Increment index
                index += FRAGMENTSIZE
            else:
                payload_len = len(buffer) - index

                # Pack the header data
                sock352PktHdrData = '!BBBBHHLLQQLL'
                udpPkt_hdr_data = struct.Struct(sock352PktHdrData)
                header = udpPkt_hdr_data.pack(version, flags, opt_ptr, protocol, header_len, checksum,
                                              source_port, dest_port, sequence_no, ack_no, window,
                                              payload_len)

                # Encrypt message if encrypt is enabled
                if self.encrypt:
                    nonce = nacl.utils.random(Box.NONCE_SIZE)
                    header = self.box.encrypt(header, nonce)

                s.send(header)

                # Send fragment to server
                fragment = buffer[index:len(buffer)]

                # Encrypt fragment if encrypt is enabled
                if self.encrypt:
                    nonce = nacl.utils.random(Box.NONCE_SIZE)
                    fragment = self.box.encrypt(fragment, nonce)

                    # Set timeout and send fragment
                try:
                    s.settimeout(.2)
                    s.send(fragment)
                except syssock.timeout:
                    s.send(fragment)
                finally:
                    s.settimeout(None)

                print('sent packet: '), len(fragment), ('bytes')

                # TODO: receive ACK?
                # Check for encrypion before receiving
                if self.encrypt:
                    receivedHeader = s.recv(header_len + 40)
                    receivedHeader = self.box.decrypt(receivedHeader)
                else:
                    receivedHeader = s.recv(header_len)

                # Increment index
                index = payload_len
                break;

        return len(buffer)

    def recv(self, nbytes):
        # Fill in header values
        global version, opt_ptr, protocol, header_len, checksum, source_port, dest_port, window

        # Receive and unpack header data from client
        receivedHeader = ''
        # Check for encrypion before receiving
        if self.encrypt:
            receivedHeader = s.recv(header_len + 40)
            receivedHeader = self.box.decrypt(receivedHeader)
        else:
            receivedHeader = s.recv(header_len)
        sock352PktHdrData = '!BBBBHHLLQQLL'
        udpPkt_hdr_data = struct.Struct(sock352PktHdrData)
        (version, flags, opt_ptr, protocol, header_len, checksum,
         source_port, dest_port, sequence_no, ack_no, window,
         payload_len) = udpPkt_hdr_data.unpack(receivedHeader)

        # Receive the bytes dictated by the payload_len
        # Check for encrypion before receiving
        if self.encrypt:
            bytesreceived = s.recv(payload_len + 40)
            bytesreceived = self.box.decrypt(bytesreceived)
        else:
            bytesreceived = s.recv(payload_len)

            # Give ack_no the value of the next sequence number the client should send over
        # And give sequence_no the value of what the client is asking for
        temp = ack_no
        ack_no = sequence_no + payload_len + 1
        sequence_no = temp
        flags = SOCK352_ACK

        # Pack and send the ACK to the client
        header = udpPkt_hdr_data.pack(version, flags, opt_ptr, protocol, header_len, checksum,
                                      source_port, dest_port, sequence_no, ack_no, window,
                                      payload_len)

        # Encrypt message if encrypt is enabled
        if self.encrypt:
            nonce = nacl.utils.random(Box.NONCE_SIZE)
            header = self.box.encrypt(header, nonce)

        s.send(header)
        print('received '), len(bytesreceived), (' bytes')

        return bytesreceived

    def __sock352_get_packet(self):
        global version, opt_ptr, protocol, header_len, checksum, source_port, dest_port, window

        # Receive and unpack the data
        receivedHeader = ''
        addr = (1, 1)

        # If encryption is enabled, receive a longer encrypted message and decrypt it
        if self.encrypt:
            (receivedHeader, addr) = s.recvfrom(header_len + 40)
            if addr[0] == '127.0.0.1':
                self.box = Box(privateKeys[('*', '*')], publicKeys[('localhost', str(Tx))])
            else:
                self.box = Box(privateKeys[('*', '*')], publicKeys[(addr[0], str(Tx))])
            receivedHeader = self.box.decrypt(receivedHeader)
        else:
            (receivedHeader, addr) = s.recvfrom(header_len)

        sock352PktHdrData = '!BBBBHHLLQQLL'
        udpPkt_hdr_data = struct.Struct(sock352PktHdrData)
        (version, flags, opt_ptr, protocol, header_len, checksum,
         source_port, dest_port, sequence_no, ack_no, window,
         payload_len) = udpPkt_hdr_data.unpack(receivedHeader)

        # If the header flag was SYN
        if flags == SOCK352_SYN:
            # Check to see if the address is in the list of connections
            # and if it's not, send back a random sequence_no and a
            # and set the ack_no to the incoming sequence_no + 1
            # Also instantiate a second socket to communicate w/ client
            if addr not in connections:
                connections.append(addr)
                ack_no = sequence_no + 1
                sequence_no = random.random()
                flags = SOCK352_SYN + SOCK352_ACK
                header = udpPkt_hdr_data.pack(version, flags, opt_ptr, protocol, header_len, checksum,
                                              source_port, dest_port, sequence_no, ack_no, window,
                                              payload_len)
                s.connect(addr)

                # Check for encryption before sending
                if self.encrypt:
                    nonce = nacl.utils.random(Box.NONCE_SIZE)
                    header = self.box.encrypt(header, nonce)

                    # Send out the SYN/ACK flagged header, and wait for
                # ACK response from client
                while flags != SOCK352_ACK:
                    s.send(header)

                    # Check for encrypion before receiving
                    if self.encrypt:
                        receivedHeader = s.recv(header_len + 40)
                        receivedHeader = self.box.decrypt(receivedHeader)
                    else:
                        receivedHeader = s.recv(header_len)

                    (version, flags, opt_ptr, protocol, header_len, checksum,
                     source_port, dest_port, sequence_no, ack_no, window,
                     payload_len) = udpPkt_hdr_data.unpack(receivedHeader)

                print('Connected to:')
                return (self, addr)
            # If it is in the list, the connection is reset
            else:
                sequence_no = sequence_no + 1
                flags = SOCK352_RESET
                header = udpPkt_hdr_data.pack(version, flags, opt_ptr, protocol, header_len, checksum,
                                              source_port, dest_port, sequence_no, ack_no, window,
                                              payload_len)
                s.connect(addr)
                # Encrypt message if encrypt is enabled
                if self.encrypt:
                    nonce = nacl.utils.random(Box.NONCE_SIZE)
                    header = self.box.encrypt(header, nonce)
                s.send(header)
                return

        else:
            # If the header flag is FIN, send back a FIN and remove the addr
            # from connections and clear the fragments
            if flags == SOCK352_FIN:
                flags = SOCK352_FIN
                header = udpPkt_hdr_data.pack(version, flags, opt_ptr, protocol, header_len, checksum,
                                              source_port, dest_port, sequence_no, ack_no, window,
                                              payload_len)
                connections.remove(addr)
                self.fragments.clear()
                s.connect(addr)
                # Encrypt message if encrypt is enabled
                if self.encrypt:
                    nonce = nacl.utils.random(Box.NONCE_SIZE)
                    header = self.box.encrypt(header, nonce)
                s.send(header)
                print('closing connection')
