import binascii
import socket as syssock
import struct
import sys
import time
import random

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
def init(UDPportTx,UDPportRx):   # initialize your UDP socket here 
    global Tx, Rx, s, connections
    Tx = UDPportTx
    Rx = UDPportRx
    s = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)
    s.bind(('localhost', int(Rx)))    
    connections = []
    return
    
class socket:
    
    def __init__(self): 
        fragments = []
        return
    
    def bind(self,address):
        return 

    def connect(self,address):
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
        s.connect((destination, int(Tx)))
        print('Trying to connect w/ server..')
        
        # Send SYN flagged header to server and receive the server's response and check to see if SYN/ACK
        # If the server had another response, resend the packet        
        while flags != SOCK352_SYN + SOCK352_ACK:
            s.send(header)
            receivedHeader = s.recv(header_len)
            (version, flags, opt_ptr, protocol, header_len, checksum,
            source_port, dest_port, sequence_no, ack_no, window, 
            payload_len) = udpPkt_hdr_data.unpack(receivedHeader)
        print('test')
        
        # After receiving SYN/ACK from server, send ACK
        flags = SOCK352_ACK
        temp = sequence_no
        sequence_no = ack_no
        ack_no = temp + 1
        header = udpPkt_hdr_data.pack(version, flags, opt_ptr, protocol, header_len, checksum,
                                      source_port, dest_port, sequence_no, ack_no, window, 
                                      payload_len) 
        s.send(header)
        return 
    
    def listen(self,backlog):
        return

    def accept(self):
        # Wait to receive header data
        print('waiting for connection...')
       
        (clientsocket,address) =  self.__sock352_get_packet()
        print(address)
        return (clientsocket,address)
    
    def close(self):   # fill in your code here 
        return 

    def send(self,buffer):
        bytessent = 0     # fill in your code here 
        return bytessent 

    def recv(self,nbytes):
        bytesreceived = 0     # fill in your code here
        return bytesreceived 


    def  __sock352_get_packet(self):
        global version, opt_ptr, protocol, header_len, checksum, source_port, dest_port, window
        
        # Receive and unpack the data        
        (header, addr) = s.recvfrom(header_len)
        sock352PktHdrData = '!BBBBHHLLQQLL'
        udpPkt_hdr_data = struct.Struct(sock352PktHdrData)
        (version, flags, opt_ptr, protocol, header_len, checksum,
        source_port, dest_port, sequence_no, ack_no, window, 
        payload_len) = udpPkt_hdr_data.unpack(header)
        
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
                # Close out intial server socket b/c you can't have multiple 
                # sockets connected to one address (I think this is only for Part 1)
                s.close()
                s2 = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)
                s2.bind (('localhost', int(Rx)))
                s2.connect(addr)
                
                # Send out the SYN/ACK flagged header, and wait for 
                # ACK response from client
                while flags != SOCK352_ACK:
                    s2.send(header)
                    receivedHeader = s2.recv(header_len)
                    (version, flags, opt_ptr, protocol, header_len, checksum,
                     source_port, dest_port, sequence_no, ack_no, window, 
                     payload_len) = udpPkt_hdr_data.unpack(receivedHeader) 
                print('Connected')
                return (s2, addr)
            # If it is in the list, the connection is reset
            else:
                sequence_no = sequence_no + 1
                flags = SOCK352_RESET
                header = udpPkt_hdr_data.pack(version, flags, opt_ptr, protocol, header_len, checksum,
                                              source_port, dest_port, sequence_no, ack_no, window, 
                                              payload_len)
                s.connect(addr)
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
                s.send(header)
                print('closing connection')
            # If it's not a SYN or FIN flagged packet, check the seq_no
            # to see if it's the right seq_no
            else:   
                pass