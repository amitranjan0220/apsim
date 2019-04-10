#!/usr/bin/env python3

import socket
import sctp
import binascii
from pycrate_asn1dir import S1AP
from pycrate_asn1rt.utils import *
from binascii import hexlify, unhexlify

PDU = S1AP.S1AP_PDU_Descriptions.S1AP_PDU

# Listining ip and host
HOST = '127.0.0.1'
PORT = 36412
s1_setup_request =(b'\x00\x11\x00.\x00\x00\x04\x00;\x00\t\x00E\xf6B@\x80\x00\xc2@\x00<@\n\x03\x80ipaccess\x00@\x00\x07\x00\x00\x06\xc0E\xf6B\x00\x89@\x01@')
s1_setup_response=binascii.unhexlify(b'20110022000003003d400702004c544547570069000b000045f64200008701003000574001ff')

initial_ue_message_attach_request =(b"\x00\x0c@|\x00\x00\x06\x00\x08\x00\x02\x00\x01\x00\x1a\x00IH\x07Ar\x08\t\x100\x102T\x06\x00\x04\xe0`\xc0@\x00$\x02\x01\xd01\xd1'\x1d\x80\x80!\x10\x01\x00\x00\x10\x81\x06\x00\x00\x00\x00\x83\x06\x00\x00\x00\x00\x00\r\x00\x00\x03\x00\x00\n\x00\\\n\x001\x03\xe5\xe04\x90\x11\x03WX\xa6]\x01\x00\x00C\x00\x06\x00E\xf6B\x00\x1b\x00d@\x08\x00E\xf6B\x80\x00\xc2@\x00\x86@\x010\x00K@\x07\x00E\xf6B!\xfd0")
downlink_nas_transport_identity_request =binascii.unhexlify(b'000b4019000003000000048010001f000800020001001a000403075501')


# Ebabling Heartbeat
ss = sctp.paddrparams.flags_HB_ENABLE
ss = 1

# Creating Socket
s = sctp.sctpsocket_tcp(socket.AF_INET)
s.bind((HOST, PORT))
s.listen()


while True:
    conn, addr = s.accept()
    data = conn.recv(1024)
    if not data:
        break
    # #print('Received', repr(data))
    # elif data == s1_setup_request:
    #     print('Received',repr(data))
    #     conn.sendall(s1_setup_response)
    # elif data == initial_ue_message_attach_request:
    #     conn.sendall(downlink_nas_transport_identity_request)
    # else:
    #     print("no request")
