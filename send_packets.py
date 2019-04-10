# Function for Sending Packets
import socket
import binascii
import sctp
import time
from pycrate_asn1dir import S1AP
from pycrate_asn1rt.utils import *
from binascii import hexlify, unhexlify
from kamene.all import *
from kamene.contrib.gtp import *

#SCTP Server host and Port
#HOST = '127.0.0.1'
HOST = '172.24.253.34'
PORT = 36412

#Created PDU object of S1AP
PDU = S1AP.S1AP_PDU_Descriptions.S1AP_PDU

#Enabiling Heartbeat
ss = sctp.paddrparams.flags_HB_ENABLE
ss = 1

#Creating sctp socket
s = sctp.sctpsocket_tcp(socket.AF_INET)
s.initparams.max_instreams = 3
s.initparams.num_ostreams = 3

s.events.clear()
s.events.data_io = 1
s.connect((HOST, PORT))



#Setting Heartbeat interval
getpaddrObj = s.get_paddrparams(0, (HOST, PORT))
getpaddrObj.hbinterval = 1
s.set_paddrparams(getpaddrObj)

def send_s1aprequest(msg):
    if True:
        s.sctp_send(msg,ppid= 301989888)
        data = s.recv(1024)
        # if data:
        #     data_list = []
        #     data = hexlify(data)
        #     PDU.from_aper(unhexlify(data))
        #     try:
        #         IEs = get_val_at(PDU, ['successfulOutcome', 'value', 'S1SetupResponse', 'protocolIEs'])
        #         for ie in IEs:
        #             data_list.append(ie['value'])
        #         for key,value in data_list:
        #             print(key,value)
        #     except:
        #         print("wrong response s1aprequest")
        # else:
        #     pass

def send_initial_ue_message_attach(msg):
    if True:
        s.sctp_send(msg,ppid= 301989888)
        #comment for local testing
        data = s.recv(1024)
        if data:
            data_list = []
            data = hexlify(data)
            PDU.from_aper(unhexlify(data))
            try:
                IEs = get_val_at(PDU, ['initiatingMessage', 'value', 'DownlinkNASTransport', 'protocolIEs'])
                for ie in IEs:
                    data_list.append(ie['value'])
                for key,value in data_list:
                    print(key,value)
            except:
                print("wrong response initial_ue_message_attach")
        return data_list

def send_uplink_nas_transport_identity_response(msg):
    if True:
        s.sctp_send(msg,ppid= 301989888)



def send_uplink_nas_transport_esm_response(msg):
    if True:
        s.sctp_send(msg,ppid= 301989888)
        try:
            data = recv(1024)
        except:
            pass


def send_initial_context_setup_response(msg):
    if True:
        s.sctp_send(msg,ppid= 301989888)
        try:
            data = s.recv(1024)
        except:
            pass


def send_uplink_nas_transport_attach_complete(msg):
    if True:
        s.sctp_send(msg,ppid= 301989888)
        try:
            data = recv(1024)
        except:
            pass


def send_ue_context_release_request(msg):
    if True:
        s.sctp_send(msg,ppid= 301989888)
        try:
            data = recv(1024)
        except:
            pass

def send_ue_context_release_complete(msg):
    if True:
        s.sctp_send(msg,ppid= 301989888)
        try:
            data = recv(1024)
        except:
            pass


def send_initial_ue_message_tracking_area_update(msg):
    if True:
        s.sctp_send(msg,ppid= 301989888)
        data = s.recv(1024)
        if data:
            data_list = []
            data = hexlify(data)
            PDU.from_aper(unhexlify(data))
            print(PDU.to_asn1())
            try:
                IEs = get_val_at(PDU, ['initiatingMessage', 'value', 'DownlinkNASTransport', 'protocolIEs'])
                for ie in IEs:
                    data_list.append(ie['value'])
                for key,value in data_list:
                    print(key,value)
            except:
                print("wrong response")
        return data_list


def send_uplink_nas_transport_identity_response_location(msg):
    if True:
        s.sctp_send(msg,ppid= 301989888)
    #    data = s.recv(1024)

def send_uplink_nas_transport_tracking_area_complete(msg):
    if True:
        s.sctp_send(msg,ppid= 301989888)
        data = s.recv(1024)

def send_ue_location_context_release_complete(msg):
    if True:
        s.sctp_send(msg,ppid= 301989888)

def send_gtp_echo_request(msg):
    if True:
        send(msg)


def send_gtp_icmp_request(msg):
     if True:
         send(msg)
