#!/usr/bin/env python3
import socket
import binascii
import sctp
import time
import ipaddress
from pycrate_asn1dir import S1AP
from pycrate_mobile.NAS import *
from packets import *
from kamene.all import *
from kamene.contrib.gtp import *
from six.moves import configparser
from multiprocessing import Process, Queue
from threading import Thread
import threading

# Getting input data for request_parameter.txt
config = configparser.ConfigParser()
configFilePath = r'/home/amit/Documents/simulator/Apsim/parameter.txt'
config.read(configFilePath)
config.sections()
server_ip = config['SERVER']['server_ip']
host_ip = config['SERVER']['host_ip']
server_port = config['SERVER']['server_port']
cell_id = int(config['ATTRIBUTE']['cell_id'])
Number_of_ap = int(config['ATTRIBUTE']['Number_of_ap'])
Number_of_ue = int(config['ATTRIBUTE']['Number_of_ue'])
delay_in_second = int(config['ATTRIBUTE']['delay_in_second'])
data_in_bytes = config['ATTRIBUTE']['data_in_bytes']
imsi = int(config['ATTRIBUTE']['imsi'])

#SCTP Server host and Port
#HOST = '127.0.0.1'
HOST = server_ip
PORT = int(server_port)
SRC_HOST = host_ip

#Created PDU object of S1AP
PDU = S1AP.S1AP_PDU_Descriptions.S1AP_PDU

def my_socket():
    ap_socket = sctp.sctpsocket_tcp(socket.AF_INET)
    ap_socket.initparams.max_instreams = 1
    ap_socket.initparams.num_ostreams = 1
    ap_socket.events.clear()
    ap_socket.events.data_io = 1
    ap_socket.connect((HOST, PORT))
    return ap_socket


class AP():

    def __init__(self,cell_id):
        self.cell_id = cell_id;

    def s1_ap_request(self):

        self.msg = s1_setup_request(self.cell_id)
        ap_socket.sctp_send(self.msg,ppid= 301989888)
        self.data = ap_socket.recv(1024)

class UE(Thread):

    def __init__(self,cell_id,imsi,enb_id,gtp_teid_icr):
        Thread.__init__(self)
        self.cell_id = cell_id;
        self.imsi = imsi;
        self.enb_id = enb_id;
        self.gtp_teid_icr = gtp_teid_icr;
        self.tmsi = 0xc0000fef;
        #self.mme_ue_s1ap_id = 1;
        #self.mme_ue_s1ap_id_2 = 1;
        self.GTP_TEID = 1234;
        self.GTP_ICMP_ADDRESS = '172.86.2.15';
        self.UDP_IP_ADDRESS_SRC = '172.24.2.123';
        self.UDP_IP_ADDRESS_DST = '172.23.254.34';


    def ue_attach_and_release(self):
            mme = {}
            #Sending InitialUEMessage, Attach request, PDN connectivity request Packet
            #Receving DownlinkNASTransport, Identity request
            self.msg= initial_ue_message_attach(self.cell_id,self.imsi,self.enb_id)
            ap_socket.sctp_send(self.msg,ppid= 301989888)
            while True:
                self.data = ap_socket.recv(1024)
                self.data = hexlify(self.data)
                PDU.from_aper(unhexlify(self.data))
                if self.data:
                    try:
                        self.IEs = get_val_at(PDU, ['initiatingMessage', 'value', 'DownlinkNASTransport', 'protocolIEs'])
                        self.mme_ue_s1ap_id = self.IEs[0]['value']
                        self.mme_ue_s1ap_id = self.mme_ue_s1ap_id[1]
                        break
                    except:
                        pass
                else:
                    print("no initial_ue_message_attach msg")


            # Sending UplinkNASTransport, Identity response
            # Receving DownlinkNASTransport, ESM Information request
            self.msg = uplink_nas_transport_identity_response(self.cell_id,self.mme_ue_s1ap_id,self.imsi,self.enb_id)
            ap_socket.sctp_send(self.msg,ppid= 301989888)
            while True:
                self.data = ap_socket.recv(1024)
                self.data = hexlify(self.data)
                PDU.from_aper(unhexlify(self.data))
                if self.data:
                    try:
                        self.IEs = get_val_at(PDU, ['initiatingMessage', 'value', 'DownlinkNASTransport', 'protocolIEs'])
                        break
                    except:
                        pass
                else:
                    print("no initial_ue_message_attach msg")


            # Sending UplinkNASTransport, ESM Information response
            # Receving  InitialContextSetupRequest, Attach accept, Activate default EPS bearer context request
            self.msg = uplink_nas_transport_esm_response(self.mme_ue_s1ap_id,self.cell_id,self.enb_id)
            ap_socket.sctp_send(self.msg,ppid= 301989888)
            while True:
                self.data = ap_socket.recv(1024)
                self.data = hexlify(self.data)
                PDU.from_aper(unhexlify(self.data))
                if self.data:
                    try:
                        self.IEs = get_val_at(PDU, ['initiatingMessage', 'value', 'InitialContextSetupRequest', 'protocolIEs'])
                        self.data = PDU.get_val_paths()
                        self.tl_addr = self.data[21]
                        self.tl_addr = self.tl_addr[-1]
                        self.tl_addr = self.tl_addr[0]
                        self.tl_addr = ipaddress.ip_address(self.tl_addr).__str__()
                        self.UDP_IP_ADDRESS_DST = self.tl_addr
                        print("OK")
                        #print(UDP_IP_ADDRESS_DST)
                        self.gtp_teid = self.data[22]
                        self.gtp_teid = self.gtp_teid[-1]
                        self.gtp_teid = self.gtp_teid.hex()
                        self.GTP_TEID = int(self.gtp_teid,16)
                        print("OK")
                        #print(GTP_TEID)
                        self.gtp_ip = self.data[23]
                        self.gtp_ip = self.gtp_ip[1]
                        self.gtp_ip = hexlify(self.gtp_ip)
                        self.gtp_ip = parse_NAS_MO(unhexlify(self.gtp_ip))
                        self.gtp_ip = self.gtp_ip.__getitem__(0)
                        self.gtp_ip = self.gtp_ip.get_val()
                        self.gtp_ip = self.gtp_ip.__getitem__(3)
                        self.gtp_ip = hexlify(self.gtp_ip)
                        self.gtp_ip = parse_NAS_MO(unhexlify(self.gtp_ip))
                        self.gtp_ip = self.gtp_ip.__getitem__(0)
                        self.tmsi = self.gtp_ip[6]
                        self.gtp_ip = self.gtp_ip[5]
                        self.gtp_ip = self.gtp_ip['ESMActDefaultEPSBearerCtxtRequest'][3]
                        self.gtp_ip = self.gtp_ip.__getitem__(1)[2]
                        self.gtp_ip = self.gtp_ip.get_val()
                        self.gtp_ip = ipaddress.IPv4Address(self.gtp_ip)
                        self.gtp_ip = self.gtp_ip.__str__()
                        self.GTP_ICMP_ADDRESS = self.gtp_ip
                        self.tmsi = self.tmsi['EPSID'][6]
                        self.tmsi = self.tmsi.get_val()
                        print("OOK")
                        break
                    except:
                        print("wrong response gtp")
                else:
                    print("no uplink_nas_transport_esm_response")

        #    time.sleep(1)
            # Sending InitialContextSetupResponse
            self.msg = initial_context_setup_response(self.mme_ue_s1ap_id,host_ip,self.gtp_teid_icr,self.enb_id)
            ap_socket.sctp_send(self.msg,ppid= 301989888)

            #time.sleep(1)
            # Sending UplinkNASTransport, Attach complete, Activate default EPS bearer context accept
            self.msg = uplink_nas_transport_attach_complete(self.mme_ue_s1ap_id,self.cell_id,self.enb_id)
            ap_socket.sctp_send(self.msg,ppid= 301989888)

            #time.sleep(1)
            self.msg = gtp_echo_request(self.UDP_IP_ADDRESS_SRC,self.UDP_IP_ADDRESS_DST)
            send(self.msg)

            t_end = time.time() + delay_in_second
            while time.time() < t_end:
                self.msg =gtp_icmp_request(self.UDP_IP_ADDRESS_SRC,self.UDP_IP_ADDRESS_DST,self.GTP_ICMP_ADDRESS,self.GTP_TEID,data_in_bytes)
                send(self.msg)

            # Sending UEContextReleaseRequest [RadioNetwork-cause=user-inactivity]
            # Recieved UEContextReleaseCommand
            self.msg = ue_context_release_request(self.mme_ue_s1ap_id,self.enb_id)
            ap_socket.sctp_send(self.msg,ppid= 301989888)
            while True:
                self.data = ap_socket.recv(1024)
                self.data = hexlify(self.data)
                PDU.from_aper(unhexlify(self.data))
                if self.data:
                    try:
                        self.IEs = get_val_at(PDU, ['initiatingMessage', 'value', 'UEContextReleaseCommand', 'protocolIEs'])
                        break
                    except:
                        pass
                else:
                    print("no uplink_nas_transport_tracking_area_complete msg")

            #time.sleep(1)
            # Sending UEContextReleaseComplete
            self.msg = ue_context_release_complete(self.mme_ue_s1ap_id,self.enb_id)
            ap_socket.sctp_send(self.msg,ppid= 301989888)
            #time.sleep(1)


            # mme_ue_s1ap_id_2 = 0
            # Sending, InitialMessage, Tracking area update request
            # Received DownlinkNASTransport, Identity request
            self.msg = initial_ue_message_tracking_area_update(self.cell_id,self.tmsi,self.enb_id)
            ap_socket.sctp_send(self.msg,ppid= 301989888)
            while True:
                self.data = ap_socket.recv(1024)
                self.data = hexlify(self.data)
                PDU.from_aper(unhexlify(self.data))
                if self.data:
                    try:
                        self.IEs = get_val_at(PDU, ['initiatingMessage', 'value', 'DownlinkNASTransport', 'protocolIEs'])
                        self.mme_ue_s1ap_id_2 = self.IEs[0]['value']
                        self.mme_ue_s1ap_id_2 =self.mme_ue_s1ap_id_2[1]
                        break
                    except:
                        pass
                else:
                    print("no ue_location_attach_and_release msg")

        #    time.sleep(1)
            # Sending UplinkNASTransport,Identity response
            # Receving DownlinkNASTransport, Tracking area upadate accept
            self.msg = uplink_nas_transport_identity_response_location(self.cell_id,self.mme_ue_s1ap_id_2,self.imsi,self.enb_id)
            ap_socket.sctp_send(self.msg,ppid= 301989888)
            while True:
                self.data = ap_socket.recv(1024)
                self.data = hexlify(self.data)
                PDU.from_aper(unhexlify(self.data))
                if self.data:
                    try:
                        self.IEs = get_val_at(PDU, ['initiatingMessage', 'value', 'DownlinkNASTransport', 'protocolIEs'])
                        break
                    except:
                        pass
                else:
                    print("no uplink_nas_transport_identity_response_location msg")

            #time.sleep(1)
            #Sending UplinkNASTransport,Tracking area update complete
            #Recieved UEContextReleaseCommand
            self.msg =uplink_nas_transport_tracking_area_complete(self.cell_id,self.mme_ue_s1ap_id_2,self.enb_id)
            ap_socket.sctp_send(self.msg,ppid= 301989888)
            while True:
                self.data = ap_socket.recv(1024)
                self.data = hexlify(self.data)
                PDU.from_aper(unhexlify(self.data))
                if self.data:
                    try:
                        self.IEs = get_val_at(PDU, ['initiatingMessage', 'value', 'UEContextReleaseCommand', 'protocolIEs'])
                        break
                    except:
                        pass
                else:
                    print("no uplink_nas_transport_tracking_area_complete msg")

            #time.sleep(1)
            #Sending UEContextReleaseComplete
            self.msg = ue_location_context_release_complete(self.mme_ue_s1ap_id_2,self.enb_id)
            ap_socket.sctp_send(self.msg,ppid= 301989888)

    def run(self):
        processes_1 = []
        p_1 = Process(target=self.ue_attach_and_release())
        processes_1.append(p_1)
        for p_1 in processes_1:
            p_1.join()


if __name__ == '__main__':

    num_processes = 1
    processes = []

    enb_id = 1
    gtp_teid_icr = 33558538

    for ap in range(Number_of_ap):
        process_name = "Started Process {}".format(num_processes)
        q = Queue()
        ap_socket = my_socket()
        print(cell_id)
        ap = AP(cell_id)
        p = Process(target=ap.s1_ap_request(),  name=process_name)
        processes.append(p)
        p.start()
        print(process_name)
        num_processes = num_processes + 1

        for ue in range(Number_of_ue):
            ue = UE(ap.cell_id,imsi,enb_id,gtp_teid_icr)
            ue.start()
            imsi += 1
            enb_id += 1
            gtp_teid_icr += 1
            print(ap.cell_id)
            print(imsi)
            print(enb_id)
            print(gtp_teid_icr)

        cell_id += 1

    for p in processes:
        p.join()
