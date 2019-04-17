#!/usr/bin/env python3
import socket
import binascii
import sctp
import time
import ipaddress
from pycrate_mobile.NAS import *
from packets import *
from kamene.all import *
from kamene.contrib.gtp import *
from six.moves import configparser

# Getting input data for request_parameter.txt
config = configparser.ConfigParser()
configFilePath = r'/home/amit/Documents/simulator/Apsim/parameter.txt'
config.read(configFilePath)
config.sections()
server_ip = config['SERVER']['server_ip']
host_ip = config['SERVER']['host_ip']
server_port = config['SERVER']['server_port']
AP_Starting_No = int(config['ATTRIBUTE']['AP_Starting_No'])
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

#Enabiling Heartbeat
socket_hb = sctp.paddrparams.flags_HB_ENABLE
socket_hb = 1

#Creating sctp socket
ap_socket = sctp.sctpsocket_tcp(socket.AF_INET)
ap_socket.initparams.max_instreams = 1
ap_socket.initparams.num_ostreams = 1

ap_socket.events.clear()
ap_socket.events.data_io = 1
ap_socket.connect((HOST, PORT))

#Setting Heartbeat interval
getpaddrObj = ap_socket.get_paddrparams(0, (HOST, PORT))
getpaddrObj.hbinterval = 1
ap_socket.set_paddrparams(getpaddrObj)

class AP():

    def __init__(self,cell_id):
        self.cell_id = cell_id;

    def s1_ap_request(self):
        self.msg = s1_setup_request(self.cell_id)
        ap_socket.sctp_send(self.msg,ppid= 301989888)
        data = ap_socket.recv(1024)

class UE(AP):

    mme_ue_s1ap_id = 0
    mme_ue_s1ap_id_2 = 0
    imsi = 1030103254060
    GTP_TEID = 1234
    GTP_ICMP_ADDRESS = '172.86.2.15'
    UDP_IP_ADDRESS_SRC = '172.24.2.123'
    UDP_IP_ADDRESS_DST = '172.23.254.34'

    def ue_attach_and_release_request(self):
        data_list = []
        #Sending InitialUEMessage, Attach request, PDN connectivity request Packet
        #Receving DownlinkNASTransport, Identity request
        self.msg = initial_ue_message_attach(self.cell_id,self.imsi)
        ap_socket.sctp_send(self.msg,ppid= 301989888)
        data = ap_socket.recv(1024)
        if data:
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
                print("wrong response initial_ue_message_attach")
        data_dic = dict(data_list)
        self.mme_ue_s1ap_id = (data_dic["MME-UE-S1AP-ID"])
        #self.mme_ue_s1ap_id = 2000
        time.sleep(1)

        # Sending UplinkNASTransport, Identity response
        # Receving DownlinkNASTransport, ESM Information request
        self.msg = uplink_nas_transport_identity_response(self.cell_id,self.mme_ue_s1ap_id)
        ap_socket.sctp_send(self.msg,ppid= 301989888)
        data = ap_socket.recv(1024)
        time.sleep(1)

        # Sending UplinkNASTransport, ESM Information response
        # Receving  InitialContextSetupRequest, Attach accept, Activate default EPS bearer context request
        self.msg = uplink_nas_transport_esm_response(self.mme_ue_s1ap_id,self.cell_id)
        ap_socket.sctp_send(self.msg,ppid= 301989888)
        time.sleep(1)
        data = ap_socket.recv(1024)
        data = hexlify(data)
        PDU.from_aper(unhexlify(data))
        print(PDU.to_asn1())
        try:
            IEs = get_val_at(PDU, ['initiatingMessage', 'value', 'InitialContextSetupRequest', 'protocolIEs'])
            data = PDU.get_val_paths()
            data
            tl_addr = data[21]
            tl_addr = tl_addr[-1]
            tl_addr = tl_addr[0]
            tl_addr = ipaddress.ip_address(tl_addr).__str__()
            self.UDP_IP_ADDRESS_DST = tl_addr
            print(self.UDP_IP_ADDRESS_DST)
            gtp_teid = data[22]
            gtp_teid = gtp_teid[-1]
            gtp_teid = gtp_teid.hex()
            self.GTP_TEID = int(gtp_teid,16)
            print(self.GTP_TEID)
            gtp_ip = data[23]
            gtp_ip = gtp_ip[1]
            gtp_ip = hexlify(gtp_ip)
            gtp_ip = parse_NAS_MO(unhexlify(gtp_ip))
            gtp_ip = gtp_ip.__getitem__(0)
            gtp_ip = gtp_ip.get_val()
            gtp_ip = gtp_ip.__getitem__(3)
            gtp_ip = hexlify(gtp_ip)
            gtp_ip = parse_NAS_MO(unhexlify(gtp_ip))
            gtp_ip = gtp_ip.__getitem__(0)
            gtp_ip = gtp_ip[5]
            gtp_ip = gtp_ip['ESMActDefaultEPSBearerCtxtRequest'][3]
            gtp_ip = gtp_ip.__getitem__(1)[2]
            gtp_ip = gtp_ip.get_val()
            gtp_ip = ipaddress.IPv4Address(gtp_ip)
            gtp_ip = gtp_ip.__str__()
            self.GTP_ICMP_ADDRESS =gtp_ip
            print(self.GTP_ICMP_ADDRESS)
        except:
            print("wrong response gtp")


        # Sending InitialContextSetupResponse
        self.msg = initial_context_setup_response(self.mme_ue_s1ap_id)
        ap_socket.sctp_send(self.msg,ppid= 301989888)
        data = ap_socket.recv(1024)
        time.sleep(1)

        # Sending UplinkNASTransport, Attach complete, Activate default EPS bearer context accept
        self.msg = uplink_nas_transport_attach_complete(self.mme_ue_s1ap_id,self.cell_id)
        ap_socket.sctp_send(self.msg,ppid= 301989888)
    #    data = s.recv(1024)
        time.sleep(1)


        self.msg = gtp_echo_request(self.UDP_IP_ADDRESS_SRC,self.UDP_IP_ADDRESS_DST)
        send(self.msg)

        t_end = time.time() + delay_in_second
        while time.time() < t_end:
            self.msg =gtp_icmp_request(self.UDP_IP_ADDRESS_SRC,self.UDP_IP_ADDRESS_DST,self.GTP_ICMP_ADDRESS,self.GTP_TEID,data_in_bytes)
            send(self.msg)

        # Sending UEContextReleaseRequest [RadioNetwork-cause=user-inactivity]
        # Recieved UEContextReleaseCommand
        self.msg = ue_context_release_request(self.mme_ue_s1ap_id)
        ap_socket.sctp_send(self.msg,ppid= 301989888)
        data = ap_socket.recv(1024)
        time.sleep(1)

        # Sending UEContextReleaseComplete
        self.msg = ue_context_release_complete(self.mme_ue_s1ap_id)
        ap_socket.sctp_send(self.msg,ppid= 301989888)
        # data = s.recv(1024)
        time.sleep(1)

    def ue_location_attach_and_release(self):
        data_list_2 = []
        # Sending, InitialMessage, Tracking area update request
        # Received DownlinkNASTransport, Identity request
        self.msg = initial_ue_message_tracking_area_update(self.cell_id)
        # try:
        #     data = ap_socket.recv(1024)
        # except:
        #     pass
        ap_socket.sctp_send(self.msg,ppid= 301989888)
        data = ap_socket.recv(1024)
        if data:
            data = hexlify(data)
            PDU.from_aper(unhexlify(data))
            print(PDU.to_asn1())
            try:
                IEs = get_val_at(PDU, ['initiatingMessage', 'value', 'DownlinkNASTransport', 'protocolIEs'])
                for ie in IEs:
                    data_list_2.append(ie['value'])
                for key,value in data_list_2:
                    print(key,value)
            except:
                print("wrong response")
        data_dic =dict(data_list_2)
        self.mme_ue_s1ap_id_2 = (data_dic["MME-UE-S1AP-ID"])
        #self.mme_ue_s1ap_id_2 = 2000
        time.sleep(1)

        # Sending UplinkNASTransport,Identity response
        # Receving DownlinkNASTransport, Tracking area upadate accept
        self.msg = uplink_nas_transport_identity_response_location(self.cell_id,self.mme_ue_s1ap_id_2)
        ap_socket.sctp_send(self.msg,ppid= 301989888)
        try:
            data = ap_socket.recv(1024)
        except:
            pass
        time.sleep(1)

        #Sending UplinkNASTransport,Tracking area update complete
        #Recieved UEContextReleaseCommand
        self.msg =uplink_nas_transport_tracking_area_complete(self.cell_id,self.mme_ue_s1ap_id_2)
        ap_socket.sctp_send(self.msg,ppid= 301989888)
        try:
            data = ap_socket.recv(1024)
        except:
            pass
        time.sleep(1)

        #Sending UEContextReleaseComplete
        self.msg = ue_location_context_release_complete(self.mme_ue_s1ap_id_2)
        ap_socket.sctp_send(self.msg,ppid= 301989888)
        time.sleep(1)
        try:
            data = ap_socket.recv(1024)
        except:
            pass


ap = AP(AP_Starting_No)
ap.s1_ap_request()
ue_list = []
for obj in range(Number_of_ue):
    obj = UE(ap.cell_id)
    obj.imsi = imsi
    imsi += 1
    ue_list.append(obj)

for ue in ue_list:
    ue.ue_attach_and_release_request()
    ue.ue_location_attach_and_release()
    time.sleep(1)
