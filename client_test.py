#!/usr/bin/env python3
import socket
import binascii
import sctp
import time
import ipaddress
import threading
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
# exit_time = int(config['ATTRIBUTE']['exit_time'])

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

class UE(AP):

    mme_ue_s1ap_id = 0
    mme_ue_s1ap_id_2 = 0
    imsi = 1030103254060
    GTP_TEID = 1234
    GTP_ICMP_ADDRESS = '172.86.2.15'
    UDP_IP_ADDRESS_SRC = '172.24.2.123'
    UDP_IP_ADDRESS_DST = '172.23.254.34'

    def ue_attach_and_release_request(self):
        #Sending InitialUEMessage, Attach request, PDN connectivity request Packet
        #Receving DownlinkNASTransport, Identity request
        self.msg = initial_ue_message_attach(self.cell_id,self.imsi)
        ap_socket.sctp_send(self.msg,ppid= 301989888)


    def ue_location_attach_and_release(self):
        # Sending, InitialMessage, Tracking area update request
        # Received DownlinkNASTransport, Identity request
        self.msg = initial_ue_message_tracking_area_update(self.cell_id)
        ap_socket.sctp_send(self.msg,ppid= 301989888)

imsi = 1030103254060
#imsi = 1030103254600
ap = AP(AP_Starting_No)
ap.s1_ap_request()
ue_list = []
for obj in range(Number_of_ue):
    obj = UE(ap.cell_id)
    obj.imsi = imsi
    imsi += 1
    ue_list.append(obj)

threads = []
for ue in ue_list:
    def ue_call(ue):
        ue.ue_attach_and_release_request()
        ue.ue_location_attach_and_release()
    threads.append(threading.Thread(target=ue_call(ue)))
    threads[-1].start()
    time.sleep(1)

for t in threads:
        t.join()
