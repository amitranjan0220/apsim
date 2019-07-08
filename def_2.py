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
import threading
from threading import Thread

#Created PDU object of S1AP
PDU = S1AP.S1AP_PDU_Descriptions.S1AP_PDU

def mysocket():
    #Creating sctp socket
    mysocket = sctp.sctpsocket_tcp(socket.AF_INET)
    mysocket.initparams.max_instreams = 1
    mysocket.initparams.num_ostreams = 1
    mysocket.events.clear()
    mysocket.events.data_io = 1
    mysocket.connect((HOST, PORT))
    return mysocket


def ap_request(cell_id):
        msg = s1_setup_request(cell_id)
        ap_socket.sctp_send(msg,ppid= 301989888)
        print("ap cell_id={}".format(cell_id))
        data = ap_socket.recv(1024)
        return cell_id
        #time.sleep(1)

def ue_attach_and_release(ue_cell_id,imsi,enb_id,gtp_teid_icr):
        # mme_ue_s1ap_id = 1
        # GTP_TEID = 1234
        # GTP_ICMP_ADDRESS = '172.86.2.15'
        UDP_IP_ADDRESS_SRC = '172.24.2.123'
        # UDP_IP_ADDRESS_DST = '172.23.254.34'
        # tmsi =0xc0000fef

        #Sending InitialUEMessage, Attach request, PDN connectivity request Packet
        #Receving DownlinkNASTransport, Identity request
        msg= initial_ue_message_attach(ue_cell_id,imsi,enb_id)
        ap_socket.sctp_send(msg,ppid= 301989888)
        print("ue cell_id={}".format(cell_id))
        print("imsi={}".format(imsi))
        print("enb_id={}".format(enb_id))
        print("gtp_teid_icr={}".format(gtp_teid_icr))
        while True:
            data = ap_socket.recv(1024)
            data = hexlify(data)
            PDU.from_aper(unhexlify(data))
            if data:
                try:
                    IEs = get_val_at(PDU, ['initiatingMessage', 'value', 'DownlinkNASTransport', 'protocolIEs'])
                    mme_ue_s1ap_id = IEs[0]['value']
                    mme_ue_s1ap_id = mme_ue_s1ap_id[1]
                    break
                except:
                    pass
            else:
                print("no initial_ue_message_attach msg")
        #time.sleep(1)

        # Sending UplinkNASTransport, Identity response
        # Receving DownlinkNASTransport, ESM Information request
        msg = uplink_nas_transport_identity_response(ue_cell_id,mme_ue_s1ap_id,imsi,enb_id)
        ap_socket.sctp_send(msg,ppid= 301989888)
        while True:
            data = ap_socket.recv(1024)
            data = hexlify(data)
            PDU.from_aper(unhexlify(data))
            if data:
                try:
                    IEs = get_val_at(PDU, ['initiatingMessage', 'value', 'DownlinkNASTransport', 'protocolIEs'])
                    break
                except:
                    pass
            else:
                print("no initial_ue_message_attach msg")

        #time.sleep(1)
        # Sending UplinkNASTransport, ESM Information response
        # Receving  InitialContextSetupRequest, Attach accept, Activate default EPS bearer context request
        msg = uplink_nas_transport_esm_response(mme_ue_s1ap_id,ue_cell_id,enb_id)
        ap_socket.sctp_send(msg,ppid= 301989888)
        while True:
            data = ap_socket.recv(1024)
            data = hexlify(data)
            PDU.from_aper(unhexlify(data))
            if data:
                try:
                    IEs = get_val_at(PDU, ['initiatingMessage', 'value', 'InitialContextSetupRequest', 'protocolIEs'])
                    data = PDU.get_val_paths()
                    tl_addr = data[21]
                    tl_addr = tl_addr[-1]
                    tl_addr = tl_addr[0]
                    tl_addr = ipaddress.ip_address(tl_addr).__str__()
                    UDP_IP_ADDRESS_DST = tl_addr
                    print(UDP_IP_ADDRESS_DST)
                    gtp_teid = data[22]
                    gtp_teid = gtp_teid[-1]
                    gtp_teid = gtp_teid.hex()
                    GTP_TEID = int(gtp_teid,16)
                    print(GTP_TEID)
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
                    tmsi = gtp_ip[6]
                    gtp_ip = gtp_ip[5]
                    gtp_ip = gtp_ip['ESMActDefaultEPSBearerCtxtRequest'][3]
                    gtp_ip = gtp_ip.__getitem__(1)[2]
                    gtp_ip = gtp_ip.get_val()
                    gtp_ip = ipaddress.IPv4Address(gtp_ip)
                    gtp_ip = gtp_ip.__str__()
                    GTP_ICMP_ADDRESS =gtp_ip
                    tmsi = tmsi['EPSID'][6]
                    tmsi = tmsi.get_val()
                    tmsi = tmsi
                    print(GTP_ICMP_ADDRESS)
                    print(tmsi)
                    break
                except:
                    print("wrong response gtp")
            else:
                print("no uplink_nas_transport_esm_response")

        # time.sleep(1)
        # Sending InitialContextSetupResponse
        msg = initial_context_setup_response(mme_ue_s1ap_id,host_ip,gtp_teid_icr,enb_id)
        ap_socket.sctp_send(msg,ppid= 301989888)

        # time.sleep(1)
        # Sending UplinkNASTransport, Attach complete, Activate default EPS bearer context accept
        msg = uplink_nas_transport_attach_complete(mme_ue_s1ap_id,ue_cell_id,enb_id)
        ap_socket.sctp_send(msg,ppid= 301989888)

        #time.sleep(1)
        msg = gtp_echo_request(UDP_IP_ADDRESS_SRC,UDP_IP_ADDRESS_DST)
        send(msg)

        t_end = time.time() + delay_in_second
        while time.time() < t_end:
            msg =gtp_icmp_request(UDP_IP_ADDRESS_SRC,UDP_IP_ADDRESS_DST,GTP_ICMP_ADDRESS,GTP_TEID,data_in_bytes)
            send(msg)

        # Sending UEContextReleaseRequest [RadioNetwork-cause=user-inactivity]
        # Recieved UEContextReleaseCommand
        msg = ue_context_release_request(mme_ue_s1ap_id,enb_id)
        ap_socket.sctp_send(msg,ppid= 301989888)
        while True:
            data = ap_socket.recv(1024)
            data = hexlify(data)
            PDU.from_aper(unhexlify(data))
            if data:
                try:
                    IEs = get_val_at(PDU, ['initiatingMessage', 'value', 'UEContextReleaseCommand', 'protocolIEs'])
                    break
                except:
                    pass
            else:
                print("no uplink_nas_transport_tracking_area_complete msg")

        # time.sleep(1)
        # Sending UEContextReleaseComplete
        msg = ue_context_release_complete(mme_ue_s1ap_id,enb_id)
        ap_socket.sctp_send(msg,ppid= 301989888)
        # time.sleep(1)
        return imsi, enb_id, tmsi

def ue_location_attach_and_release(ue_cell_id,ue_imsi, ue_enb_id, ue_tmsi):
    #mme_ue_s1ap_id_2 = 0
    # Sending, InitialMessage, Tracking area update request
    # Received DownlinkNASTransport, Identity request
    msg = initial_ue_message_tracking_area_update(ue_cell_id,ue_tmsi,ue_enb_id)
    ap_socket.sctp_send(msg,ppid= 301989888)
    while True:
        data = ap_socket.recv(1024)
        data = hexlify(data)
        PDU.from_aper(unhexlify(data))
        if data:
            try:
                IEs = get_val_at(PDU, ['initiatingMessage', 'value', 'DownlinkNASTransport', 'protocolIEs'])
                mme_ue_s1ap_id_2 = IEs[0]['value']
                mme_ue_s1ap_id_2 = mme_ue_s1ap_id_2[1]
                break
            except:
                pass
        else:
            print("no ue_location_attach_and_release msg")

    # time.sleep(1)
    # Sending UplinkNASTransport,Identity response
    # Receving DownlinkNASTransport, Tracking area upadate accept
    msg = uplink_nas_transport_identity_response_location(ue_cell_id,mme_ue_s1ap_id_2,ue_imsi,ue_enb_id)
    ap_socket.sctp_send(msg,ppid= 301989888)
    while True:
        data = ap_socket.recv(1024)
        data = hexlify(data)
        PDU.from_aper(unhexlify(data))
        if data:
            try:
                IEs = get_val_at(PDU, ['initiatingMessage', 'value', 'DownlinkNASTransport', 'protocolIEs'])
                break
            except:
                pass
        else:
            print("no uplink_nas_transport_identity_response_location msg")

    # time.sleep(1)
    #Sending UplinkNASTransport,Tracking area update complete
    #Recieved UEContextReleaseCommand
    msg =uplink_nas_transport_tracking_area_complete(ue_cell_id,mme_ue_s1ap_id_2,ue_enb_id)
    ap_socket.sctp_send(msg,ppid= 301989888)
    while True:
        data = ap_socket.recv(1024)
        data = hexlify(data)
        PDU.from_aper(unhexlify(data))
        if data:
            try:
                IEs = get_val_at(PDU, ['initiatingMessage', 'value', 'UEContextReleaseCommand', 'protocolIEs'])
                break
            except:
                pass
        else:
            print("no uplink_nas_transport_tracking_area_complete msg")

    # time.sleep(1)
    #Sending UEContextReleaseComplete
    msg = ue_location_context_release_complete(mme_ue_s1ap_id_2,ue_enb_id)
    ap_socket.sctp_send(msg,ppid= 301989888)


def main(loop_limit,imsi_2,enb_id_2,gtp_teid_icr_2):
    time.sleep(1)
    while loop_limit > 0:
        ue_imsi, ue_enb_id, ue_tmsi = ue_attach_and_release(ue_cell_id,imsi_2,enb_id_2,gtp_teid_icr_2)
        ue_location_attach_and_release(ue_cell_id,ue_imsi, ue_enb_id, ue_tmsi)
        loop_limit -= 1

if __name__ == '__main__':
    # Getting input data for request_parameter.txt
    config = configparser.ConfigParser()
    configFilePath = r'/home/amit/Documents/simulator/apsim/parameter.txt'
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
    loop_limit = int(config['ATTRIBUTE']['loop_limit'])
    enb_id = 1
    gtp_teid_icr = 33558538

    HOST = server_ip
    PORT = int(server_port)
    SRC_HOST = host_ip

    num_processes = 1
    processes = []
    processes_1 = []
    reset_no = 0

    for ap in range(Number_of_ap):
        ap_socket = mysocket()
        p_1 = Process(target=ap_request, args=(cell_id,))
        processes_1.append(p_1)
        p_1.start()
        ue_cell_id = cell_id
        imsi += reset_no
        enb_id += reset_no
        gtp_teid_icr += reset_no
        imsi_2 = imsi
        enb_id_2 = enb_id
        gtp_teid_icr_2 = gtp_teid_icr

        for ue in range(Number_of_ue):
            process_name = "Started Process {}".format(num_processes)
            q = Queue()
            p = Process(target=main, args=(loop_limit,imsi_2,enb_id_2,gtp_teid_icr_2), name=process_name)
            imsi_2 += 1
            enb_id_2 += 1
            gtp_teid_icr_2 += 1
            num_processes = num_processes + 1
            # processes.append(p)
            p.start()
            print(process_name)

        reset_no = Number_of_ue
        cell_id += 1
        time.sleep(1)
    for p in processes_1:
        p.join()
