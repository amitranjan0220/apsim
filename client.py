#!/usr/bin/env python3
import socket
import binascii
import sctp
import time
from packets import *
from send_packets import *
from kamene.all import *
from kamene.contrib.gtp import *


class ApSimulator:
    mme_ue_s1ap_id = 0;
    mme_ue_s1ap_id_2 = 0;

    def __init__(self,cell_id):
        self.cell_id = cell_id;
        self.s1aprequest = s1_setup_request(self.cell_id)
        send_s1aprequest(self.s1aprequest)

    #def send_s1aprequest(self):

    def ue_attach_and_release_request(self):
        # Sending InitialUEMessage, Attach request, PDN connectivity request Packet
        # Receving DownlinkNASTransport, Identity request
        self.initial_ue_message_attach = initial_ue_message_attach(self.cell_id)
        data_list = send_initial_ue_message_attach(self.initial_ue_message_attach)
        data_dic = dict(data_list)
        self.mme_ue_s1ap_id = (data_dic["MME-UE-S1AP-ID"])
        #self.mme_ue_s1ap_id = 2000
        time.sleep(1)

        # Sending UplinkNASTransport, Identity response
        # Receving DownlinkNASTransport, ESM Information request
        self.uplink_nas_transport_identity_response = uplink_nas_transport_identity_response(self.cell_id,self.mme_ue_s1ap_id)
        send_uplink_nas_transport_identity_response(self.uplink_nas_transport_identity_response)
        time.sleep(1)

        # Sending UplinkNASTransport, ESM Information response
        # Receving  InitialContextSetupRequest, Attach accept, Activate default EPS bearer context request
        self.uplink_nas_transport_esm_response = uplink_nas_transport_esm_response(self.mme_ue_s1ap_id,self.cell_id)
        send_uplink_nas_transport_esm_response(self.uplink_nas_transport_esm_response)
        time.sleep(1)

        # Sending InitialContextSetupResponse
        self.initial_context_setup_response = initial_context_setup_response(self.mme_ue_s1ap_id)
        send_initial_context_setup_response(self.initial_context_setup_response)
        time.sleep(1)

        # Sending UplinkNASTransport, Attach complete, Activate default EPS bearer context accept
        self.uplink_nas_transport_attach_complete = uplink_nas_transport_attach_complete(self.mme_ue_s1ap_id,self.cell_id)
        send_uplink_nas_transport_attach_complete(self.uplink_nas_transport_attach_complete)
        time.sleep(1)

        # Sending UEContextReleaseRequest [RadioNetwork-cause=user-inactivity]
        # Recieved UEContextReleaseCommand
        self.ue_context_release_request = ue_context_release_request(self.mme_ue_s1ap_id)
        send_ue_context_release_request(self.ue_context_release_request)
        time.sleep(1)

        # Sending UEContextReleaseComplete
        self.ue_context_release_complete = ue_context_release_complete(self.mme_ue_s1ap_id)
        send_ue_context_release_complete(self.ue_context_release_complete)
        self.mme_ue_s1ap_id = 0
        time.sleep(1)

    def ue_location_attach_and_release(self):
        # Sending, InitialMessage, Tracking area update request
        # Received DownlinkNASTransport, Identity request
        self.initial_ue_message_tracking_area_update = initial_ue_message_tracking_area_update(self.cell_id)
        data_list_2 = send_initial_ue_message_tracking_area_update(self.initial_ue_message_tracking_area_update)
        data_dic =dict(data_list_2)
        self.mme_ue_s1ap_id_2 = (data_dic["MME-UE-S1AP-ID"])
        #self.mme_ue_s1ap_id_2 = 2000
        time.sleep(1)

        # Sending UplinkNASTransport,Identity response
        # Receving DownlinkNASTransport, Tracking area upadate accept
        self.uplink_nas_transport_identity_response_location = uplink_nas_transport_identity_response_location(self.cell_id,self.mme_ue_s1ap_id_2)
        send_uplink_nas_transport_identity_response_location(self.uplink_nas_transport_identity_response_location)
        time.sleep(1)

        #Sending UplinkNASTransport,Tracking area update complete
        #Recieved UEContextReleaseCommand
        self.uplink_nas_transport_tracking_area_complete =uplink_nas_transport_tracking_area_complete(self.cell_id,self.mme_ue_s1ap_id_2)
        send_uplink_nas_transport_tracking_area_complete(self.uplink_nas_transport_tracking_area_complete)
        time.sleep(1)

        #Sending UEContextReleaseComplete
        self.ue_location_context_release_complete = ue_location_context_release_complete(self.mme_ue_s1ap_id_2)
        send_ue_location_context_release_complete(self.ue_location_context_release_complete)
        time.sleep(1)

    def gtp_echo_request_packet(self):
        self.gtp_echo_request = gtp_echo_request(UDP_IP_ADDRESS_SRC,UDP_IP_ADDRESS_DST)
        send_gtp_echo_request(self.gtp_echo_request)

    def gtp_icmp_data(self):
        self.gtp_icmp_request =gtp_icmp_request(UDP_IP_ADDRESS_SRC,UDP_IP_ADDRESS_DST,GTP_ICMP_ADDRESS)
        send_gtp_icmp_request(self.gtp_icmp_request)

if __name__ == '__main__':

    UDP_IP_ADDRESS_SRC = '172.24.2.123'
    UDP_IP_ADDRESS_DST = '172.24.2.51'
    GTP_ICMP_ADDRESS = '172.86.2.15'

    #UDP_IP_ADDRESS_SRC = "127.0.0.1"
    #UDP_IP_ADDRESS_DST = "127.0.0.1"

    cell_id = 134220836

    p1 = ApSimulator(cell_id)
    time.sleep(1)

    p1.counter =1
    p1.ue_attach_and_release_request()
    p1.ue_location_attach_and_release()
    # p1.gtp_echo_request_packet()
    # while p1.counter < 4:
    #     p1.counter = p1.counter + 1
    #
    #     p1.gtp_icmp_data()
    #     time.sleep(1)
    # del p1.counter
    #p1.ue_location_attach_and_release()
