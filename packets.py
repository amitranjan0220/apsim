from pycrate_asn1dir import S1AP
from pycrate_asn1rt.utils import *
from pycrate_mobile.NAS import *
import binascii
import ipaddress
from binascii import hexlify, unhexlify
from kamene.all import *
from kamene.contrib.gtp import *

#Created PDU object of S1AP
PDU = S1AP.S1AP_PDU_Descriptions.S1AP_PDU

#S1SetupRequest packet
def s1_setup_request(cell_id):
    IEs = []
    IEs.append({'id': 59, 'value': ('Global-ENB-ID', {'pLMNidentity': b'\x45\xf6\x42', 'eNB-ID': ('homeENB-ID',(cell_id, 28))}), 'criticality': 'reject'})
    IEs.append({'id': 60, 'value': ('ENBname', 'ipaccess'), 'criticality': 'ignore'})
    IEs.append({'id': 64, 'value': ('SupportedTAs', [{'tAC': b'\x00\x1b', 'broadcastPLMNs': [b'\x45\xf6\x42']}]), 'criticality': 'reject'})
    IEs.append({'id': 137, 'value': ('PagingDRX', 'v128'), 'criticality': 'ignore'})
    val = ('initiatingMessage', {'procedureCode': 17, 'value': ('S1SetupRequest', {'protocolIEs': IEs}), 'criticality': 'reject'})
    PDU.set_val(val)
    msg =  hexlify(PDU.to_aper())
    msg = binascii.unhexlify(msg)
    return msg

#InitialUEMessage, Attach request, PDN connectivity request Packet
def initial_ue_message_attach(cell_id,imsi,enb_id):
    IEs = []
    imsi = str(imsi)
    imsi = ''.join([imsi[x:x+2][::-1] for x in range(0,len(imsi),2)])
    imsi = imsi[2:]
    imsi =bytes(str(imsi),encoding='utf-8')
    nas_pdu = b'0741720809' + imsi + b'04E060C04000240201D031D1271D8080211001000010810600000000830600000000000D00000300000A005C0A003103E5E0349011035758A65D0100'
    IEs.append({'id': 8, 'value': ('ENB-UE-S1AP-ID', enb_id),'criticality': 'reject'})
    IEs.append({'id': 26, 'value': ('NAS-PDU', unhexlify(nas_pdu)), 'criticality': 'reject'})
    IEs.append({'id': 67, 'value': ('TAI', {'pLMNidentity': b'\x45\xf6\x42', 'tAC': b'\x00\x1b'}), 'criticality': 'reject'})
    IEs.append({'id': 100, 'value': ('EUTRAN-CGI', {'cell-ID': (cell_id, 28), 'pLMNidentity': b'\x45\xf6\x42'}), 'criticality': 'ignore'})
    IEs.append({'id': 134, 'value': ('RRC-Establishment-Cause', 'mo-Signalling'), 'criticality': 'ignore'})
    IEs.append({'id': 75, 'value': ('GUMMEI',{'pLMN-Identity': b'\x45\xf6\x42', 'mME-Group-ID': b'\x21\xfd','mME-Code':b'\x30' }), 'criticality':'ignore'})
    val = ('initiatingMessage', {'procedureCode': 12, 'value': ('InitialUEMessage', {'protocolIEs': IEs}), 'criticality': 'ignore'})
    PDU.set_val(val)
    msg =  hexlify(PDU.to_aper())
    msg = binascii.unhexlify(msg)
    return msg

# DownlinkNASTransport, Identity response packet
def uplink_nas_transport_identity_response(cell_id,mme_ue_s1ap_id,imsi,enb_id):
    IEs = []
    imsi = str(imsi)
    imsi = ''.join([imsi[x:x+2][::-1] for x in range(0,len(imsi),2)])
    imsi = imsi[2:]
    imsi =bytes(str(imsi),encoding='utf-8')
    nas_pdu = b'276007ABDC0507560809' + imsi
    IEs.append({'id': 0, 'value': ('MME-UE-S1AP-ID', mme_ue_s1ap_id),'criticality': 'reject'})
    IEs.append({'id': 8, 'value': ('ENB-UE-S1AP-ID', enb_id), 'criticality': 'reject'})
    IEs.append({'id': 26, 'value': ('NAS-PDU', unhexlify(nas_pdu)), 'criticality': 'reject'})
    IEs.append({'id': 100, 'value': ('EUTRAN-CGI', {'cell-ID': (cell_id, 28), 'pLMNidentity': b'\x45\xf6\x42'}), 'criticality': 'ignore'})
    IEs.append({'id': 67, 'value': ('TAI', {'pLMNidentity': b'\x45\xf6\x42', 'tAC': b'\x00\x1b'}), 'criticality': 'reject'})
    val = ('initiatingMessage', {'procedureCode': 13, 'value': ('UplinkNASTransport', {'protocolIEs': IEs}), 'criticality': 'ignore'})
    PDU.set_val(val)
    msg =  hexlify(PDU.to_aper())
    msg = binascii.unhexlify(msg)
    return msg

#UplinkNASTransport, ESM information response packet
def uplink_nas_transport_esm_response(mme_ue_s1ap_id,cell_id,enb_id):
    IEs = []
    IEs.append({'id': 0, 'value': ('MME-UE-S1AP-ID', mme_ue_s1ap_id),'criticality': 'reject'})
    IEs.append({'id': 8, 'value': ('ENB-UE-S1AP-ID', enb_id), 'criticality': 'reject'})
    IEs.append({'id': 26, 'value': ('NAS-PDU', unhexlify(b'2771377CBA060201DA280908696E7465726E657427208080211001000010810600000000830600000000000D00000A00000500001000')), 'criticality': 'reject'})
    IEs.append({'id': 100, 'value': ('EUTRAN-CGI', {'cell-ID': (cell_id, 28), 'pLMNidentity': b'\x45\xf6\x42'}), 'criticality': 'ignore'})
    IEs.append({'id': 67, 'value': ('TAI', {'pLMNidentity': b'\x45\xf6\x42', 'tAC': b'\x00\x1b'}), 'criticality': 'reject'})
    val = ('initiatingMessage', {'procedureCode': 13, 'value': ('UplinkNASTransport', {'protocolIEs': IEs}), 'criticality': 'ignore'})
    PDU.set_val(val)
    msg =  hexlify(PDU.to_aper())
    msg = binascii.unhexlify(msg)
    return msg

# InitialContextSetupResponse
def initial_context_setup_response(mme_ue_s1ap_id,host_ip,gtp_teid_icr,enb_id):
    ip = int(ipaddress.ip_address(str(host_ip)))
    gtp_teid_icr = gtp_teid_icr.to_bytes(4,'big')
    IEs = []
    IEs.append({'id': 0, 'value': ('MME-UE-S1AP-ID', mme_ue_s1ap_id),'criticality': 'ignore'})
    IEs.append({'id': 8, 'value': ('ENB-UE-S1AP-ID', enb_id), 'criticality': 'ignore'})
    IEs.append({'id': 51, 'value':('E-RABSetupListCtxtSURes', [{'criticality': 'ignore', 'value': ('E-RABSetupItemCtxtSURes',
    {'e-RAB-ID': 5, 'transportLayerAddress': (ip, 32), 'gTP-TEID': gtp_teid_icr }), 'id': 50}]), 'criticality':'ignore'})
    val = ('successfulOutcome', {'procedureCode': 9, 'value': ('InitialContextSetupResponse', {'protocolIEs': IEs}), 'criticality': 'ignore'})
    PDU.set_val(val)
    #print(PDU.to_asn1())
    msg =  hexlify(PDU.to_aper())
    msg = binascii.unhexlify(msg)
    return msg

#UplinkNASTransport, Attach complete, Activate default EPS bearer context accept
def uplink_nas_transport_attach_complete(mme_ue_s1ap_id,cell_id,enb_id):
    IEs = []
    IEs.append({'id': 0, 'value': ('MME-UE-S1AP-ID', mme_ue_s1ap_id),'criticality': 'reject'})
    IEs.append({'id': 8, 'value': ('ENB-UE-S1AP-ID', enb_id), 'criticality': 'reject'})
    IEs.append({'id': 26, 'value': ('NAS-PDU', unhexlify('271D0C49EE07074300035200C2')), 'criticality': 'reject'})
    IEs.append({'id': 100, 'value': ('EUTRAN-CGI', {'cell-ID': (cell_id, 28), 'pLMNidentity': b'\x45\xf6\x42'}), 'criticality': 'ignore'})
    IEs.append({'id': 67, 'value': ('TAI', {'pLMNidentity': b'\x45\xf6\x42', 'tAC': b'\x00\x1b'}), 'criticality': 'reject'})
    val = ('initiatingMessage', {'procedureCode': 13, 'value': ('UplinkNASTransport', {'protocolIEs': IEs}), 'criticality': 'ignore'})
    PDU.set_val(val)
    #print(PDU.to_asn1())
    msg =  hexlify(PDU.to_aper())
    msg = binascii.unhexlify(msg)
    return msg

#UEContextReleaseRequest [RadioNetwork-cause=user-inactivity]
def ue_context_release_request(mme_ue_s1ap_id,enb_id):
    IEs = []
    IEs.append({'id': 0, 'value': ('MME-UE-S1AP-ID', mme_ue_s1ap_id),'criticality': 'ignore'})
    IEs.append({'id': 8, 'value': ('ENB-UE-S1AP-ID', enb_id), 'criticality': 'ignore'})
    IEs.append({'id': 2, 'value': ('Cause', ('radioNetwork','user-inactivity')), 'criticality': 'ignore'})
    val = ('initiatingMessage', {'procedureCode': 18, 'value': ('UEContextReleaseRequest', {'protocolIEs': IEs}), 'criticality': 'ignore'})
    PDU.set_val(val)
    msg =  hexlify(PDU.to_aper())
    msg = binascii.unhexlify(msg)
    return msg


#UEContextReleaseComplete
def ue_context_release_complete(mme_ue_s1ap_id,enb_id):
    IEs = []
    IEs.append({'id': 0, 'value': ('MME-UE-S1AP-ID', mme_ue_s1ap_id),'criticality': 'ignore'})
    IEs.append({'id': 8, 'value': ('ENB-UE-S1AP-ID', enb_id), 'criticality': 'ignore'})

    val = ('successfulOutcome', {'procedureCode': 23, 'value': ('UEContextReleaseComplete', {'protocolIEs': IEs}), 'criticality': 'reject'})
    PDU.set_val(val)
    msg =  hexlify(PDU.to_aper())
    msg = binascii.unhexlify(msg)
    return msg

#InitialUEMessage, Tracking area update
#C0000FEF
def initial_ue_message_tracking_area_update(cell_id,tmsi,enb_id):
    IEs = []
    tmsi = hex(tmsi)
    tmsi = str(tmsi)
    tmsi = tmsi[2:]
    tmsi = bytes(str(tmsi),encoding='utf-8')
    nas_pdu = b'17BBA066A00F0748020BF645F642871D52' + tmsi + b'5804E060C0405245F642001A5C0A00570220003103E5E0341330F2310C8D11035758A65D0103E0C1'
    IEs.append({'id': 8, 'value': ('ENB-UE-S1AP-ID', enb_id), 'criticality': 'reject'})
    IEs.append({'id': 26, 'value': ('NAS-PDU', unhexlify(nas_pdu)), 'criticality': 'reject'})
    IEs.append({'id': 67, 'value': ('TAI', {'pLMNidentity': b'\x45\xf6\x42', 'tAC': b'\x00\x1b'}), 'criticality': 'reject'})
    IEs.append({'id': 100, 'value': ('EUTRAN-CGI', {'cell-ID': (cell_id, 28), 'pLMNidentity': b'\x45\xf6\x42'}), 'criticality': 'ignore'})
    IEs.append({'id': 134, 'value': ('RRC-Establishment-Cause', 'mo-Signalling'), 'criticality': 'ignore'})
    val = ('initiatingMessage', {'procedureCode': 12, 'value': ('InitialUEMessage', {'protocolIEs': IEs}), 'criticality': 'reject'})
    PDU.set_val(val)
    msg =  hexlify(PDU.to_aper())
    msg = binascii.unhexlify(msg)
    return msg

def uplink_nas_transport_identity_response_location(cell_id,mme_ue_s1ap_id_2,imsi,enb_id):
    imsi = str(imsi)
    imsi = ''.join([imsi[x:x+2][::-1] for x in range(0,len(imsi),2)])
    imsi = imsi[2:]
    imsi =bytes(str(imsi),encoding='utf-8')
    nas_pdu = b'276007ABDC0507560809' + imsi
    IEs = []
    IEs.append({'id': 0, 'value': ('MME-UE-S1AP-ID', mme_ue_s1ap_id_2),'criticality': 'reject'})
    IEs.append({'id': 8, 'value': ('ENB-UE-S1AP-ID', enb_id), 'criticality': 'reject'})
    IEs.append({'id': 26, 'value': ('NAS-PDU', unhexlify(nas_pdu)), 'criticality': 'reject'})
    IEs.append({'id': 100, 'value': ('EUTRAN-CGI', {'cell-ID': (cell_id, 28), 'pLMNidentity': b'\x45\xf6\x42'}), 'criticality': 'ignore'})
    IEs.append({'id': 67, 'value': ('TAI', {'pLMNidentity': b'\x45\xf6\x42', 'tAC': b'\x00\x1b'}), 'criticality': 'reject'})
    val = ('initiatingMessage', {'procedureCode': 13, 'value': ('UplinkNASTransport', {'protocolIEs': IEs}), 'criticality': 'ignore'})
    PDU.set_val(val)
    msg =  hexlify(PDU.to_aper())
    msg = binascii.unhexlify(msg)
    return msg

#UplinkNASTransport, Tracking area update complete
def uplink_nas_transport_tracking_area_complete(cell_id,mme_ue_s1ap_id_2,enb_id):
    IEs = []
    IEs.append({'id': 0, 'value': ('MME-UE-S1AP-ID', mme_ue_s1ap_id_2),'criticality': 'ignore'})
    IEs.append({'id': 8, 'value': ('ENB-UE-S1AP-ID', enb_id), 'criticality': 'reject'})
    IEs.append({'id': 26, 'value': ('NAS-PDU', unhexlify('27779006560D074A')), 'criticality': 'reject'})
    IEs.append({'id': 100, 'value': ('EUTRAN-CGI', {'cell-ID': (cell_id, 28), 'pLMNidentity': b'\x45\xf6\x42'}), 'criticality': 'ignore'})
    IEs.append({'id': 67, 'value': ('TAI', {'pLMNidentity': b'\x45\xf6\x42', 'tAC': b'\x00\x1b'}), 'criticality': 'reject'})
    val = ('initiatingMessage', {'procedureCode': 13, 'value': ('UplinkNASTransport', {'protocolIEs': IEs}), 'criticality': 'reject'})
    PDU.set_val(val)
    msg =  hexlify(PDU.to_aper())
    msg = binascii.unhexlify(msg)
    return msg

def ue_location_context_release_complete(mme_ue_s1ap_id_2,enb_id):
    IEs = []
    IEs.append({'id': 0, 'value': ('MME-UE-S1AP-ID', mme_ue_s1ap_id_2),'criticality': 'ignore'})
    IEs.append({'id': 8, 'value': ('ENB-UE-S1AP-ID', enb_id), 'criticality': 'ignore'})

    val = ('successfulOutcome', {'procedureCode': 23, 'value': ('UEContextReleaseComplete', {'protocolIEs': IEs}), 'criticality': 'reject'})
    PDU.set_val(val)
    msg =  hexlify(PDU.to_aper())
    msg = binascii.unhexlify(msg)
    return msg

#GTP Echo Request
def gtp_echo_request(UDP_IP_ADDRESS_SRC,UDP_IP_ADDRESS_DST,):
    msg =IP(src=UDP_IP_ADDRESS_SRC,dst=UDP_IP_ADDRESS_DST)/UDP(sport= 2152,dport=2152)/GTPHeader()/GTPEchoRequest()
    return msg

#GTP[ICMP] Ping request
#TEID=0x0100188
def gtp_icmp_request(UDP_IP_ADDRESS_SRC,UDP_IP_ADDRESS_DST,GTP_ICMP_ADDRESS,GTP_TEID,data_in_bytes):
    msg =IP(src=UDP_IP_ADDRESS_SRC,dst=UDP_IP_ADDRESS_DST)/UDP(sport=2152,dport=2152)/GTP_U_Header(TEID=GTP_TEID)/IP(src=GTP_ICMP_ADDRESS,dst=GTP_ICMP_ADDRESS,ttl=128)/ICMP(id=0x0004,seq=3)/data_in_bytes
    return msg
