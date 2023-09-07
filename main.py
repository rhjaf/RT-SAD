import numpy
from plot import plot_cdf_and_save
import matplotlib.pyplot as plt
import statistics
import pyshark
import argparse
import regex as re
import time
from datetime import datetime, timedelta


# parser.add_argument('-p', '--protocol', metavar=' ', help= 'To capture packet using ptotocl filter')
# parser.add_argument('-u', '--udp', action = 'store_true', help = 'To capture udp packet only')
# parser.add_argument('-t', '--tcp', action = 'store_true', help = 'To capture tcp packet only')
# parser.add_argument('-v', '--verbose', required = False, action = 'store_true', help = 'To print the all layer of packet')

flows = dict() # Flow data
           # Format: <Endpoint-Port-Endpoint-Port-Portocol> --> { "Type": <Type>, "Start": <Start_Time>, "End": <End_Time>, "Num_Packets": <Num_Packets>,
           # "Size": <Size>, "Header_Size": <Header_Size>, "Arrival_Time": [ Packet arrival times ... ], "TCP_State": <TCP_State>, "Is_Failed": <If_TCP_Failed>,
           # "RTT": { <Seq_Num>: [ <Packet_Sent_Time>, <RTT> ] }, "Seq_Num": [ <Sequence_Number> ], "Ack_Num": [ <Acknowledgement_Number> ], 
           # "TCP_Times": [ <TCP_Packet_Sent_Times> ] }
TYPE = "Type"
START = "Start_Time"
END = "End_Time"
NUM_PACKETS = "Num_Packets"
SIZE = "Size"
HEADER_SIZE = "Header_Size"
ARRIVAL_TIME = "Arrival_Time"
TCP_STATE = "TCP_State"
IS_FAILED = "Is_Failed"
RTT = "RTT"
SEQ = "Seq_Num"
ACK = "Ack_Num"
TCP_TIMES = "TCP_Times"

# 'time', 'time_delta', 'time_delta_displayed', 'time_epoch', 'time_relative'
#print(pkt.frame_info.time) # do not use
#print(pkt.frame_info.time_delta)
#print(pkt.frame_info.time_delta_displayed)
#print(pkt.frame_info.time_epoch) # do not use
#print(pkt.frame_info.time_relative)

def flowfunc(pkt):
  
  LAST_PACKET_TIME = 1.455324301
  if pkt.transport_layer=="TCP" or pkt.transport_layer=="UDP":
    src_port = 0
    dest_port = 0
    if pkt.transport_layer == "TCP":
      src_port = pkt.tcp.srcport
      dest_port = pkt.tcp.dstport
    if pkt.transport_layer == "UDP":
      src_port = pkt.udp.srcport
      dest_port = pkt.udp.dstport  
    try:         
      flow_key = pkt.ip.src + "-" + src_port + "-" + pkt.ip.dst + "-" + dest_port + "-" + pkt.transport_layer
    except:
      return
    if not flow_key in flows:
      # Might be from the other direction
      flow_key = pkt.ip.dst + "-" + dest_port + "-" + pkt.ip.src + "-" + src_port + "-" + pkt.transport_layer
    if not flow_key in flows:
      # Record this new flow
      flows[flow_key] = {TYPE: "", START: 0, END: 0, NUM_PACKETS: 0, SIZE: 0, HEADER_SIZE: 0, ARRIVAL_TIME: [], TCP_STATE: "", IS_FAILED: True}
      flows[flow_key][TYPE] = pkt.transport_layer
      flows[flow_key][START] = float(pkt.frame_info.time_relative)
      flows[flow_key][END] = float(pkt.frame_info.time_relative)
      flows[flow_key][NUM_PACKETS] = 1
      flows[flow_key][SIZE] = int(pkt.length)
      if pkt.transport_layer == "TCP":
        flows[flow_key][HEADER_SIZE] = int(pkt.length) - int(pkt.tcp.len)
        tcp_state = "Ongoing"
        if pkt.tcp.flags_syn:
          tcp_state = "Request"
        if pkt.tcp.flags_reset:
          tcp_state = "Reset"
        if pkt.tcp.flags_fin:
          tcp_state = "Finished"
        flows[flow_key][TCP_STATE] = tcp_state
        if float(pkt.frame_info.time_relative) > (LAST_PACKET_TIME - 300):
            flows[flow_key][IS_FAILED] = False
        flows[flow_key][RTT] = dict()
        flows[flow_key][SEQ] = []
        flows[flow_key][ACK] = []
        flows[flow_key][TCP_TIMES] = []
      flows[flow_key][ARRIVAL_TIME].append(float(pkt.frame_info.time_relative))
    else:
        # add packet to flow
        flows[flow_key][END] = float(pkt.frame_info.time_relative)
        flows[flow_key][NUM_PACKETS] =  flows[flow_key][NUM_PACKETS] + 1
        flows[flow_key][SIZE] = flows[flow_key][SIZE] + int(pkt.length)
        flows[flow_key][ARRIVAL_TIME].append(float(pkt.frame_info.time_relative))
        if pkt.transport_layer == "TCP":
          flows[flow_key][HEADER_SIZE] = flows[flow_key][HEADER_SIZE] + int(pkt.length) - int(pkt.tcp.len)
          tcp_state = "Ongoing"
          if pkt.tcp.flags_syn == "Set":
            tcp_state = "Request"
          if pkt.tcp.flags_reset == "Set":
            tcp_state = "Reset"
          if pkt.tcp.flags_fin == "Set":
            tcp_state = "Finished"
          flows[flow_key][TCP_STATE] = tcp_state
          if float(pkt.frame_info.time_relative) > (LAST_PACKET_TIME - 300):
            flows[flow_key][IS_FAILED] = False
    if pkt.transport_layer == "TCP":
      flows[flow_key][RTT][pkt.tcp.seq] = [float(pkt.sniff_timestamp), -1]
      flows[flow_key][SEQ].append(pkt.tcp.seq)
      flows[flow_key][ACK].append(pkt.tcp.ack)
      flows[flow_key][TCP_TIMES].append(float(pkt.sniff_timestamp))

#for i in range(59):
#  flowfunc(pcap[i])




parser = argparse.ArgumentParser()
parser.add_argument('-i', '--interface', metavar=" ", type=str, required = True, help = 'To specify the interface ')
parser.add_argument('-o', '--output', metavar=' ', help = 'To capture and save the pcap in a file')
args = parser.parse_args()

capture = pyshark.LiveCapture(interface=args.interface)
window_duration = timedelta(seconds=60)

def process_packets(packet_list):
    for packet in packet_list:
        flowfunc(packet)
    
    
    

start_time = datetime.now()
packet_list = []

# Capture packets continuously
for packet in capture.sniff_continuously():
    packet_list.append(packet)
    elapsed_time = datetime.now() - start_time
    if elapsed_time >= window_duration:
        process_packets(packet_list)
        packet_list = []
        start_time = datetime.now()    
        flows.clear() 
capture.close()



'''


# Record RTT for each packet (while excluding the retransmitted ones)
for flow_key in flows:
  if flows[flow_key][TYPE] == "TCP":
    for i in range(len(flows[flow_key][SEQ])):
      seq_num = flows[flow_key][SEQ][i]
      ack_num = flows[flow_key][ACK][i]
      time = flows[flow_key][TCP_TIMES][i]
      if seq_num in flows[flow_key][RTT]:
        if flows[flow_key][RTT][seq_num][1] == -1:
          flows[flow_key][RTT][seq_num][1] = 0
        elif flows[flow_key][RTT][seq_num][1] == 0:
          flows[flow_key][RTT].pop(seq_num)
      if ack_num in flows[flow_key][RTT]:
        if flows[flow_key][RTT][ack_num][1] == 0:
          flows[flow_key][RTT][ack_num][1] = flows[flow_key][RTT][ack_num][0] - time


print(flows)

'''



