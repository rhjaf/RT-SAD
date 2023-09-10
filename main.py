import numpy
from plot import plot_cdf_and_save
import matplotlib.pyplot as plt
import statistics
import pyshark
import argparse
import regex as re
import time
from datetime import datetime, timedelta
from countminsketch import CountMinSketch
import welford


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



### setting up command line
parser = argparse.ArgumentParser()
parser.add_argument('-i', '--interface', metavar=" ", type=str, required = True, help = 'To specify the interface ')
parser.add_argument('-o', '--output', metavar=' ', help = 'To capture and save the pcap in a file')
parser.add_argument('-a', '--alpha', metavar=' ', type=int, help = 'time interval to update alpha')

args = parser.parse_args()



stat_exist = CountMinSketch(2^11,2)
stat_asym = CountMinSketch(2^11,2)

detect_asym = CountMinSketch(2^11,2)
detect_pred = CountMinSketch(2^11,2) # predicate_value
detect_thld = CountMinSketch(2^11,2)



n = 10 # the residual aggregation size
min_alpha = 0.3
max_alpha = 0.7
delta_alpha = 0.1

sampling_rate = 10 

update_set = {} # the IPs that their threshold and predicated values are gonna be update at the end of each window


res_list = [] # a list of residual sequence for each ip
alpha_list=[] # a list of min,max,delta alpha for each ip



def update_predicated(ip):
  detect_pred[ip] = (1-alpha) * detect_pred[ip] + alpha * stat_asym[ip]
'''
the article doesn't say anything about when to update alpha-values
  but I considered two methods:
    1 - update it when an attck has been detected (default mode)
    2 - update it within specific periods defined by -a command
'''

def update_alpha(ip):
  current_res = abs(detect_pred[ip]-stat_asym[ip])
  if current_res > res_list[ip].mean + 3 * res_list[ip].standardDeviation():
    if alpha_list[ip].get("alpha") < alpha_list[ip].get("max_alpha"):
      alpha_list[ip] = alpha_list[ip].get("alpha") + alpha_list[ip].get("delta_alpha")
  elif current_res < res_list[ip].mean() + res_list[ip].standardDdeviation():
    if alpha_list[ip].get("alpha") < alpha_list[ip].get("min_alpha"):
      alpha_list[ip]["alpha"] = alpha_list[ip]["alpha"] - alpha_list[ip]["delta_alpha"]




def calculate_detect_threshold(ip): 
  # runs at the end of each window 
  res = abs(detect_pred[ip]-stat_asym[ip])
  res_list[ip].push(res) 
  ## this is the regular method for calculating threshold
  #mean ( 0<i<n : res(i)) + 3 *  standard_deviation_of_historical_res_sequence ( radical_variance(0<i<n : res(i)))
  detect_thld[ip] = res_list[ip].mean() + 3 * res_list[ip].standardDeviation()



def flowfunc(pkt):
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
      flow_key = pkt.ip.src + pkt.ip.dst
    except:
      return
    if res_list[pht.ip.dst] is None:
      res_list[pkt.ip.dst] = welford()
      alpha_list[pkt.ip.dst] = {"min_alpha":0.3,"max_alpha":0.7,"delta_alpha":0.1}
    
    
    if stat_exist[flow_key]==0:
      stat_exist[flow_key] = stat_exist[flow_key]+1
      flow_key_rev = pkt.ip.dst + pkt.ip.src
      if stat_exist[flow_key_rev]==0:
        stat_asym[pkt.ip.src] += stat_asym[pkt.ip.src] 
      elif stat_exist[flow_key_rev]>0:
        stat_asym[pkt.ip.src] -= stat_asym[pkt.ip.sr]
    
    # ddos detection
    res = abs(detect_pred[pkt.ip.dst]-stat_asym[pkt.ip.dst])
    
    if (res>detect_thld[pkt.ip.dst]):
      # attack occured
      print ("[+]","IP ",pkt.ip.dst," is under attack!")
      if args.alpha is None:
        update_alpha(pkt.ip.dst)
    else:
      update_set.add(pkt.ip.dst)
      
  



capture = pyshark.LiveCapture(interface=args.interface)
window_duration = timedelta(seconds=60)

def process_packets(packet_list):
    for packet in packet_list:
        flowfunc(packet)
        
    
    

start_time = datetime.now()
packet_list = []
counter = 0



# Capture packets continuously
for packet in capture.sniff_continuously():
    if counter !=sampling_rate:
      continue
    counter+=1
    packet_list.append(packet)
    elapsed_time = datetime.now() - start_time
    if elapsed_time >= window_duration:
        # end of time window
        process_packets(packet_list)
        #### calculate current window res for each ip ==> dip
        # 
        ## but we don't store all res for all IPs
       
               
        ### update threshold & predicated_value for each DIP in update_set
        for ip in update_set:
          calculate_detect_threshold(ip)
          update_predicated(ip)
        
        
        packet_list = []
        start_time = datetime.now()    
        flows.clear() 
capture.close()





