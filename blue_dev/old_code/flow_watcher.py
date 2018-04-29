# from __future__ import print_function
# import pcap
import dpkt
import pcapy
import binascii
import pprint

import flows

# REF http://code.activestate.com/recipes/576678-packet-monitoring-with-pcap-and-dpkt/
# FOR PYTHON 3... USE PCAPY INSTEAD OF PYPCAP. ALSO, USE MIGRATE_PY3 BRANCH OF DPKT

MP_CAPABLE = 0
MP_JOIN = 1
MP_DSS = 2
MP_ADD_ADDR = 3
MP_REMOVE_ADDR = 4
MP_PRIO = 5
MP_FAIL = 6
MP_FASTCLOSE = 7

# On join
#   create new flow & subflow object
#   on handshake complete deepcopy to correct flow (lookup token mp_keyhash_table)
#   modify subflow_flow_table to be correct

#      to authenticate  to new flow:
#

def state_change_callback(flow_watcher):

    pass


class FlowWatcher:
    def __init__(self):
        self.subflow_flow_table = {}  # Find flows by subflow id.
        self.mp_token_flow_table = {}  #  Find flows by Multipath Key Hashes

    def new_packet(self, packet):
        # Packet should be a dpkt.ip.IP() object.
        id = flows.get_flow_id(packet)
        if id in self.subflow_flow_table:
            self.subflow_flow_table[id].new_packet(packet)
        else:
            # Create New Flow. Ensuing subflow will add itself to right flow and update subflow_flow_table
            flows.Flow(packet, flow_watcher=self)
            # self.subflow_flow_table[id] = flows.Flow(packet, flow_watcher=self)

    # def check_mp_token_flow_table(self, token):


    def state_change_callback(self):
        pass


def packet_handler(ts, buf):
    #print(ts, 'new packet', buf)
    # print('NEW_PACKET!')
    frame = dpkt.ethernet.Ethernet(buf)
    packet = frame.data
    segment = packet.data
    flow_watcher.new_packet(packet)


def print_flow_watcher(flow_watcher):
    """Pretty Print a FlowWatcher() Object"""
    for flow in set(flow_watcher.subflow_flow_table.values()):
        print(flow)
        for subflow_id, subflow in flow.subflows.items():
            print('\t', subflow)


pc = pcapy.open_offline('pcaps/chapter3_pcaps_ch3scenario3test2.pcapng')
# pc = pcapy.open_live('eth0', 1518, True, 0)
pc.setfilter('tcp')
print(pc.datalink())
flow_watcher = FlowWatcher()
try:
    pc.loop(0, packet_handler)
except KeyboardInterrupt as e:
    print(e)



print('RESULTS:')
print_flow_watcher(flow_watcher)
