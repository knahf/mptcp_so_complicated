import dpkt
from socket import inet_ntoa
import hashlib
import copy

MPTCP = 0x1e
MP_CAPABLE = 0
MP_JOIN = 1
MP_DSS = 2    # includes offset from start of bytestream and length of packet
MP_ADD_ADDR = 3
MP_REMOVE_ADDR = 4
MP_PRIO = 5
MP_FAIL = 6
MP_FASTCLOSE = 7

class SubFlow:
    """ Class for a TCP Connection """
    def __init__(self, packet, flow_watcher=None):
        if flow_watcher:
            self.flow_watcher = flow_watcher
        else:
            raise RuntimeError('To track flows, SubFlow.__init__ needs a flow_watcher object passed as kwarg')

        self.id = get_flow_id(packet)
        segment = packet.data
        segment = dpkt.tcp.TCP()
        self.state = ''
        self.type = ''
        if segment.flags == dpkt.tcp.TH_SYN:
            self.state = 'SYN'
            self.observed_handshake = True
        else:
            self.observed_handshake = False
        self.initiator = tx_socket(packet)
        self.receiver = rx_socket(packet)

        # if segment.flags & dpkt.tcp.TH_SYN:
        #     self.initiator_seq = segment.seq
        # if segment.flags & dpkt.tcp.TH_ACK:
        #     self.initiator_ack = segment.ack
        self.new_packet(packet)

    def __str__(self):
        socket1, socket2 = self.id
        return inet_ntoa(socket1[0]) + ':' + str(socket1[1]) + ' <-> ' + inet_ntoa(socket2[0]) + ':' + str(socket2[1])



    def new_packet(self, packet):
        if self.state == 'SYN' and \
                        packet.data.flags == ( dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK ) and \
                        tx_socket(packet) == self.receiver:
            self.state = 'SYN/ACK'
            # self.receiver_ack = packet.data.ack
            # self.receiver_seq = packet.data.seq
        elif self.state == 'SYN/ACK' and packet.data.flags & dpkt.tcp.TH_ACK and tx_socket == self.initiator :
            self.state = 'ESTABLISHED'


        # MPTCP Tracking
        for kind, value in dpkt.tcp.parse_opts(packet.data.opts):
            if kind != MPTCP:
                continue
            subtype = (value[0] & 0xF0) >> 4

            if packet.data.flags == (dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK) and (subtype == MP_CAPABLE):
                # Harvest Keys for new MPTCP Flow.
                self.sender_key = value[2:10]
                self.receiver_key = value[10:18]
                self.type = 'MPTCP INITIAL'

                # Tokens in current MPTCP version are sha1 of key truncated to 32-bits
                self.sender_token = hashlib.sha1(self.sender_key).digest()[:4]
                self.receiver_token = hashlib.sha1(self.receiver_key).digest()[:4]

                # update flow_watcher mp_token_flow_table with tokens
                self.flow_watcher.mp_token_flow_table[self.sender_token] = self.flow_watcher.subflow_flow_table[self.id]
                self.flow_watcher.mp_token_flow_table[self.receiver_token] = self.flow_watcher.subflow_flow_table[self.id]


            elif packet.data.flags == (dpkt.tcp.TH_SYN) and (subtype == MP_JOIN):
                address_id = value[1]
                receiver_token = value[2:6]
                sender_nonce = value[6:]
                self.type = 'MPTCP JOIN'


                try:
                    mp_flow = self.flow_watcher.mp_token_flow_table[receiver_token]
                    self.new_mp_subflow(mp_flow)
                except KeyError:
                    print('MP_JOIN for Unobserved MP Handshake')

    def new_mp_subflow(self, flow):
        self.flow_watcher.subflow_flow_table[self.id] = flow
        flow.subflows[self.id] = self


class Flow():
    def __init__(self, packet, flow_watcher):
        if flow_watcher:
            self.flow_watcher = flow_watcher
        else:
            raise RuntimeError('To track flows, Flow.__init__ needs a flow_watcher object passed as kwarg')

        new_subflow = SubFlow(packet, flow_watcher=flow_watcher)
        if new_subflow.id in self.flow_watcher.subflow_flow_table:
            # subflow already added MP_JOIN
            pass
        else:
            self.subflows = {get_flow_id(packet): new_subflow}
            self.flow_watcher.subflow_flow_table[get_flow_id(packet)] = self


    def new_packet(self, packet):
        self.subflows[get_flow_id(packet)].new_packet(packet)

    def add_subflow(self, subflow):
        self.subflows[subflow.id] = subflow

    def add_multipath_keys(self, sender, receiver):
        self.sender_key = sender
        self.receiver_key = receiver

    def __contains__(self, subflow):
        """ Returns True if a subflow belongs to this flow."""
        return subflow in self.subflows


def get_mptcp_option(segment):
    result = False
    for kind, value in dpkt.tcp.parse_opts(segment.opts):
        if kind == MPTCP:
            result = value
    return False

def get_flow_id(packet):
    """ Returns a Flow-ID socket pair for a packet. """
    return tuple({(packet.src, packet.data.sport), (packet.dst, packet.data.dport)})

def tx_socket(packet):
    return (packet.src, packet.data.sport)

def rx_socket(packet):
    return (packet.dst, packet.data.dport)

def get_subtype(subtype_and_version):
    return (subtype_and_version & 0xF0) >> 4