import socket
import pprint
import hashlib
from collections import namedtuple, ChainMap

#TODO: Resolve missing segment errors  <-- logic is broken
#TODO: Easy Performance Improvements -- cache reassembled flows instead of rebuilding for every packet
#TODO: Double Check that sequence mapping is happening correctly
#TODO: Implement watch window? & Stop massive # of extraneous alerts
#TODO: Figure out how to get Snort to give us every packet
#TODO: TCP Connection State Tracking
#TODO: Implement ACK tracking
#TODO: Further testing w/o roundrobin scheduler.
#TODO: Option to use on remote computer? Set up as central MPTCP Tracker (easy)
#TODO: Add IPv4 Multicast to talk to IDSes and retrieve missing setments (moderate)
#TODO: Come up with better scheme for storing MP subtype data
#TODO: Make directionality stuff easier to read / explicit in code.
#TODO: Do more Snort dev to figure out how to get subflow streams from Snort
#TODO: Write a server/wireshark plugin that will just do this for pcap files

# TCP Flag Constants
TCP_NULL = 0x00
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PUSH = 0x08
TCP_ACK = 0x10

# MPTCP Subtype Constants
MP_CAPABLE = 0
MP_JOIN = 1
MP_DSS = 2
MP_ADD_ADDR = 3
MP_REMOVE_ADDR = 4
MP_PRIO = 5
MP_FAIL = 6
MP_FASTCLOSE = 7

BYTE_TO_INT_ENDIANESS = 'big'

FAKE_PAYLOAD = b"fjslFIREFIREFIREajlsj\n"  # To test triggering alerts
MISSING_SEGMENT_FILL_BYTE = b"\x00"

MPTCPContainers = {MP_CAPABLE: namedtuple("MP_CAPABLE", ("send_key", "recv_key", "send_token",
                                                         "recv_token")),
                   MP_JOIN: namedtuple("MP_JOIN", ("recv_token", "send_nonce")),
                   'generic': namedtuple("GENERIC", ("val"))}

class DSSContainer:
    def __init__(self, opt_data):
        self.F = False  # The 'F' flag indicates "DATA_FIN".
        self.a = False  #  a = Data ACK is 8 octets (if not set, Data ACK is 4 octets)
        self.A = False  # A = Data ACK present
        self.M = False  # M = Data Sequence Number (DSN), Subflow Sequence Number (SSN),
                         #  Data-Level Length, and Checksum present
        self.m = False # m = Data sequence number is 8 octets (if not set, DSN is 4 octets)
        flag_vals = opt_data[1] & 0x1F

        # These constants are in the RFC 6824. Kind of redundant. But it gives us nice bools.
        self.F = (flag_vals & 0x10) == 0x10
        self.m = (flag_vals & 0x08) == 0x08
        self.M = (flag_vals & 0x04) == 0x04
        self.a = (flag_vals & 0x02) == 0x02
        self.A = (flag_vals & 0x01) == 0x01

        data_ptr = 2
        if self.A:
            if self.a:  # 8 byte ACK
                ack_len = 8
            else:  # 4-byte ACK
                ack_len = 4
            self.DATA_ACK = int().from_bytes(opt_data[data_ptr:data_ptr + ack_len], BYTE_TO_INT_ENDIANESS)
            data_ptr += ack_len

        if self.M:

            if self.m:  # 8 byte DSN
                dsn_len = 8
                # self.DSN = int().from_bytes(opt_data[2:10], BYTE_TO_INT_ENDIANESS)   # Data Sequence Number
                # self.SSN = int().from_bytes(opt_data[10:14], BYTE_TO_INT_ENDIANESS)  # Subflow Sequence Number
                # self.DLL = int().from_bytes(opt_data[14:16], BYTE_TO_INT_ENDIANESS)  # Data Level Length
            else:  # 4 byte DSN
                dsn_len = 4

            self.DSN = int().from_bytes(opt_data[data_ptr:data_ptr + dsn_len], BYTE_TO_INT_ENDIANESS)
            data_ptr += dsn_len
            self.SSN = int().from_bytes(opt_data[data_ptr:data_ptr + 4], BYTE_TO_INT_ENDIANESS)
            data_ptr += 4
            self.DLL = int().from_bytes(opt_data[data_ptr:data_ptr + 2], BYTE_TO_INT_ENDIANESS)
            data_ptr += 2



        # TODO: Implement Checksum parsing & support



def get_mptcp_subtype(opt_data):
    """ Expect MPTCP Option Data (opt code and len bytes removed) """
    subtype = (opt_data[0] & 0xF0) >> 4
    version = opt_data[0] & 0x0F
    res = None
    if subtype == MP_CAPABLE:
        if len(opt_data) < 18:  # This is either the SYN or SYN/ACK
            pass  # For now ignore the first 2 parts of the handshake
        elif len(opt_data) >= 18:  # This is the end of the handshake. both keys are here. len=20?
            send_key = opt_data[2:10]
            recv_key = opt_data[10:18]
            res = MPTCPContainers[MP_CAPABLE](send_key=send_key, recv_key=recv_key,
                                              send_token=hashlib.sha1(send_key).digest()[:4],
                                              recv_token=hashlib.sha1(recv_key).digest()[:4])
    elif subtype == MP_JOIN:
        if len(opt_data) < 22:
            res = MPTCPContainers[MP_JOIN](recv_token=opt_data[2:6], send_nonce=opt_data[6:10])
        elif len(opt_data) >= 22:
        # length of SYN/ACK MP_JOIN option subtype (4+4) + addr_id (1) + truncated hmac (64) + nonce (32)
            pass
    elif subtype == MP_DSS:
        res = DSSContainer(opt_data)

    return res


class ReassemblyWarning(Warning):
    pass


class SegmentMissing(ReassemblyWarning):
    pass

class SegmentOverlap(ReassemblyWarning):
    pass

def get_subflow_id(pkt):
    # Return a set of src_addr and dst_addr -- bidirectional flow id.
    return tuple({(pkt.src_ip, pkt.src_port), (pkt.dst_ip, pkt.dst_port)})

def fixd_inet_ntoa(pb_int32_ip):
    return socket.inet_ntoa(pb_int32_ip.to_bytes(4, 'little'))

class Stream:
    def __init__(self, id=None):
        # Map sequence numbers to bytes
        if id:
            self.id = id
        self.data = {}
        self.segments = set()

    def add_segment(self, relative_seq, buf):
        # for start, end in self.segments:  # check for overlaps
        #     #TODO: Verify This Logic
        #     if start < relative_seq < end:
        #         raise SegmentOverlap("%d + %d overlaps with %d %d" % (relative_seq,
        #                                                               relative_seq + len(buf),
        #                                                               start, end))
        #     elif start < relative_seq + len(buf) < end:
        #         raise SegmentOverlap("%d + %d overlaps with %d %d" % (relative_seq,
        #                                                               relative_seq + len(buf),
        #                                                               start, end))
        #     elif relative_seq < start and relative_seq + len(buf) > start:
        #         raise SegmentOverlap("%d + %d overlaps with %d %d" % (relative_seq,
        #                                                               relative_seq + len(buf),
        #                                                               start, end))
        if relative_seq:
            self.data[relative_seq] = buf
            self.segments.add((relative_seq, relative_seq + len(buf)))

    def get_full_stream(self):
        buf = b""
        # last_seqno = 1
        # first_seq = self.data.keys()[0]
        for seqno in sorted(self.data.keys()):
            if seqno != len(buf)+1:  # SEQ Number is 1 before payload starts being Tx'd
                self.get_missing_segment(len(buf)+1, seqno)
            buf += self.data[seqno]


        return buf

    def get_missing_segment(self, start, end):
        print("\tMissing a Segment! %d:%d for %r" % (start, end, self.id))
        pprint.pprint(self.data)
        # This is where we would put code to request missing segment from
        # other sensors.  IMO, we could do this naively with IPv4 Multicast.
        # Or, maybe if we're wind up using concurrency we wait a bit of time.
        # Or, maybe we wait a bit here if packets are out of order. ...
        #   though we should really only do that after implementing tracking of
        #   whether data is acknowledged (this may already be happening since Snort
        #   isn't giving us all packets -- No SYN/ACK and no ACKs w/o payload )
        # We could also wait for a period of time if this was being used as a
        # central reassembly server.
        #TODO: Implement Asynchronous Wait
        #TODO: Implement multicast request for missing segments.
        pass


DataSequenceMapping = namedtuple("Data_Sequence_Mapping", ("dsn", "sfid", "ssn", "dll"))

class MPTCPConnection:
    def __init__(self, mp_capable_object):
        self.mp_capable_object = mp_capable_object
        self.subflows = {}  # MP Initiator == TCP Initiator
        self.sfid_to_dsm = {}  # Subflow ID to Data Sequence Mapping
        self.to_init_initial_DSN = None
        self.to_recv_initial_DSN = None
        self.init_sockaddrs = set()
        self.recv_sockaddrs = set()
        self.dss_list = []
        self.to_recv_dsnmap = {}
        self.to_init_dsnmap = {}
        pass

    def add_init_endpoint(self, socket_address):
        self.init_sockaddrs.add(socket_address)

    def add_recv_endpoint(self, socket_address):
        self.recv_sockaddrs.add(socket_address)

    def new_packet(self, pkt):
        self.subflows[get_subflow_id(pkt)].new_packet(pkt)

    def add_subflow(self, subflow):
        self.subflows[subflow.id] = subflow
        # self.sfid_to_dsm[subflow.id] = {'to_recv': [],
        #                                 'to_init': []}

    def add_DSS(self, pkt, dss_object):
        self.dss_list.append(dss_object)
        if not dss_object.M:  # No Data Mapping (just DATA ACKs)
            return

        sfid = get_subflow_id(pkt)
        if (pkt.src_ip, pkt.src_port) in self.init_sockaddrs:
            # Sent from MPTCP Initiator
            if self.to_recv_initial_DSN is None:
                self.to_recv_initial_DSN = dss_object.DSN - 1

            self.to_recv_dsnmap[dss_object.DSN] =  DataSequenceMapping(dsn=dss_object.DSN,
                                                                       sfid=sfid,
                                                                       ssn=dss_object.SSN,
                                                                       dll=dss_object.DLL)
        else:
            # Sent from MPTCP Receiver
            if self.to_init_initial_DSN is None:
                self.to_init_initial_DSN = dss_object.DSN - 1

            self.to_init_dsnmap[dss_object.DSN] =  DataSequenceMapping(dsn=dss_object.DSN,
                                                                       sfid=sfid,
                                                                       ssn=dss_object.SSN,
                                                                       dll=dss_object.DLL)


    def get_stream_for_packet(self, pkt):
        buf = b""
        segments = {}

        # Determine Direction
        if (pkt.src_ip, pkt.src_port) in self.init_sockaddrs:  # to_recv direction
            ds_maps = self.to_recv_dsnmap
            for dsn in sorted(ds_maps.keys()):
                dsm = ds_maps[dsn]
                x = self.subflows[dsm.sfid].to_mp_recv_stream.get_full_stream()
                segments[self.get_relative_dsn(dsm.dsn, pkt)] = x[dsm.ssn: dsm.ssn + dsm.dll]

        else:
            ds_maps = self.to_init_dsnmap
            for dsn in sorted(ds_maps.keys()):
                dsm = ds_maps[dsn]
                x = self.subflows[dsm.sfid].to_mp_init_stream.get_full_stream()
                segments[self.get_relative_dsn(dsm.dsn, pkt)] = x[dsm.ssn : dsm.ssn + dsm.dll]

        # pprint.pprint(ds_maps)


        # print("Test MP SEGment map:")
        # pprint.pprint(segments)
        for seqno in sorted(segments.keys()):
            if seqno != len(buf)+1:  # SEQ Number is 1 before payload starts being Tx'd
                self.get_missing_segment(len(buf)+1, seqno)
            buf += segments[seqno]

        # print(buf)

        return buf

    def get_missing_segment(self, start, end):
        print("missing mptcp segment: %d : %d" % (start, end))
        # raise ReassemblyWarning('wtf')


    def get_relative_dsn(self, dsn, pkt):
        if (pkt.src_ip, pkt.src_port) in self.init_sockaddrs:
            return dsn - self.to_recv_initial_DSN
        else:
            return dsn - self.to_init_initial_DSN




class SubFlow:
    def __init__(self, packet_info):
        self.id = get_subflow_id(packet_info)
        self.init_addr = (packet_info.src_ip, packet_info.src_port)
        self.recv_addr = (packet_info.dst_ip, packet_info.dst_port)
        #
        # if packet_info.tcp_flags & TCP_SYN == TCP_SYN:  # First SYN
        #     self.to_recv_seq_start = packet_info.seqno
        #     print("\tset SEQ1")
        # else:
        #     raise RuntimeWarning('Did not See first SEQ for flow %r' %self.id)
        self.to_recv_seq_start = None
        self.to_init_seq_start = None

        self.to_recv_stream = Stream(self.id)  #  Strem to Receiver
        self.to_init_stream = Stream(self.id)  #  Stream to Initiator
        # self.owned_by = None  # Update this on MP_JOIN
        pass

    def new_packet(self, pkt):
        """ This should updata subflow's stream"""

        # if pkt.tcp_flags & ( TCP_SYN | TCP_ACK ) == (TCP_SYN | TCP_ACK):
        #     if self.to_init_seq_start:
        #         raise RuntimeWarning("Saw >1 SYN+ACK handshake for %r" % self.id)
        #     self.to_init_seq_start = pkt.seqno
        #     print("set SEQ2")

        # This seems hacky. Originally I wanted to get the 2nd part of the handshake
        # however, Snort seems to not include segments that only ACK data :(
        # probably to speed things up...  -- Or, I just misconfigured Snort.
        # If this works for reassembly though, maybe it's more robust if we miss
        # the first 2 parts of the handshake ?? And maybe we should use this for
        # setting the to_recv seqno too.

        if ((pkt.src_ip, pkt.src_port) == self.init_addr) and not self.to_recv_seq_start:
            self.to_recv_seq_start = pkt.seqno  # If TCP SYN -> rel seq should be 0
            print("\tset SEQ1")


        # TODO: Figure out how to get snort to give us SYNACKs
        if ((pkt.src_ip, pkt.src_port) == self.recv_addr) and not self.to_init_seq_start:
            self.to_init_seq_start = pkt.seqno -1 # If TCP SYNACK should be 0... in practice...
            print("\tset SEQ2")


        if pkt.payload:
            print("\tattempt stream update with payload =", pkt.payload)
            if (pkt.src_ip, pkt.src_port) == self.init_addr:  # This packet sent from initiator
                self.to_recv_stream.add_segment(self.get_rel_seqno(pkt), pkt.payload)
            else:
                self.to_init_stream.add_segment(self.get_rel_seqno(pkt), pkt.payload)


    def get_rel_seqno(self, pkt):
        if (pkt.src_ip, pkt.src_port) == self.init_addr:  # This packet sent from initiator
            return pkt.seqno - self.to_recv_seq_start
        else:  # This packet sent from TCP receiver
            return pkt.seqno - self.to_init_seq_start


    def get_stream_for_packet(self, pkt):
        # Returns a b"" of the subflow stream.
        # pkt is used to determine direction and not to update stream!
        if (pkt.src_ip, pkt.src_port) == self.init_addr:  # This packet sent from initiator
            return self.to_recv_stream.get_full_stream()
        else:
            return self.to_init_stream.get_full_stream()

class MPTracker:
    def __init__(self):
        # Map subflows to MPTCP Connections
        self.sfid_to_mp = {}
        # self.subflows = {}
        self.token_to_mp = {}  # Probably should be a MultiDict
        self.unclaimed_subflows = {}
        self.connections = ChainMap(self.sfid_to_mp, self.unclaimed_subflows)
        #

    def new_packet(self, pkt):
        """ packet info should have the following attributes (i.e. pass it the protobuff message):
        src_ip, dst_ip, src_port, dst_port, mptcp_option, payload """

        print("New Packet %s:%d -> %s:%d Flags: %d %s" % (fixd_inet_ntoa(pkt.src_ip),
                                                          pkt.src_port,
                                                          fixd_inet_ntoa(pkt.dst_ip),
                                                          pkt.dst_port, pkt.tcp_flags,
                                                          pkt.payload))

        id = get_subflow_id(pkt)

        # Create a New Subflow Object if we haven't seen this subflow before
        if not id in self.connections.keys():
            self.unclaimed_subflows[id] = SubFlow(pkt)

        if hasattr(pkt, 'mptcp_option'):
            for option in pkt.mptcp_option:
                subtype = get_mptcp_subtype(option)
                if isinstance(subtype, MPTCPContainers[MP_CAPABLE]):
                    # We create a new MPTCP Connection object. Packets will get routed here before
                    #  they go to subflows now.
                    mp = MPTCPConnection(subtype)
                    subflow = self.connections[id]
                    mp.add_init_endpoint(self.connections[id].init_addr)
                    mp.add_recv_endpoint(self.connections[id].recv_addr)
                    setattr(subflow, 'to_mp_init_stream', subflow.to_init_stream)
                    setattr(subflow, 'to_mp_recv_stream', subflow.to_recv_stream)

                    # This mapping of subflow id -> MPTCP object allows the above described routing.
                    self.sfid_to_mp[id] = mp

                    # Add the new subflow to our MPTCP object
                    mp.add_subflow(self.unclaimed_subflows[id])

                    # Following line not necessary b/c of ChainMap search order, but nice to clean up
                    del self.unclaimed_subflows[id]

                    # So we can find this MPTCP object when we see MP_JOINs
                    self.token_to_mp[subtype.send_token] = mp
                    self.token_to_mp[subtype.recv_token] = mp  # Two entries allow MP_JOIN from either direction

                elif isinstance(subtype, MPTCPContainers[MP_JOIN]):
                    try:
                        mp = self.token_to_mp[subtype.recv_token]
                        subflow = self.connections[id]
                        print("JOINING WITH ", subflow)
                        self.sfid_to_mp[id] = mp
                        mp.add_subflow(self.unclaimed_subflows[id])
                        del self.unclaimed_subflows[id]
                        if mp.mp_capable_object.recv_token == subtype.recv_token:
                            # Same direction as MP Handshake
                            mp.add_init_endpoint(subflow.init_addr)
                            mp.add_recv_endpoint(subflow.recv_addr)
                            setattr(subflow, 'to_mp_init_stream', subflow.to_init_stream)
                            setattr(subflow, 'to_mp_recv_stream', subflow.to_recv_stream)
                        else:
                            # Initiated in opposite direction as MP Handshake
                            mp.add_init_endpoint(subflow.recv_addr)
                            mp.add_recv_endpoint(subflow.init_addr)
                            setattr(subflow, 'to_mp_init_stream', subflow.to_recv_stream)
                            setattr(subflow, 'to_mp_recv_stream', subflow.to_init_stream)
                    except KeyError:
                        raise ReassemblyWarning("Couldn't Locate MPTCP by Token")

                elif isinstance(subtype, DSSContainer):
                    self.connections[id].add_DSS(pkt, subtype)

                else:
                    print(subtype)

        # Finally, send the packet to the right connection object
        self.connections[id].new_packet(pkt)

        # We'll just return the reassembled payload here
        return self.connections[id].get_stream_for_packet(pkt)
        # return FAKE_PAYLOAD


if __name__ == '__main__':
    print("Hi")