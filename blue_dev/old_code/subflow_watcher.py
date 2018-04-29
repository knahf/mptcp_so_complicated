from __future__ import print_function
# import pcap
import pcapy
import dpkt
import binascii

# REF http://code.activestate.com/recipes/576678-packet-monitoring-with-pcap-and-dpkt/
# FOR PYTHON 3... USE PCAPY INSTEAD OF PYPCAP. ALSO, USE MIGRATE_PY3 BRANCH OF DPKT

def packet_handler(ts, buf):
    print(ts, 'new packet', buf)
    frame = dpkt.ethernet.Ethernet(buf)
    packet = frame.data
    segment = packet.data
    print(binascii.hexlify(segment.opts))
    options = dpkt.tcp.parse_opts(segment.opts) # ret# urns tuple of options
    print(options)
    print(segment.data)
    for option in options:
        if option[0] != 30:
            continue
        else:
            print(ts, 'new mp packet', option, segment.data)
            temp = list(option[1])
            print(temp)
            kind = ord(temp.pop(0))
            length = ord(temp.pop(0))
            print(kind)

            if kind == 0x0: # MP_CAPABLE
                print('MP_CAPABLE', temp)
                pass
            elif kind == 0x1:  # MP_JOIN
                pass
            elif kind == 0x2:  # DSS
                pass
            elif kind == 0x3:  # ADD_ADDR
                pass
            elif kind == 0x4: # REMOVE_ADDR
                pass
            elif kind == 0x5:  # MP_PRIO
                pass
            elif kind == 0x6:  # MP_FAIL
                pass
            elif kind == 0x7:  # MP_FASTCLOSE
                pass
            else:
                raise RuntimeWarning('Something Weird happened while trying to determine MP Kind')


    print()

# pc = pcap.pcap('lo')
pc = pcapy.open_live('lo', 1518, True, 0)
pc.setfilter('tcp')
print('datalink', pc.datalink())
# print("watching: ", pc.filter, "from ", pc.name)
try:
    pc.loop(0, packet_handler)
except KeyboardInterrupt:
    print('CTRL-C')
    exit()
pass