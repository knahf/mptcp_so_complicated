import asyncio
import os
import time
import socket
import mp_tracker

UNIX_SOCKET_PATH = '/tmp/bluesock'




class MPReassemblyProtocol(asyncio.Protocol):
    def __init__(self, tracker=None):
        self.transport = None
        self.tracker = tracker


    def connection_made(self, transport):
        self.transport = transport
        # print("New Connection")
        pass

    def data_received(self, data):
        # print("Received: ", data)
        request = xfer.PacketMsg()
        request.ParseFromString(data)  # Note: msg = xfer.Test().ParseFromString(data) doesn't work.
        # print(reqest)
        # print(fixd_inet_ntoa(reqest.src_ip))

        # Process the packet and get the reassembled stream
        payload = self.tracker.new_packet(request)
        print("\treassembled payload = %r" % payload)

        response = xfer.ReassembledPayload()
        response.payload = payload
        buf = response.SerializeToString()
        self.transport.write(buf)
        self.transport.close()  # Necessary?? guess we gotta flush the buffs.

    def connection_lost(self, exc):
        # print("Lost Connection err=%r \n" % exc)
        pass


if __name__ == '__main__':
    if os.path.exists(UNIX_SOCKET_PATH):
        os.unlink(UNIX_SOCKET_PATH)
    print(os.getcwd())
    os.system("protoc -I=./proto --python_out=./proto proto/seg_xfer.proto")
    import proto.seg_xfer_pb2 as xfer
    print('imported proto')
    loop = asyncio.get_event_loop()

    # Instantiate an object that tracks Multipath
    mpt = mp_tracker.MPTracker()

    server = loop.create_unix_server((lambda : MPReassemblyProtocol(tracker=mpt)),
                                     UNIX_SOCKET_PATH)
    loop.run_until_complete(server)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print("Saw CTRL-C. Goodbye.")
        print(mpt.subflows)
        os.unlink(UNIX_SOCKET_PATH)
    except Exception as e:
        os.unlink(UNIX_SOCKET_PATH)
        raise e


    # proto = loop.create_server((lambda: SplicerProtocol(victim_address)), *listen_address)
    # loop.run_until_complete(proto)
    # loop.run_forever()