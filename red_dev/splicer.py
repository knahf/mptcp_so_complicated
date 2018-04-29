"""splicer3.py

Usage:
    splicer.py <listen_addrport> <victim_addrport>

"""

import asyncio
import argparse

### CONSTANTS ###

FROM_CLIENT = "from client"
FROM_SERVER = "from server"

### CONFIG ###
# TODO: Move this somewhere not horrible.
PRESERVE_CLIENT_PORT = False
SPECIFY_CLIENT_PORT = False

class PortForwardProtocol(asyncio.Protocol):


    def __init__(self, forward_to=None):
        self.state = None
        self.forward_to = None
        self.transport = None
        self.src_ip = None
        self.src_port = None
        self.dst_port = None
        self.buf = b""

        if type(forward_to) is tuple:
            self.state = FROM_CLIENT  # Receives data from clients/initiators
            self.dst_ip, self.dst_port = forward_to
        elif isinstance(forward_to, asyncio.BaseTransport):
            self.state = FROM_SERVER  # Receives data from servers
        else:
            raise RuntimeError('__init__ should be called with either a socket address ("127.0.0.1", 80:) '
                               'or asyncio.transport')

        self.forward_to = forward_to
        super().__init__()

    def connection_made(self, transport):
        if self.state == FROM_CLIENT:
            self.transport = transport
            self.src_ip, self.src_port = transport.get_extra_info('peername')
            print("Connecting: {}:{} <-> {}:{}".format(self.src_ip, self.src_port, self.dst_ip, self.dst_port))
            asyncio.get_event_loop().create_task(self.start_forwarding(transport))


    async def start_forwarding(self, transport):
        local_addr = None
        if PRESERVE_CLIENT_PORT:
            local_addr = ('0.0.0.0', self.src_port)

        if SPECIFY_CLIENT_PORT and isinstance(SPECIFY_CLIENT_PORT, int):
            local_addr = ('0.0.0.0', SPECIFY_CLIENT_PORT)

        try:
            coro = asyncio.get_event_loop().create_connection(lambda: PortForwardProtocol(forward_to=transport),
                                                              self.dst_ip, self.dst_port, local_addr=local_addr)
            self.forward_to, inner_protocol = await coro
        except ConnectionRefusedError as e:
            print(e)  # Print error message to console
            transport.write(str(e).encode() + b'\n')  # Also send error message to initiator.
            transport.close()

    async def send(self):
        # following 2 commented lines might be necessary...
        while not isinstance(self.forward_to, asyncio.BaseTransport):  # Wait until connection to target is made.
            await asyncio.sleep(0.1)

        # actually send the whole buffer
        self.forward_to.write(self.buf)

    def data_received(self, data):
        self.buf += data
        asyncio.get_event_loop().create_task(self.send())


    def connection_lost(self, exc):
        asyncio.get_event_loop().create_task(self.clean_shutdown())

    def eof_received(self):
        asyncio.get_event_loop().create_task(self.clean_shutdown())

    async def clean_shutdown(self):
        while self.buf:
            await asyncio.sleep(0.1)
        if isinstance(self.forward_to, asyncio.BaseTransport):
            self.forward_to.close()
        if isinstance(self.transport, asyncio.BaseTransport):
            self.transport.close()

class SplicerProtocol(PortForwardProtocol):
    async def send(self):
        timeout = 0.1

        while isinstance(self.forward_to, tuple):
            await asyncio.sleep(0.1)

        while len(self.buf) > 0:
            # Pop a byte off our buffer of data to forward
            byte = self.buf[0]
            self.buf = self.buf[1:]

            # actaully send the byte
            self.forward_to.write(byte.to_bytes(1, 'little'))

            # don't send anything for some time
            await asyncio.sleep(timeout)



if __name__ == '__main__':
    # args = docopt.docopt(__doc__, version='splicer')
    parser = argparse.ArgumentParser()
    parser.add_argument("listen_sockaddr", help="Socket Address of listener like so: 127.0.0.1:40600")
    parser.add_argument("victim_sockaddr", help="Socket Address of victim like so: 127.0.0.1:40601")
    parser.add_argument("--preserve_client_port", help="Attempt to preserve the client port from the TCP Initiator."
                                                       "Useful when using find port shellcodes.", action='store_true')
    parser.add_argument("--specify_client_port", help= "A specified client port will be used when the connection "
                                                       "to the server is made.", type=int)
    # parser.add_argument("--")
    args = parser.parse_args()


    if args.specify_client_port:
        SPECIFY_CLIENT_PORT = args.specify_client_port
    if args.preserve_client_port:
        PRESERVE_CLIENT_PORT = True

    ip, port = args.listen_sockaddr.split(':')
    listen_address = (ip, int(port))
    ip, port = args.victim_sockaddr.split(':')
    victim_address = (ip, int(port))

    loop = asyncio.get_event_loop()

    proto = loop.create_server((lambda: SplicerProtocol(victim_address)), *listen_address)
    loop.run_until_complete(proto)
    loop.run_forever()
    print('bye')
