import asyncio
import proto.seg_xfer_pb2 as xfer


UNIX_SOCKET_PATH = '/tmp/bluesock'



async def corou():
    reader, writer = await asyncio.open_unix_connection(UNIX_SOCKET_PATH)
    msg = xfer.Test()
    msg.name = "test client"
    msg.payload = b"FIREbualdsjl..."

    writer.write(msg.SerializeToString())
    print('wrote msg')
    await asyncio.sleep(0.5)
    print('waiting for read')
    buf = await reader.read()
    msg2 = xfer.Test()
    msg2.ParseFromString(buf)
    print(msg2)

loop = asyncio.get_event_loop()
loop.run_until_complete(corou())
