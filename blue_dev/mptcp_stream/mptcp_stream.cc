// This is a modified Snort++ example. Cisco's original copyright notice 
// if below: 
//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// dpx.cc author Russ Combs <rcombs@sourcefire.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>

#include "main/snort.h"
#include "detection/detect.h"
#include "main/snort_debug.h"
#include "main/snort_types.h"
//#include "main/snort.h"
#include "events/event_queue.h"
#include "framework/inspector.h"
#include "framework/module.h"
#include "log/messages.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "protocols/tcp_options.h"
#include "protocols/udp.h"
#include "profiler/profiler.h"
#include "utils/stats.h"

#include "proto/seg_xfer.pb.h"
#include <sys/socket.h>
#include <sys/un.h>

#define MPTCP_STREAM_GID 256
#define MPTCP_STREAM_SID 1
#define MPTCP 0x1e


static const char* s_name = "mptcp_stream";
static const char* s_help = "dynamic inspector example";


static const char *socket_path = "/tmp/bluesock";


static THREAD_LOCAL ProfileStats mptcp_streamPerfStats;

static THREAD_LOCAL SimpleStats mptcp_streamstats;

THREAD_LOCAL Packet * mp_pkt;

const char* trigger_buff = "FIREFIREFIRE\n"; // for testing

int packet_count = 0;

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Mptcp_stream : public Inspector
{
public:
    Mptcp_stream(uint16_t port, uint16_t max);

    void show(SnortConfig*) override;
    void eval(Packet*) override;

private:
    uint16_t port;
    uint16_t max;
};

Mptcp_stream::Mptcp_stream(uint16_t p, uint16_t m)
{
    LogMessage("Mptcp_stream Constructor??");
    port = p;
    max = m;
}

void Mptcp_stream::show(SnortConfig*)
{
    LogMessage("%s config:\n", s_name);
    LogMessage("    port = %d\n", port);
    LogMessage("    max = %d\n", max);
    LogMessage("Mptcp_stream Show\n");
}

void Mptcp_stream::eval(Packet* p)
{
    packet_count++;
    printf("Packet Count: %d\n", packet_count);


    // precondition - what we registered for
//    assert(p->is_tcp());

//    if (!(p->is_tcp())){
//        printf("\t NOT TCP!\n");
//        return;


    /* Build the PROTOBUF */
    seg_xfer::PacketMsg segment_msg;
    seg_xfer::ReassembledPayload reassembled_payload;

    segment_msg.set_name("From Snort");
    mp_pkt = new Packet();

//    printf("Snort IP ADDRESSES %x %x", p->ptrs.ip_api.get_src()->ip32[0], p->ptrs.ip_api.get_dst()->ip32[0]);
    // TODO: Figure out why snort isn't always changing src/dst IP addresses when the server replies.
    // TODO:   observed this behavior when netcating from host machine -> VMware VM. (works ok with pcaps tho)

    segment_msg.set_src_ip( p->ptrs.ip_api.get_src()->ip32[0]); // only IPv4 Right now
    segment_msg.set_dst_ip( p->ptrs.ip_api.get_dst()->ip32[0]);
    segment_msg.set_src_port(p->ptrs.tcph->src_port());
    segment_msg.set_dst_port(p->ptrs.tcph->dst_port());
    segment_msg.set_seqno( (uint32_t) p->ptrs.tcph->seq());
    segment_msg.set_ackno( (uint32_t) p->ptrs.tcph->ack());
    segment_msg.set_tcp_flags(p->ptrs.tcph->th_flags);
    segment_msg.set_payload((char *) p->data, p->dsize);
    segment_msg.set_dsize(p->dsize);

    /* Report MPTCP Options */
    tcp::TcpOptIterator iter(p->ptrs.tcph, p);
    for ( const tcp::TcpOption& opt : iter )
    {
        if ( (std::uint8_t) opt.code == MPTCP ) /* 0x1e == MPTCP */
        {
            segment_msg.add_mptcp_option(opt.data, opt.len);
        }
    }


    /* Connect to Reassembly Server */
    /* Thanks https://github.com/troydhanson/network/blob/master/unixdomain/cli.c */
    struct sockaddr_un addr;
    char buf[100];
    int fd,rc;

    if ( (fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket error");
        exit(-1);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path)-1);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("connect error");
        exit(-1);
    }

    /* Send the segment info */
    segment_msg.SerializeToFileDescriptor(fd);

    /* Receive Reassembled Buffer */
    reassembled_payload.ParseFromFileDescriptor(fd);


    /* Close the FD to the Reassembly Server */
    close(fd);

    // test this hack  // Comment out bad hack
//    p->data = (uint8_t *) reassembled_payload.payload().data();
//    p->dsize = reassembled_payload.payload().length();


//    LogMessage("New Packet - SEQ: %lu - ACK: %lu\n", p->ptrs.tcph->seq(), p->ptrs.tcph->ack());


    /* lots of this from tcp_reassembler.cc */

    mp_pkt->ptrs.set_pkt_type(PktType::PDU);
    mp_pkt->flow = p->flow;  // Need to figure out how to prevent multiple alerts being generated from same traffic
    mp_pkt->proto_bits |= PROTO_BIT__TCP;
//    mp_pkt->packet_flags |= (pkt_flags & PKT_PDU_FULL);
    mp_pkt->ptrs.ip_api.set(*p->ptrs.ip_api.get_dst(),
                            *p->ptrs.ip_api.get_src());
    mp_pkt->ptrs.dp = p->ptrs.sp;
    mp_pkt->ptrs.sp = p->ptrs.dp;
    mp_pkt->data = (uint8_t *) reassembled_payload.payload().data();
    mp_pkt->dsize = reassembled_payload.payload().length();
//
    printf("\tsnort_detect result=%d\n", snort_detect(mp_pkt));

    if ( p->ptrs.dp == port && p->dsize > max )
        SnortEventqAdd(MPTCP_STREAM_GID, MPTCP_STREAM_SID);

    ++mptcp_streamstats.total_packets;


}

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

static const Parameter mptcp_stream_params[] =
{
    { "port", Parameter::PT_PORT, nullptr, nullptr,
      "port to check" },

    { "max", Parameter::PT_INT, "0:65535", "0",
      "maximum payload before alert" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap mptcp_stream_rules[] =
{
    { MPTCP_STREAM_SID, "too much data sent to port" },
    { 0, nullptr }
};

class Mptcp_streamModule : public Module
{
public:
    Mptcp_streamModule() : Module(s_name, s_help, mptcp_stream_params)
    { }

    unsigned get_gid() const override
    { return MPTCP_STREAM_GID; }

    const RuleMap* get_rules() const override
    { return mptcp_stream_rules; }

    const PegInfo* get_pegs() const override
    { return simple_pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&mptcp_streamstats; }

    ProfileStats* get_profile() const override
    { return &mptcp_streamPerfStats; }

    bool set(const char*, Value& v, SnortConfig*) override;

public:
    uint16_t port;
    uint16_t max;
};

bool Mptcp_streamModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("port") )
        port = v.get_long();

    else if ( v.is("max") )
        max = v.get_long();

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new Mptcp_streamModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* mptcp_stream_ctor(Module* m)
{
    Mptcp_streamModule* mod = (Mptcp_streamModule*)m;
    return new Mptcp_stream(mod->port, mod->max);
}

static void mptcp_stream_dtor(Inspector* p)
{
    delete p;
}

static const InspectApi mptcp_stream_api
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    IT_PACKET,   // changed from IT_NETWORK
    (uint16_t)PktType::TCP,     // HF: Change this from DPX example to UDP
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    mptcp_stream_ctor,
    mptcp_stream_dtor,
    nullptr, // ssn
    nullptr  // reset
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &mptcp_stream_api.base,
    nullptr
};

