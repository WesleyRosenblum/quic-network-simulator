#ifndef TCP_PACKET_H
#define TCP_PACKET_H

#include <cstdint>

#include "ns3/header.h"
#include "ns3/packet.h"
#include "ns3/ppp-header.h"
#include "ns3/ipv4-header.h"
#include "ns3/tcp-header.h"

using namespace ns3;
using namespace std;

bool IsTCPPacket(Ptr<Packet> p);

class TcpPacket {
public:
    TcpPacket(Ptr<Packet> p);
    // Assemble a new packet.
    // It uses the PPP, IP and TCP header that it parsed from the original packet,
    // and recalculates IP and TCP checksums.
    void ReassemblePacket();
    Ipv4Header& GetIpv4Header();
    TcpHeader& GetTcpHeader();
    vector<uint8_t>& GetTcpPayload();
    bool IsVersionNegotiationPacket();

private:
    Ptr<Packet> p_;
    PppHeader ppp_hdr_;
    Ipv4Header ipv4_hdr_;
    TcpHeader tcp_hdr_;
    uint32_t tcp_hdr_len_;
    uint32_t total_hdr_len_;
    vector<uint8_t> tcp_payload_;
};

#endif /* TCP_PACKET_H */
