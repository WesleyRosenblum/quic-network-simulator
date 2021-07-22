#include <cstdint>
#include <vector>

#include "tcp-packet.h"

#include "ns3/packet.h"
#include "ns3/ppp-header.h"
#include "ns3/ipv4-header.h"
#include "ns3/ipv6-header.h"
#include "ns3/tcp-header.h"

using namespace ns3;
using namespace std;


bool IsTCPPacket(Ptr<Packet> p) {
    PppHeader ppp_hdr = PppHeader();
    p->RemoveHeader(ppp_hdr);
    bool is_tcp = false;
    switch(ppp_hdr.GetProtocol()) {
        case 0x21: // IPv4
            {
                Ipv4Header hdr = Ipv4Header();
                p->PeekHeader(hdr);
                is_tcp = hdr.GetProtocol() == 6;
            }
            break;
        case 0x57: // IPv6
            {
                Ipv6Header hdr = Ipv6Header();
                p->PeekHeader(hdr);
                is_tcp = hdr.GetNextHeader() == 6;
            }
            break;
        default:
            cout << "Unknown PPP protocol: " << ppp_hdr.GetProtocol() << endl;
            break;
    }
    p->AddHeader(ppp_hdr);
    return is_tcp;
}


TcpPacket::TcpPacket(Ptr<Packet> p) : p_(p) {
    const uint32_t p_len = p->GetSize();
    uint8_t *buffer= new uint8_t[p_len];
    p->CopyData(buffer, p_len);
    ppp_hdr_ = PppHeader();
    uint32_t ppp_hdr_len = p->RemoveHeader(ppp_hdr_);
    // TODO: This currently only works for IPv4.
    ipv4_hdr_ = Ipv4Header();
    uint32_t ip_hdr_len = p->RemoveHeader(ipv4_hdr_);
    tcp_hdr_ = TcpHeader();
    tcp_hdr_len_ = p->RemoveHeader(tcp_hdr_);
    total_hdr_len_ = ppp_hdr_len + ip_hdr_len + tcp_hdr_len_;
    tcp_payload_ = vector<uint8_t>(&buffer[total_hdr_len_], &buffer[total_hdr_len_] + p_len - total_hdr_len_);
}

Ipv4Header& TcpPacket::GetIpv4Header() { return ipv4_hdr_; }

TcpHeader& TcpPacket::GetTcpHeader() { return tcp_hdr_; }

vector<uint8_t>& TcpPacket::GetTcpPayload() { return tcp_payload_; }

bool TcpPacket::IsVersionNegotiationPacket() {
    return false;
}

void TcpPacket::ReassemblePacket() {
    // Start with the TCP payload.
    Packet new_p = Packet(tcp_payload_.data(), tcp_payload_.size());
    // Add the TCP header and make sure to recalculate the checksum.
    tcp_hdr_.InitializeChecksum(ipv4_hdr_.GetSource(), ipv4_hdr_.GetDestination(), ipv4_hdr_.GetProtocol());
    tcp_hdr_.EnableChecksums();
    new_p.AddHeader(tcp_hdr_);
    // Add the IP header, again make sure to recalculate the checksum.
    ipv4_hdr_.EnableChecksum();
    new_p.AddHeader(ipv4_hdr_);
    // Add the PPP header.
    new_p.AddHeader(ppp_hdr_);
    p_->RemoveAtEnd(p_->GetSize());
    p_->AddAtEnd(Ptr<Packet>(&new_p));
}
