#include <iomanip>

#include "../helper/quic-packet.h"
#include "../helper/tcp-packet.h"
#include "drop-rate-error-model.h"

using namespace std;

NS_OBJECT_ENSURE_REGISTERED(DropRateErrorModel);

TypeId DropRateErrorModel::GetTypeId(void) {
    static TypeId tid = TypeId("DropRateErrorModel")
        .SetParent<ErrorModel>()
        .AddConstructor<DropRateErrorModel>()
        ;
    return tid;
}

DropRateErrorModel::DropRateErrorModel()
    : rate(0), distr(0, 99), burst(INT_MAX), dropped_in_a_row(0), dropped(0), forwarded(0)
{
    std::random_device rd;
    rng = new std::mt19937(rd());
}

void DropRateErrorModel::DoReset(void) {
    dropped_in_a_row = 0;
    dropped = 0;
    forwarded = 0;
}
 
bool DropRateErrorModel::DoCorrupt(Ptr<Packet> p) {
    bool shouldDrop = false;

    if(IsUDPPacket(p) || IsTCPPacket(p)) {
        if (dropped_in_a_row >= burst) {
            dropped_in_a_row = 0;
            shouldDrop = false;
        } else if (distr(*rng) < rate) {
            dropped_in_a_row++;
            shouldDrop = true;
        } else {
            dropped_in_a_row = 0;
            shouldDrop = false;
        }
    } else {
        return false;
    }


    if(IsUDPPacket(p)) {
        QuicPacket qp = QuicPacket(p);

        if (shouldDrop) {
            cout << "Dropping ";
            dropped++;
        } else {
            cout << "Forwarding ";
            forwarded++;
            qp.ReassemblePacket();
        }
        cout << qp.GetUdpPayload().size()
             << " bytes " << qp.GetIpv4Header().GetSource() << ":"
             << qp.GetUdpHeader().GetSourcePort() << " -> "
             << qp.GetIpv4Header().GetDestination() << ":"
             << qp.GetUdpHeader().GetDestinationPort()
             << ", dropped " << dropped << "/" << dropped + forwarded << " ("
             << fixed << setprecision(1)
             << (double)dropped / (dropped + forwarded) * 100
             << "%)" << endl;

        return shouldDrop;
    } else if(IsTCPPacket(p)) {
        TcpPacket tp = TcpPacket(p);

        if (shouldDrop) {
            cout << "Dropping ";
            dropped++;
        } else {
            cout << "Forwarding ";
            forwarded++;
            tp.ReassemblePacket();
        }

        cout << tp.GetTcpPayload().size()
             << " bytes " << tp.GetIpv4Header().GetSource() << ":"
             << tp.GetTcpHeader().GetSourcePort() << " -> "
             << tp.GetIpv4Header().GetDestination() << ":"
             << tp.GetTcpHeader().GetDestinationPort()
             << ", dropped " << dropped << "/" << dropped + forwarded << " ("
             << fixed << setprecision(1)
             << (double)dropped / (dropped + forwarded) * 100
             << "%)" << endl;

        return shouldDrop;
    } else {
        return false;
    }
}

void DropRateErrorModel::SetDropRate(int rate_in) {
    rate = rate_in;
}

void DropRateErrorModel::SetMaxDropBurst(int burst_in) {
    burst = burst_in;
}
