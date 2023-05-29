#include "suricata-common.h"
#include "packet-queue.h"
#include "decode.h"
#include "decode-arp.h"
#include "decode-events.h"
#include "defrag.h"
#include "pkt-var.h"
#include "host.h"

#include "util-unittest.h"
#include "util-debug.h"
#include "util-optimize.h"
#include "util-print.h"
#include "util-profiling.h"

int DecodeARP(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, 
        const uint8_t *pkt, uint32_t len)
{
    StatsIncr(tv, dtv->counter_arp);

    SCLogDebug("pkt %p len %"PRIu32"", pkt, len);

    if (!PacketIncreaseCheckLayers(p)) {
        return TM_ECODE_FAILED;
    }

    if (unlikely(len < ARP_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, ARP_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    p->arph = (ARPHdr *)pkt;
    // p->payload = NULL;

    // printf("test\n");

    if (unlikely(p->arph == NULL))
        return TM_ECODE_FAILED;

    // printf("ARP: SHA: %02x:%02x:%02x:%02x:%02x:%02x SPA: %u.%u.%u.%u -> THA: %02x:%02x:%02x:%02x:%02x:%02x TPA: %u.%u.%u.%u\n",
    // p->arph->arp_src_mac[0], p->arph->arp_src_mac[1], p->arph->arp_src_mac[2],
    // p->arph->arp_src_mac[3], p->arph->arp_src_mac[4], p->arph->arp_src_mac[5],
    // p->arph->arp_src_ip[0], p->arph->arp_src_ip[1], p->arph->arp_src_ip[2],
    // p->arph->arp_src_ip[3], p->arph->arp_des_mac[0], p->arph->arp_des_mac[1],
    // p->arph->arp_des_mac[2], p->arph->arp_des_mac[3], p->arph->arp_des_mac[4],
    // p->arph->arp_des_mac[5], p->arph->arp_des_ip[0], p->arph->arp_des_ip[1],
    // p->arph->arp_des_ip[2], p->arph->arp_des_ip[3]);

    // printf("ARP opcode: %d\n", ntohs(p->arph->arp_opcode));
    // printf("ARP proto size: %d\n", p->arph->arp_proto_size);
    return TM_ECODE_OK;
}