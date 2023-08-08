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
#include "flow-hash.h"

int DecodeARP(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, 
        const uint8_t *pkt, uint32_t len)
{
    StatsIncr(tv, dtv->counter_arp);

    if (!PacketIncreaseCheckLayers(p)) {
        return TM_ECODE_FAILED;
    }

    if (len < sizeof(ARPHdr)) {
        // ENGINE_SET_INVALID_EVENT(p, ARP_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    p->arph = (ARPHdr *)pkt;
    
    if (unlikely(p->arph == NULL))
        return TM_ECODE_FAILED;
    
    return TM_ECODE_OK;
}

