/* Copyright (C) 2015-2020 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/*
 * TODO: Update \author in this file and in output-json-template.h.
 * TODO: Remove SCLogNotice statements, or convert to debug.
 * TODO: Implement your app-layers logging.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * Implement JSON/eve logging app-layer Template.
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-unittest.h"
#include "util-buffer.h"
#include "util-debug.h"
#include "util-byte.h"

#include "output.h"
#include "output-json.h"

#include "app-layer.h"
#include "app-layer-parser.h"

#include "app-layer-template.h"
#include "output-json-template.h"

typedef struct OutputArpCtx_ {
    LogFileCtx *file_ctx;
    OutputJsonCommonSettings cfg;
} OutputArpCtx;

typedef struct JsonArpLogThread_ {
    OutputArpCtx *arplog_ctx;
    LogFileCtx *file_ctx;
    MemBuffer *buffer;
} JsonArpLogThread;

static int JsonArpLogger(ThreadVars *tv, void *thread_data, const Packet *p,
                         Flow *f, void *state, void *txptr, uint64_t tx_id)
{
    JsonArpLogThread *alt = (JsonArpLogThread *)thread_data;
    OutputArpCtx *arp_ctx = alt->arplog_ctx;

    if (unlikely(state == NULL)) {
        return 0;
    }

    JsonBuilder *js = CreateEveHeaderWithTxId(p, LOG_DIR_FLOW, "arp", NULL, tx_id);
    if (unlikely(js == NULL))
        return 0;

    EveAddCommonOptions(&arp_ctx->cfg, p, f, js);

    /* reset */
    MemBufferReset(alt->buffer);

    jb_open_object(js, "arp");

    /* Get MAC and IP addresses */
    char src_mac[6];
    char dst_mac[6];
    char src_ip[4];
    char dst_ip[4];

    if (unlikely(p->flags & PKT_FLAG_ETHERNET)) {
        EthernetHdr *eth_hdr = (EthernetHdr *)p->data;
        if (unlikely(eth_hdr->type == ETHERTYPE_ARP)) {
            ArpHdr *arp_hdr = (ArpHdr *)(p->data + sizeof(EthernetHdr));
            FormatMacAddress(arp_hdr->src_mac, src_mac, sizeof(src_mac));
            FormatMacAddress(arp_hdr->dst_mac, dst_mac, sizeof(dst_mac));
            FormatIpAddress(arp_hdr->src_ip, src_ip, sizeof(src_ip));
            FormatIpAddress(arp_hdr->dst_ip, dst_ip, sizeof(dst_ip));

            jb_add_string(js, "src_mac", src_mac);
            jb_add_string(js, "dst_mac", dst_mac);
            jb_add_string(js, "src_ip", src_ip);
            jb_add_string(js, "dst_ip", dst_ip);
        }
    }

    jb_close(js);
    OutputJsonBuilderBuffer(js, alt->file_ctx, &alt->buffer);

    jb_free(js);
    return 0;
}

static TmEcode JsonArpLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogARP. \"initdata\" argument NULL");
        return TM_ECODE_FAILED;
    }

    JsonArpLogThread *alt = SCCalloc(1, sizeof(JsonArpLogThread));
    if (unlikely(alt == NULL))
        return TM_ECODE_FAILED;

    /* Use the Output Context (file pointer and mutex) */
    alt->arplog_ctx = ((OutputCtx *)initdata)->data;

    alt->buffer = MemBufferCreateNew(JSON_OUTPUT_BUFFER_SIZE);
    if (alt->buffer == NULL) {
        goto error_exit;
    }

    alt->file_ctx = LogFileEnsureExists(alt->arplog_ctx->file_ctx, t->id);
    if (!alt->file_ctx) {
        goto error_exit;
    }

    *data = (void *)alt;
    return TM_ECODE_OK;

error_exit:
    if (alt->buffer != NULL) {
        MemBufferFree(alt->buffer);
    }
    SCFree(alt);
    return TM_ECODE_FAILED;
}

static TmEcode JsonArpLogThreadDeinit(ThreadVars *t, void *data)
{
    JsonArpLogThread *alt = (JsonArpLogThread *)data;
    if (alt == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(alt->buffer);
    /* clear memory */
    memset(alt, 0, sizeof(JsonArpLogThread));

    SCFree(alt);
    return TM_ECODE_OK;
}

static void OutputArpLogDeinitSub(OutputCtx *output_ctx)
{
    OutputArpCtx *arp_ctx = output_ctx->data;
    SCFree(arp_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputArpLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ojc = parent_ctx->data;

    OutputArpCtx *arp_ctx = SCMalloc(sizeof(OutputArpCtx));
    if (unlikely(arp_ctx == NULL))
        return result;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(arp_ctx);
        return result;
    }

    arp_ctx->file_ctx = ojc->file_ctx;
    arp_ctx->cfg = ojc->cfg;

    output_ctx->data = arp_ctx;
    output_ctx->DeInit = OutputArpLogDeinitSub;

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

int ARPTxLogCondition(ThreadVars * tv, const Packet * p, void *state, void *tx, uint64_t tx_id)
{
    return 1; // always log
}

void JsonArpLogRegister(void)
{
    /* register as child of eve-log */
    OutputRegisterTxSubModuleWithCondition(LOGGER_JSON_ARP,
        "eve-log", "JsonArpLog", "eve-log.arp",
        OutputArpLogInitSub, ALPROTO_ARP, JsonArpLogger,
        ARPTxLogCondition, JsonArpLogThreadInit, JsonArpLogThreadDeinit, NULL);
}