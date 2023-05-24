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
#include "util-print.h"

#include "output.h"
#include "output-json.h"

#include "app-layer.h"
#include "app-layer-parser.h"

#include "app-layer-template.h"
#include "output-json-arp.h"

#include <arpa/inet.h>

#define MODULE_NAME "LogArpLog"
typedef struct ArpJsonOutputCtx_ {
    LogFileCtx *file_ctx;
    OutputJsonCommonSettings cfg;
} ArpJsonOutputCtx;

typedef struct JsonArpLogThread_ {
    LogFileCtx *file_ctx;
    MemBuffer *json_buffer;
    ArpJsonOutputCtx *json_output_ctx;
} JsonArpLogThread;

static void convertIPToString(const uint8_t *ip, char *ipString)
{
    sprintf(ipString, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
    SCLogNotice("%s", ipString);
}

static void convertMacToString(const uint8_t *mac, char *macString)
{
    sprintf(macString, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4],
            mac[5]);
}

static int JsonArpLogger(ThreadVars *tv, void *thread_data, const Packet *p)
{
    JsonArpLogThread *aft = thread_data;
    // ArpJsonOutputCtx *json_output_ctx = aft->json_output_ctx;
    char timebuf[64];
    char srcip[16] = { 0 }, desip[16] = { 0 };
    char srcmac[18] = { 0 }, desmac[18] = { 0 };
    CreateIsoTimeString(&p->ts, timebuf, sizeof(timebuf));
    
    // for (int i = 0; i < p->alerts.cnt; i++) {

    JsonBuilder *jb = jb_new_object();
    if (unlikely(jb == NULL)) {
        return TM_ECODE_OK;
    }

    jb_set_string(jb, "timestamp", timebuf);
    // json_object_set_new(jb, "timestamp", json_string(timebuf));
    jb_set_string(jb, "event_type", "arp");
    SCLogNotice("1");
    MemBufferReset(aft->json_buffer);

    jb_open_object(jb, "arp");
    SCLogNotice("1");

    convertIPToString(p->arph->arp_src_ip, srcip);
    jb_set_string(jb, "src_ip", srcip);
    SCLogNotice("arp log: %s", timebuf);
    SCLogNotice("1");

    convertIPToString(p->arph->arp_des_ip, desip);
    jb_set_string(jb, "dst_ip", desip);
    SCLogNotice("1");

    convertMacToString(p->arph->arp_src_mac, srcmac);
    jb_set_string(jb, "src_mac", srcmac);
    SCLogNotice("1");

    convertMacToString(p->arph->arp_des_mac, desmac);
    jb_set_string(jb, "dst_mac", desmac);
    jb_set_uint(jb, "operation", ntohs(p->arph->arp_opcode));
    jb_set_uint(jb, "hw_type", ntohs(p->arph->arp_hw_type));
    jb_set_uint(jb, "proto_type", p->arph->arp_proto_type);
    SCLogNotice("1");

    jb_close(jb);

    // size_t jslen = jb_len(jb);
    // if (jslen == 0) {
    //     jb_free(jb);
    //     return TM_ECODE_OK;
    // }

    // if (MEMBUFFER_OFFSET(aft->json_buffer) + jslen > MEMBUFFER_SIZE(aft->json_buffer)) {
    //     MemBufferExpand(aft->json_buffer, jslen);
    // }

    // MemBufferWriteRaw(aft->json_buffer, jb_ptr(jb), jslen);
    // LogFileWrite(aft->file_ctx, aft->json_buffer);
    OutputJsonBuilderBuffer(jb, aft->file_ctx, &aft->json_buffer);
    jb_free(jb);

    return TM_ECODE_OK;
}

static TmEcode JsonArpLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    JsonArpLogThread *aft = SCCalloc(1, sizeof(JsonArpLogThread));
    if (unlikely(aft == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogArp.  \"initdata\" argument NULL");
        goto error_exit;
    }

    aft->json_buffer = MemBufferCreateNew(JSON_OUTPUT_BUFFER_SIZE);
    if (aft->json_buffer == NULL) {
        goto error_exit;
    }

    ArpJsonOutputCtx *json_output_ctx = ((OutputCtx *)initdata)->data;
    aft->file_ctx = LogFileEnsureExists(json_output_ctx->file_ctx, t->id);
    if (aft->file_ctx == NULL) {
        goto error_exit;
    }
    aft->json_output_ctx = json_output_ctx;

    *data = (void *)aft;
    return TM_ECODE_OK;

error_exit:
    if (aft->json_buffer != NULL) {
        MemBufferFree(aft->json_buffer);
    }
    SCFree(aft);
    return TM_ECODE_FAILED;
}

static TmEcode JsonArpLogThreadDeinit(ThreadVars *t, void *data)
{
    JsonArpLogThread *aft = (JsonArpLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->json_buffer);

    /* clear memory */
    memset(aft, 0, sizeof(JsonArpLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

// static void OutputArpLogDeinitSub(OutputCtx *output_ctx)
// {

// }

// static OutputInitResult OutputArpLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
// {

// }
static void JsonArpLogDeInitCtxSubHelper(OutputCtx *output_ctx)
{
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);

    ArpJsonOutputCtx *json_output_ctx = (ArpJsonOutputCtx *)output_ctx->data;
    if (json_output_ctx != NULL) {
        SCFree(json_output_ctx);
    }
    SCFree(output_ctx);
}
static OutputInitResult JsonArpLogInitCtxHelper(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;
    ArpJsonOutputCtx *json_output_ctx = NULL;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        return result;
    }

    json_output_ctx = SCCalloc(1, sizeof(ArpJsonOutputCtx));
    if (unlikely(json_output_ctx == NULL)) {
        goto error;
    }

    memset(json_output_ctx, 0, sizeof(ArpJsonOutputCtx));

    json_output_ctx->file_ctx = ajt->file_ctx;
    json_output_ctx->cfg = ajt->cfg;

    output_ctx->data = json_output_ctx;
    output_ctx->DeInit = JsonArpLogDeInitCtxSubHelper;

    result.ctx = output_ctx;
    result.ok = true;

    return result;

error:
    if (json_output_ctx != NULL) {
        SCFree(json_output_ctx);
    }
    if (output_ctx != NULL) {
        SCFree(output_ctx);
    }

    return result;
}

static OutputInitResult JsonArpLogInitCtxSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = JsonArpLogInitCtxHelper(conf, parent_ctx);
    if (result.ok) {
        // printf("ok\n");
        result.ctx->DeInit = JsonArpLogDeInitCtxSubHelper;
    }

    return result;
}

static int JsonArpLogCondition(ThreadVars *tv, const Packet *p)
{
    if (p->arph)
        return TRUE; 
    return FALSE;
}

// void JsonArpLogRegister(void)
// {
//     /* register as child of eve-log */
//     OutputRegisterTxSubModuleWithCondition(LOGGER_JSON_ARP,
//         "eve-log", "JsonArpLog", "eve-log.arp",
//         OutputArpLogInitSub, ALPROTO_ARP, JsonArpLogger,
//         JsonArpLogCondition, JsonArpLogThreadInit, JsonArpLogThreadDeinit, NULL);
// }

void JsonArpLogRegister(void)
{
    SCLogNotice("JsonArpLogRegister");
    OutputRegisterPacketSubModule(LOGGER_JSON_ARP, "eve-log", MODULE_NAME, "eve-log.arp",
            JsonArpLogInitCtxSub, JsonArpLogger, JsonArpLogCondition, JsonArpLogThreadInit,
            JsonArpLogThreadDeinit, NULL);
}