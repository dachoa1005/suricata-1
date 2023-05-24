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

/**
 * \file
 *
 * \author XXX Yourname <youremail@yourdomain>
 *
 * XXX Short description of the purpose of this keyword
 */

#include "suricata-common.h"
#include "util-unittest.h"
#include "util-byte.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-prefilter-common.h"

#include "detect-arp.h"

/**
 * \brief Regex for parsing our keyword options
 */
#define PARSE_REGEX  "^\\s*([0-9]+)?\\s*,s*([0-9]+)?\\s*$"
static DetectParseRegex parse_regex;

/* Prototypes of functions registered in DetectArpRegister below */
static int DetectArpMatch (DetectEngineThreadCtx *,
        Packet *, const Signature *, const SigMatchCtx *);
static int DetectArpSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectArpFree (DetectEngineCtx *, void *);
// static bool PrefilterArpIsPrefilterable(const Signature *s);
// static int PrefilterSetupArp(DetectEngineCtx *de_ctx, SigGroupHead *sgh);


#ifdef UNITTESTS
static void DetectArpRegisterTests (void);
#endif


void DetectArpRegister(void) {
    sigmatch_table[DETECT_ARP].name = "arp";
    sigmatch_table[DETECT_ARP].alias = "arp_opcode";
    sigmatch_table[DETECT_ARP].desc = "give an introduction into how a detection module works";
    sigmatch_table[DETECT_ARP].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Suricata_Developers_Guide";
    sigmatch_table[DETECT_ARP].Match = DetectArpMatch;
    sigmatch_table[DETECT_ARP].Setup = DetectArpSetup;
    sigmatch_table[DETECT_ARP].Free = DetectArpFree;
    SCLogNotice("Registering arp_opcode");

    // sigmatch_table[DETECT_ARP].SupportsPrefilter = PrefilterArpIsPrefilterable;
    // sigmatch_table[DETECT_ARP].SetupPrefilter = PrefilterSetupArp;
#ifdef UNITTESTS
    /* registers unittests into the system */
    sigmatch_table[DETECT_ARP].RegisterTests = DetectArpRegisterTests;
#endif
    /* set up the PCRE for keyword parsing */
    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

/**
 * \brief This function is used to match ARP rule option on a packet
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch with context that we will cast into DetectArpData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectArpMatch (DetectEngineThreadCtx *det_ctx, Packet *p,
                                const Signature *s, const SigMatchCtx *ctx)
{
    // int ret = 0;
    const DetectArpData *data = (const DetectArpData *) ctx;

    /* packet payload access */
    if (p->arph == NULL) {
        return 0;
    }
    SCLogNotice("ARP match");
    // return (data->arp_opcode == (uint16_t)ntohl(p->arph->arp_opcode)) ? 1 : 0;
    return 1; 
}

/**
 * \brief parse the options from the 'arp' keyword in the rule into
 *        the Signature data structure.
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param arpstr pointer to the user provided arp options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectArpSetup (DetectEngineCtx *de_ctx, Signature *s, const char *arpstr)
{
    DetectArpData *data = NULL;
    SigMatch *sm = NULL;

    data = SCMalloc(sizeof(DetectArpData));
    if (unlikely(data == NULL)) {
        SCLogNotice("Packet NULL");
        goto error;
    }
    
    sm = SigMatchAlloc();
    if (unlikely(sm == NULL)) {
        SCFree(data);
        goto error;
    }

    sm->type = DETECT_ARP;

    if (StringParseUint16(&data->arp_opcode, 10, 0,arpstr) < 0)
    {
        SCFree(data);
        goto error;
    }
    SCLogNotice("%d", data->arp_opcode);

    sm->ctx = (SigMatchCtx *)data;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    if (data)
        SCFree(data);
    if (sm)
        SigMatchFree(de_ctx, sm);
    return -1;
}

/**
 * \brief this function will free memory associated with DetectArpData
 *
 * \param ptr pointer to DetectArpData
 */
static void DetectArpFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectArpData *arpd = (DetectArpData *)ptr;

    /* do more specific cleanup here, if needed */
    SCFree(arpd);
}


// static bool PrefilterArpIsPrefilterable(const Signature *s)
// {
//     const SigMatch *sm;
//     for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
//         switch (sm->type) {
//             case DETECT_ARP:
//                 return TRUE;
//         }
//     }
//     return FALSE;
// }

// static void PrefilterPacketArpSet(PrefilterPacketHeaderValue *v, void *smctx)
// {
//     const DetectArpData *a = smctx;
//     v->u16[0] = a->arp_opcode;
// }

// static bool PrefilterPacketArpCompare(PrefilterPacketHeaderValue v, void *smctx)
// {
//     const DetectArpData *a = smctx;
//     if (v.u32[0] == a->arp_opcode)
//         return TRUE;
//     return FALSE;
// }

// static void PrefilterPacketArpMatch(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
// {
//     const PrefilterPacketHeaderCtx *ctx = pectx;

//     if (PrefilterPacketHeaderExtraMatch(ctx, p) == FALSE)
//         return;

//     if (p->arph != NULL)
//     {
//         // SCLogDebug("packet matches TCP ack %u", ctx->v1.u32[0]);
//         PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
//     }
// }


// static int PrefilterSetupArp(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
// {
//     return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_ARP,
//         PrefilterPacketArpSet,
//         PrefilterPacketArpCompare,
//         PrefilterPacketArpMatch);
// }

#ifdef UNITTESTS
#include "tests/detect-arp.c"
#endif
