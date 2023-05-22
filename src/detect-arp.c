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
#ifdef UNITTESTS
static void DetectArpRegisterTests (void);
#endif


void DetectArpRegister(void) {
    sigmatch_table[DETECT_ARP].name = "ip.arp_opcode";
    sigmatch_table[DETECT_ARP].alias = "arp_opcode";
    SCLogNotice("Registering arp_opcode");
    sigmatch_table[DETECT_ARP].desc = "give an introduction into how a detection module works";
    sigmatch_table[DETECT_ARP].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Suricata_Developers_Guide";
    sigmatch_table[DETECT_ARP].Match = DetectArpMatch;
    sigmatch_table[DETECT_ARP].Setup = DetectArpSetup;
    sigmatch_table[DETECT_ARP].Free = DetectArpFree;
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
    int ret = 0;
    // const DetectArpData *data = (const DetectArpData *) ctx;

    /* packet payload access */
    if (p->arph != NULL) {
        ret = 1;
    }
    SCLogNotice("ARP match");
    return ret;
}

/**
 * \brief This function is used to parse arp options passed via arp: keyword
 *
 * \param arpstr Pointer to the user provided arp options
 *
 * \retval arpd pointer to DetectArpData on success
 * \retval NULL on failure
 */
// static DetectArpData *DetectArpParse (const char *arpstr)
// {
//     char arg1[4] = "";
//     char arg2[4] = "";
//     int ov[MAX_SUBSTRINGS];

//     int ret = DetectParsePcreExec(&parse_regex, arpstr, 0, 0, ov, MAX_SUBSTRINGS);
//     if (ret != 3) {
//         SCLogError(SC_ERR_PCRE_MATCH, "parse error, ret %" PRId32 "", ret);
//         return NULL;
//     }

//     ret = pcre_copy_substring((char *) arpstr, ov, MAX_SUBSTRINGS, 1, arg1, sizeof(arg1));
//     if (ret < 0) {
//         SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
//         return NULL;
//     }
//     SCLogDebug("Arg1 \"%s\"", arg1);

//     ret = pcre_copy_substring((char *) arpstr, ov, MAX_SUBSTRINGS, 2, arg2, sizeof(arg2));
//     if (ret < 0) {
//         SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
//         return NULL;
//     }
//     SCLogDebug("Arg2 \"%s\"", arg2);

//     DetectArpData *arpd = SCMalloc(sizeof (DetectArpData));
//     if (unlikely(arpd == NULL))
//         return NULL;

//     if (ByteExtractStringUint8(&arpd->arg1, 10, 0, (const char *)arg1) < 0) {
//         SCFree(arpd);
//         return NULL;
//     }
//     if (ByteExtractStringUint8(&arpd->arg2, 10, 0, (const char *)arg2) < 0) {
//         SCFree(arpd);
//         return NULL;
//     }
//     return arpd;
// }

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
        return -1;
    }
    
    sm = SigMatchAlloc();
    if (unlikely(sm == NULL)) {
        SCFree(data);
        return -1;
    }

    sm->type = DETECT_ARP;

    if (StringParseUint16(&data->arp_opcode, 10, 0,arpstr) < 0)
    {
        SCFree(data);
        return -1;
    }

    sm->ctx = (SigMatchCtx *)data;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;
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

#ifdef UNITTESTS
#include "tests/detect-arp.c"
#endif
