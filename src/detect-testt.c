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

#include "detect-testt.h"

/**
 * \brief Regex for parsing our keyword options
 */
#define PARSE_REGEX  "^\\s*([0-9]+)?\\s*,s*([0-9]+)?\\s*$"
static DetectParseRegex parse_regex;

/* Prototypes of functions registered in DetectTesttRegister below */
static int DetectTesttMatch (DetectEngineThreadCtx *,
        Packet *, const Signature *, const SigMatchCtx *);
static int DetectTesttSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectTesttFree (DetectEngineCtx *, void *);
#ifdef UNITTESTS
static void DetectTesttRegisterTests (void);
#endif

/**
 * \brief Registration function for testt: keyword
 *
 * This function is called once in the 'lifetime' of the engine.
 */
void DetectTesttRegister(void) {
    /* keyword name: this is how the keyword is used in a rule */
    sigmatch_table[DETECT_TESTT].name = "testt";
    /* description: listed in "suricata --list-keywords=all" */
    sigmatch_table[DETECT_TESTT].desc = "give an introduction into how a detection module works";
    /* link to further documentation of the keyword. Normally on the Suricata redmine/wiki */
    sigmatch_table[DETECT_TESTT].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Suricata_Developers_Guide";
    /* match function is called when the signature is inspected on a packet */
    sigmatch_table[DETECT_TESTT].Match = DetectTesttMatch;
    /* setup function is called during signature parsing, when the testt
     * keyword is encountered in the rule */
    sigmatch_table[DETECT_TESTT].Setup = DetectTesttSetup;
    /* free function is called when the detect engine is freed. Normally at
     * shutdown, but also during rule reloads. */
    sigmatch_table[DETECT_TESTT].Free = DetectTesttFree;
#ifdef UNITTESTS
    /* registers unittests into the system */
    sigmatch_table[DETECT_TESTT].RegisterTests = DetectTesttRegisterTests;
#endif
    /* set up the PCRE for keyword parsing */
    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

/**
 * \brief This function is used to match TESTT rule option on a packet
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch with context that we will cast into DetectTesttData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectTesttMatch (DetectEngineThreadCtx *det_ctx, Packet *p,
                                const Signature *s, const SigMatchCtx *ctx)
{
    int ret = 0;
    const DetectTesttData *testtd = (const DetectTesttData *) ctx;
#if 0
    if (PKT_IS_PSEUDOPKT(p)) {
        /* fake pkt */
    }

    if (PKT_IS_IPV4(p)) {
        /* ipv4 pkt */
    } else if (PKT_IS_IPV6(p)) {
        /* ipv6 pkt */
    } else {
        SCLogDebug("packet is of not IPv4 or IPv6");
        return ret;
    }
#endif
    /* packet payload access */
    if (p->payload != NULL && p->payload_len > 0) {
        if (testtd->arg1 == p->payload[0] &&
            testtd->arg2 == p->payload[p->payload_len - 1])
        {
            ret = 1;
        }
    }

    return ret;
}

/**
 * \brief This function is used to parse testt options passed via testt: keyword
 *
 * \param testtstr Pointer to the user provided testt options
 *
 * \retval testtd pointer to DetectTesttData on success
 * \retval NULL on failure
 */
static DetectTesttData *DetectTesttParse (const char *testtstr)
{
    char arg1[4] = "";
    char arg2[4] = "";
    int ov[MAX_SUBSTRINGS];

    int ret = DetectParsePcreExec(&parse_regex, testtstr, 0, 0, ov, MAX_SUBSTRINGS);
    if (ret != 3) {
        SCLogError(SC_ERR_PCRE_MATCH, "parse error, ret %" PRId32 "", ret);
        return NULL;
    }

    ret = pcre_copy_substring((char *) testtstr, ov, MAX_SUBSTRINGS, 1, arg1, sizeof(arg1));
    if (ret < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
        return NULL;
    }
    SCLogDebug("Arg1 \"%s\"", arg1);

    ret = pcre_copy_substring((char *) testtstr, ov, MAX_SUBSTRINGS, 2, arg2, sizeof(arg2));
    if (ret < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
        return NULL;
    }
    SCLogDebug("Arg2 \"%s\"", arg2);

    DetectTesttData *testtd = SCMalloc(sizeof (DetectTesttData));
    if (unlikely(testtd == NULL))
        return NULL;

    if (ByteExtractStringUint8(&testtd->arg1, 10, 0, (const char *)arg1) < 0) {
        SCFree(testtd);
        return NULL;
    }
    if (ByteExtractStringUint8(&testtd->arg2, 10, 0, (const char *)arg2) < 0) {
        SCFree(testtd);
        return NULL;
    }
    return testtd;
}

/**
 * \brief parse the options from the 'testt' keyword in the rule into
 *        the Signature data structure.
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param testtstr pointer to the user provided testt options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectTesttSetup (DetectEngineCtx *de_ctx, Signature *s, const char *testtstr)
{
    DetectTesttData *testtd = DetectTesttParse(testtstr);
    if (testtd == NULL)
        return -1;

    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL) {
        DetectTesttFree(de_ctx, testtd);
        return -1;
    }

    sm->type = DETECT_TESTT;
    sm->ctx = (void *)testtd;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;
}

/**
 * \brief this function will free memory associated with DetectTesttData
 *
 * \param ptr pointer to DetectTesttData
 */
static void DetectTesttFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectTesttData *testtd = (DetectTesttData *)ptr;

    /* do more specific cleanup here, if needed */

    SCFree(testtd);
}

#ifdef UNITTESTS
#include "tests/detect-testt.c"
#endif
