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

#include "detect-test.h"

/**
 * \brief Regex for parsing our keyword options
 */
#define PARSE_REGEX  "^\\s*([0-9]+)?\\s*,s*([0-9]+)?\\s*$"
static DetectParseRegex parse_regex;

/* Prototypes of functions registered in DetectTestRegister below */
static int DetectTestMatch (DetectEngineThreadCtx *,
        Packet *, const Signature *, const SigMatchCtx *);
static int DetectTestSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectTestFree (DetectEngineCtx *, void *);
#ifdef UNITTESTS
static void DetectTestRegisterTests (void);
#endif

/**
 * \brief Registration function for test: keyword
 *
 * This function is called once in the 'lifetime' of the engine.
 */
void DetectTestRegister(void) {
    /* keyword name: this is how the keyword is used in a rule */
    sigmatch_table[DETECT_TEST].name = "dnsport";
    sigmatch_table[DETECT_TEST].desc = "give an introduction into how a detection module works";
    sigmatch_table[DETECT_TEST].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Suricata_Developers_Guide";
    sigmatch_table[DETECT_TEST].Match = DetectTestMatch;
    sigmatch_table[DETECT_TEST].Setup = DetectTestSetup;
    sigmatch_table[DETECT_TEST].Free = DetectTestFree;
#ifdef UNITTESTS
    /* registers unittests into the system */
    sigmatch_table[DETECT_TEST].RegisterTests = DetectTestRegisterTests;
#endif
    /* set up the PCRE for keyword parsing */
    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

/**
 * \brief This function is used to match TEST rule option on a packet
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch with context that we will cast into DetectTestData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectTestMatch (DetectEngineThreadCtx *det_ctx, Packet *p,
                                const Signature *s, const SigMatchCtx *ctx)
{
    int ret = 0;
    const DetectTestData *testd = (const DetectTestData *) ctx;

    SCLogNotice("testd->dnsport: %d", testd->dnsport);
    SCLogNotice("p->dp: %d", p->dp);
    if (p->payload != NULL && p->payload_len > 0) {
        if (testd->dnsport == p->dp)
        {
            ret = 1;
        }
    }

    return ret;
}

/**
//  * \brief This function is used to parse test options passed via test: keyword
//  *
//  * \param teststr Pointer to the user provided test options
//  *
//  * \retval testd pointer to DetectTestData on success
//  * \retval NULL on failure
//  */
// static DetectTestData *DetectTestParse (const char *teststr)
// {
//     char arg1[4] = "";
//     char arg2[4] = "";
//     int ov[MAX_SUBSTRINGS];

//     int ret = DetectParsePcreExec(&parse_regex, teststr, 0, 0, ov, MAX_SUBSTRINGS);
//     if (ret != 3) {
//         SCLogError(SC_ERR_PCRE_MATCH, "parse error, ret %" PRId32 "", ret);
//         return NULL;
//     }

//     ret = pcre_copy_substring((char *) teststr, ov, MAX_SUBSTRINGS, 1, arg1, sizeof(arg1));
//     if (ret < 0) {
//         SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
//         return NULL;
//     }
//     SCLogDebug("Arg1 \"%s\"", arg1);

//     ret = pcre_copy_substring((char *) teststr, ov, MAX_SUBSTRINGS, 2, arg2, sizeof(arg2));
//     if (ret < 0) {
//         SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
//         return NULL;
//     }
//     SCLogDebug("Arg2 \"%s\"", arg2);

//     DetectTestData *testd = SCMalloc(sizeof (DetectTestData));
//     if (unlikely(testd == NULL))
//         return NULL;

//     if (ByteExtractStringUint8(&testd->arg1, 10, 0, (const char *)arg1) < 0) {
//         SCFree(testd);
//         return NULL;
//     }
//     if (ByteExtractStringUint8(&testd->arg2, 10, 0, (const char *)arg2) < 0) {
//         SCFree(testd);
//         return NULL;
//     }
//     return testd;
// }

/**
 * \brief parse the options from the 'test' keyword in the rule into
 *        the Signature data structure.
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param teststr pointer to the user provided test options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectTestSetup (DetectEngineCtx *de_ctx, Signature *s, const char *teststr)
{
    DetectTestData *testd = NULL;
    testd = SCMalloc(sizeof(DetectTestData));
    if (testd == NULL)
        return -1;

    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL) {
        DetectTestFree(de_ctx, testd);
        return -1;
    }

if (StringParseUint16(&testd->dnsport, 10, 0, teststr) < 0) {
        return -1;
    }

    sm->type = DETECT_TEST;
    sm->ctx = (SigMatchCtx*)testd;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;
}

/**
 * \brief this function will free memory associated with DetectTestData
 *
 * \param ptr pointer to DetectTestData
 */
static void DetectTestFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectTestData *testd = (DetectTestData *)ptr;
    SCFree(testd);
}

#ifdef UNITTESTS
#include "tests/detect-test.c"
#endif
