
#include <openssl/asn1t.h>

#ifndef _CELOGINASNV1_H
#define _CELOGINASNV1_H

namespace CeLogin
{
    struct CELoginSequenceAlgorithmV1 {
        ASN1_OBJECT* id;
        ASN1_NULL* nullValue;
    };

    DECLARE_ASN1_FUNCTIONS(CELoginSequenceAlgorithmV1)

    struct CELoginSequenceV1 {
        ASN1_PRINTABLESTRING* processingType;
        ASN1_PRINTABLESTRING* sourceFileName;
        ASN1_OCTET_STRING* sourceFileData;
        CELoginSequenceAlgorithmV1* algorithm;
        ASN1_BIT_STRING* signature;
    };

    DECLARE_ASN1_FUNCTIONS(CELoginSequenceV1)

};
#endif