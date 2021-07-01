
#include "CeLoginAsnV1.h"

#include <openssl/asn1.h>
#include <openssl/asn1t.h>

namespace CeLogin
{
ASN1_SEQUENCE(CELoginSequenceAlgorithmV1) =
    {ASN1_SIMPLE(CELoginSequenceAlgorithmV1, id, ASN1_OBJECT),
     ASN1_SIMPLE(CELoginSequenceAlgorithmV1, nullValue,
                 ASN1_NULL)} ASN1_SEQUENCE_END(CELoginSequenceAlgorithmV1)

        IMPLEMENT_ASN1_FUNCTIONS(CELoginSequenceAlgorithmV1);

ASN1_SEQUENCE(CELoginSequenceV1) =
    {ASN1_SIMPLE(CELoginSequenceV1, processingType, ASN1_PRINTABLESTRING),
     ASN1_SIMPLE(CELoginSequenceV1, sourceFileName, ASN1_PRINTABLESTRING),
     ASN1_SIMPLE(CELoginSequenceV1, sourceFileData, ASN1_OCTET_STRING),
     ASN1_SIMPLE(CELoginSequenceV1, algorithm, CELoginSequenceAlgorithmV1),
     ASN1_SIMPLE(CELoginSequenceV1, signature,
                 ASN1_BIT_STRING)} ASN1_SEQUENCE_END(CELoginSequenceV1)

        IMPLEMENT_ASN1_FUNCTIONS(CELoginSequenceV1);

}; // namespace CeLogin
