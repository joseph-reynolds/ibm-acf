

#include <iostream>
#include <sstream>
#include <string>
#include <string.h>

#include <cinttypes>

#include <unistd.h> // getopt
#include <getopt.h>
#include <fstream>

#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/x509.h"
#include "openssl/pem.h"
#include "openssl/asn1t.h"
#include "openssl/asn1.h"
#include "openssl/x509.h" // Needoed for reading in public key
#include "openssl/rsa.h"

#include <CeLogin.h>

#include "CeLoginCli.h"




int main(int argc, char** argv)
{
    bool sPrintHelp = true;
    if(argc > 1)
    {
        if(0 == strcmp(argv[1], "create"))
        {
            sPrintHelp = false;
            cli::createHsf(argc, argv);
        }
        else if(0 == strcmp(argv[1], "decode"))
        {
            sPrintHelp = false;
            cli::decodeHsf(argc, argv);
        }
        else if(0 == strcmp(argv[1], "verify"))
        {
            sPrintHelp = false;
            cli::verifyHsf(argc, argv);
        }
    }

    if(sPrintHelp)
    {
        std::cout << "Usage:" << std::endl;
        std::cout << "    " << argv[0] << " [create|decode|verify] <args>" << std::endl;
        std::cout << std::endl;
        std::cout << "Command Help Text:" << std::endl;
        std::cout << "    " << argv[0] << " [create|decode|verify] [-h|--help]" << std::endl;
    }
}

#if 0
int oldmain()
{
    std::cout << "test" << std::endl;

    std::string json = "{\"version\": 10, \"machines\": {\"serialNumber\": \"s\", \"frameworkEc\": \"TBD\"}, \"hashedAuthCode\": \"f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b\", \"expiration\": \"a\", \"requestId\": \"TBD\", \"array\": [ 1, 2, 3 ]}";

    CELogin* parsedData = NULL;
    const unsigned char* ppin = &out4_asn[0];
    parsedData = d2i_CELogin(NULL, &ppin, out4_asn_len);
    if (parsedData)
    {
        char strbuf[200];
        bzero(strbuf, 200);
        OBJ_obj2txt(strbuf, 200, parsedData->algorithm->id, 0);

        std::cout << "SEQUENCE: CeLogin" << std::endl;
        std::cout << "{" << std::endl;
        std::cout << "\tProcessingType:\t" << parsedData->processingType->data << std::endl;
        std::cout << "\tSourceFileName:\t" << parsedData->sourceFileName->data << std::endl;
        std::cout << "\tSourceFileData: (JSON)" << std::endl;
        std::cout << "\t{" << std::endl;

        jsmn_parser jsmnParser;
        const uint64_t jsmnTokensSize = 128;
        jsmntok_t jsmnTokens[jsmnTokensSize];

        jsmn_init(&jsmnParser);
        int nTok = jsmn_parse(&jsmnParser,
                              (char*)parsedData->sourceFileData->data, parsedData->sourceFileData->length,
                              jsmnTokens, jsmnTokensSize);


        for(int i = 0; i < CeLogin::NumCELoginTags; i++)
        {
            uint32_t tokenIndexParm = 0;
            CeLogin::CeLoginRc sRc = CeLogin::getTokenFromTag((char*)parsedData->sourceFileData->data,
                                                              parsedData->sourceFileData->length,
                                                              jsmnTokens, nTok,
                                                              (CeLogin::CELoginTag)i, tokenIndexParm);
            std::cout << "\t\t" << CeLogin::CELoginTagsString[i] << ":\t";

            if(CeLogin::Success == sRc)
            {
                std::string tmpstr((char*)parsedData->sourceFileData->data);
                std::cout << tmpstr.substr(jsmnTokens[tokenIndexParm].start,
                                           jsmnTokens[tokenIndexParm].end - jsmnTokens[tokenIndexParm].start);
            }
            else
            {
                std::cout << "ERROR";
            }
            std::cout << std::endl;

        }

        std::cout << "\t}" << std::endl;


        std::cout << "\tSEQUENCE: Algorithm" << std::endl;
        std::cout << "\t{" << std::endl;
        std::cout << "\t\tid:\t" << strbuf << std::endl;
        std::cout << "\t\tnullValue:\t" << parsedData->algorithm->nullValue << std::endl;
        std::cout << "\t}" << std::endl;
        std::cout << "\tSignature:\t";
        std::stringstream ss;
        for(int i = 0; i < parsedData->signature->length; i++)
        {
            ss.width(2);
            ss.fill('0');
            ss << std::hex << std::uppercase << (int)parsedData->signature->data[i];
        }
        std::cout << ss.str() << std::endl;
        std::cout << "}" << std::endl;
    }
    else
    {
        std::cout << "Error parsing ASN.1 structure" << std::endl;
    }

    const uint8_t* binaryPublicKey = &testkey_der_pub[0];
    RSA* publicKey = d2i_RSA_PUBKEY(NULL, &binaryPublicKey, testkey_der_pub_len);
    if(publicKey)
    {
        //std::cout << OBJ_obj2nid(parsedData->algorithm->id) << " " << NID_sha1 << std::endl;
        uint8_t* hash = SHA512(parsedData->sourceFileData->data, parsedData->sourceFileData->length, NULL);
        int result = RSA_verify(NID_sha512,
                                hash, SHA512_DIGEST_LENGTH,
                                parsedData->signature->data, parsedData->signature->length,
                                publicKey);
        if(1 == result)
        {
            std::cout << "Signature validated" << std::endl;
        }
        else
        {
            std::cout << "Signature failed" << std::endl;
            uint8_t decrypted[1000];
            result = RSA_public_decrypt(parsedData->signature->length, parsedData->signature->data,
                                        decrypted, publicKey, RSA_PKCS1_PADDING);
            {
            std::stringstream ss;
            for(int i = 0; i < result; i++)
            {
                ss.width(2);
                ss.fill('0');
                ss << std::hex << std::uppercase << (int)decrypted[i];
            }
            std::cout << ss.str() << std::endl;
            }

            {

            std::stringstream ss;
            for(int i = 0; i < result - SHA512_DIGEST_LENGTH; i++)
            {
                ss.width(2);
                ss.fill('0');
                ss << std::hex << std::uppercase << (int)0;
            }

            for(int i = 0; i < SHA512_DIGEST_LENGTH; i++)
            {
                ss.width(2);
                ss.fill('0');
                ss << std::hex << std::uppercase << (int)hash[i];
            }
            std::cout << ss.str() << std::endl;
            }


            const uint8_t* binaryPrivateKey = &testkey_priv_der[0];
            RSA* privateKey = d2i_RSAPrivateKey(NULL, &binaryPrivateKey, testkey_priv_der_len);
            unsigned int signatureSize = RSA_size(privateKey);
            uint8_t newSignature[signatureSize];
            result = RSA_sign(NID_sha512, hash, SHA512_DIGEST_LENGTH, newSignature, &signatureSize, privateKey);

            result = RSA_public_decrypt(signatureSize, newSignature,
                                        decrypted, publicKey, RSA_PKCS1_PADDING);

            std::stringstream ss;
            for(int i = 0; i < result; i++)
            {
                ss.width(2);
                ss.fill('0');
                ss << std::hex << std::uppercase << (int)decrypted[i];
            }
            std::cout << ss.str() << std::endl;

            int result = RSA_verify(NID_sha512,
                                    hash, SHA512_DIGEST_LENGTH,
                                    newSignature, signatureSize,
                                    publicKey);

            if(1 == result)
            {
                std::cout << "round trip success" << std::endl;
            }
            else
            {
                std::cout << "round trip failure" << std::endl;
            }

            unsigned long err = ERR_get_error();
            std::cout << "OSSL ERROR: " << ERR_error_string(err, NULL);
            std::cout << "Signature failed" << std::endl;
            std::cout << "Source" << parsedData->sourceFileData->data << std::endl;
            std::cout << "Source Length: " << parsedData->sourceFileData->length  << " " << json.length() <<  std::endl;
            std::cout << "Signature Length: " << parsedData->signature->length << std::endl;
        }
    }
    else
    {
        std::cout << "Error reading public key" << std::endl;
    }
    return 0;
}
#endif
