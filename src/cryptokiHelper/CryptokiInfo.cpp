#include "CryptokiInfo.h"
#include "CryptokiHelperTypes.h"

using namespace Cryptoki;

std::string CryptokiInfo::getKeyTypeName(const CK_KEY_TYPE type)
{
	switch(type) {
		case KT_RSA             : return std::string("KT_RSA"			); break;
		case KT_DSA             : return std::string("KT_DSA"			); break;
		case KT_DH              : return std::string("KT_DH"			); break;
		case KT_ECDSA           : return std::string("KT_ECDSA"			); break;
		//case KT_EC              : return std::string("KT_EC"			); break;
		case KT_X9_42_DH        : return std::string("KT_X9_42_DH"		); break;
		case KT_KEA             : return std::string("KT_KEA"			); break;
		case KT_GENERIC_SECRET  : return std::string("KT_GENERIC_SECRET"); break;
		case KT_RC2             : return std::string("KT_RC2"			); break;
		case KT_RC4             : return std::string("KT_RC4"			); break;
		case KT_RC5             : return std::string("KT_RC5"			); break;
		case KT_DES             : return std::string("KT_DES"			); break;
		case KT_DES2            : return std::string("KT_DES2"			); break;
		case KT_DES3            : return std::string("KT_DES3"			); break;
		case KT_CAST            : return std::string("KT_CAST"			); break;
		case KT_CAST3           : return std::string("KT_CAST3"			); break;
		//case KT_CAST5           : return std::string("KT_CAST5"			); break;
		case KT_CAST128         : return std::string("KT_CAST128"		); break;
		case KT_IDEA            : return std::string("KT_IDEA"			); break;
		case KT_SKIPJACK        : return std::string("KT_SKIPJACK"		); break;
		case KT_BATON           : return std::string("KT_BATON"			); break;
		case KT_JUNIPER         : return std::string("KT_JUNIPER"		); break;
		case KT_CDMF            : return std::string("KT_CDMF"			); break;
		case KT_AES             : return std::string("KT_AES"			); break;
		case KT_ARIA            : return std::string("KT_ARIA"			); break;
	};
	return std::string("Unknown");
}
