#ifndef _CRYPTOKI_INFO_H_
#define _CRYPTOKI_INFO_H_

#include <string>
#include "cryptoki.h"

namespace Cryptoki {

class CryptokiInfo {
public:
	static std::string getKeyTypeName(const CK_KEY_TYPE type);

};

};

#endif //_CRYPTOKI_INFO_H_
