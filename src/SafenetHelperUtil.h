//---------------------------------------------------------
// Mehmet Suyuti Dindar
// 30.10.2013
// SmartSoft
//---------------------------------------------------------

#ifndef _SAFENET_HELPER_UTIL_H_
#define _SAFENET_HELPER_UTIL_H_

#include "cryptokiHelper/Key.h"
#include "cryptokiHelper/CryptokiHelper.h"

class SafenetHelperUtil {
public:
	static Cryptoki::Key getActiveLmk(Cryptoki::CryptokiHelper& session);
	static int getActiveLmkIndex(Cryptoki::CryptokiHelper& session);
	static Cryptoki::Key getLmk(Cryptoki::CryptokiHelper& session, int lmkIndex);
};

#endif //_SAFENET_HELPER_UTIL_H_
