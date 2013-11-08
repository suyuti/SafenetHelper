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
	static Cryptoki::Key createDES2Key(	  Cryptoki::CryptokiHelper* pSession,
									   	  std::string keyName);
	static Cryptoki::Key createDES2Key(	  Cryptoki::CryptokiHelper* pSession,
									   	  std::string keyName,
									   	  Cryptoki::KeyAttribute attr);
	static Cryptoki::Key createAES256Key( Cryptoki::CryptokiHelper* pSession,
									  	  std::string keyName);
	static Cryptoki::Key createAES256Key( Cryptoki::CryptokiHelper* pSession,
									  	  std::string keyName,
									   	  Cryptoki::KeyAttribute attr);
};

#endif //_SAFENET_HELPER_UTIL_H_
