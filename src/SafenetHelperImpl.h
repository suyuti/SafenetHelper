//---------------------------------------------------------
// Mehmet Suyuti Dindar
// 11.10.2013
// SmartSoft
//---------------------------------------------------------

#ifndef _SAFENET_HELPER_IMPL_H_
#define _SAFENET_HELPER_IMPL_H_
#include <string>
#include "../include/SafenetHelperTypes.h"

class CryptokiHelper;

class SafenetHelperImpl {
public:
	SafenetHelperImpl();

	int login(unsigned long slotId, std::string& pin);

	int GenerateAES256Key(	std::string& keyName,
							int& lmkIndex,
							VectorUChar& key,
							VectorUChar& kcv,
							bool isTokenObject = true);
private:
	CryptokiHelper* _pCryptoki;

};

#endif //_SAFENET_HELPER_IMPL_H_
