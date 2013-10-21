//---------------------------------------------------------
// Mehmet Suyuti Dindar
// 11.10.2013
// SmartSoft
//---------------------------------------------------------

#ifndef _SAFENET_HELPER_IMPL_H_
#define _SAFENET_HELPER_IMPL_H_
#include <string>
#include "../include/SafenetHelperTypes.h"
#include "cryptokiHelper/CryptokiHelper.h"

// TODO forward declaration olmalı
//class Cryptoki::CryptokiHelper;

class SafenetHelperImpl {
public:
	SafenetHelperImpl();

	int setup();
	int addLmk();

	int login(unsigned long slotId, std::string& pin);

	int GenerateAES256Key(	VectorUChar& key,
							VectorUChar& kcv);
protected:
	int getLastLmkIndex();
	int setLastLmkIndex(std::string val);

private:
	Cryptoki::CryptokiHelper* _pCryptoki;

};

#endif //_SAFENET_HELPER_IMPL_H_
