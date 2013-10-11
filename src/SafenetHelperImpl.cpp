//---------------------------------------------------------
// Mehmet Suyuti Dindar
// 11.10.2013
// SmartSoft
//---------------------------------------------------------

#include "SafenetHelperImpl.h"
#include "../include/SafenetHelperErr.h"
#include "cryptokiHelper/CryptokiHelper.h"

#define HSM_SLOT_GIB		1
#define HSM_SLOT_GIB_PIN	"1234"

SafenetHelperImpl::SafenetHelperImpl()
{
	std::string pin(HSM_SLOT_GIB_PIN);
	_pCryptoki = CryptokiHelper::instance();
	_pCryptoki->closeSession();
	_pCryptoki->openSession(HSM_SLOT_GIB);
	_pCryptoki->login(pin);
}

int SafenetHelperImpl::login(unsigned long slotId, std::string& pin)
{
	_pCryptoki->closeSession();
	_pCryptoki->openSession(slotId);
	_pCryptoki->login(pin);
	return SUCCESS;
}


int SafenetHelperImpl::GenerateAES256Key(	std::string& keyName,
											int& lmkIndex,
											VectorUChar& key,
											VectorUChar& kcv,
											bool isTokenObject)
{
	// lmkIndex'deki lmk keyi var mi
	// yoksa activeLmk'yi kullan

	Key _key = _pCryptoki->generateSecretKey(keyName, isTokenObject);

	return SUCCESS;
}
