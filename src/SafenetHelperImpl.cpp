//---------------------------------------------------------
// Mehmet Suyuti Dindar
// 11.10.2013
// SmartSoft
//---------------------------------------------------------

#include <iostream>
#include <iomanip>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include "cryptoki.h"
#include "SafenetHelperImpl.h"
#include "../include/SafenetHelperErr.h"
#include "cryptokiHelper/CryptokiHelper.h"
#include "cryptokiHelper/ExceptionCryptoki.h"
#include "../include/SafenetHelperTypes.h"

SafenetHelperImpl::SafenetHelperImpl()
{
	std::string pin(HSM_SLOT_GIB_PIN);
	LOG4CXX_INFO(g_logger, "SafenetHelperImpl constructor");
	_pCryptoki = Cryptoki::CryptokiHelper::instance();

}

int SafenetHelperImpl::login(unsigned long slotId, std::string& pin)
{
	_pCryptoki->close();
	_pCryptoki->open(slotId, pin);
	return SUCCESS;
}

int SafenetHelperImpl::setup()
{
	std::string name(GIB_ACTIVE_LMK_INDEX);
	std::string app(GIB_APPNAME);
	char data[] = {'0','0','0','0'};

	Cryptoki::DataAttribute attr;
	attr._application 	= app;
	attr._label 		= name;
	attr._token 		= TRUE;
	attr._private 		= TRUE;
	attr._data 			= data;
	attr._dataLen 		= sizeof(data);
	_pCryptoki->createData(app, name, attr);

	std:string keyName(GIB_LMK_PREFIX "000");
	Cryptoki::MechanismInfo mInfo;
	mInfo._type = MT_DES2_KEY_GEN;

	Cryptoki::KeyAttribute kAttr;
	kAttr._decrypt 		= TRUE;
	kAttr._encrypt 		= TRUE;
	kAttr._extractable 	= FALSE;
	kAttr._keyType 		= KT_DES2;
	kAttr._private 		= TRUE;
	kAttr._sensitive 	= TRUE;
	kAttr._token 		= TRUE;
	kAttr._unwrap 		= TRUE;
	kAttr._wrap 		= TRUE;

	_pCryptoki->createKey(keyName, kAttr, mInfo);

	// TODO Key size 2048 olmali
	_pCryptoki->generateKeyPair(1024, GIB_PUBLIC_KEY_NAME, GIB_PRIVATE_KEY_NAME, true);

	return SUCCESS;
}

int SafenetHelperImpl::addLmk()
{
	int index = this->getLastLmkIndex();
	index++;

	char lmkName[32] = {0x00};
	sprintf(lmkName, GIB_LMK_PREFIX "%03d", index);

	std::string keyName(lmkName);
	Cryptoki::MechanismInfo mInfo;
	mInfo._type = MT_DES2_KEY_GEN;

	Cryptoki::KeyAttribute kAttr;
	kAttr._decrypt 		= TRUE;
	kAttr._encrypt 		= TRUE;
	kAttr._extractable 	= FALSE;
	kAttr._keyType 		= KT_DES2;
	kAttr._private 		= TRUE;
	kAttr._sensitive 	= TRUE;
	kAttr._token 		= TRUE;
	kAttr._unwrap 		= TRUE;
	kAttr._wrap 		= TRUE;

	_pCryptoki->createKey(keyName, kAttr, mInfo);

	stringstream ss;
	ss << std::setfill('0') << std::setw(4) << index;
	this->setLastLmkIndex(ss.str());

	return SUCCESS;
}


// deprecated
int SafenetHelperImpl::GenerateAES256Key(VectorUChar& key,
										 VectorUChar& kcv)
{
	int index = this->getLastLmkIndex();
	stringstream ss;
	ss << GIB_LMK_PREFIX << setfill('0') << setw(3) << index;
	Cryptoki::Key lmk = _pCryptoki->getKeyByName(OC_SECRET_KEY, ss.str());

	std::string aesKeyName;
	ss.str("");
	srand(time(NULL) ^ getpid());
	ss << "AES_" << setfill('0') << setw(4) << random() % 10000 + 1;

	char keyVal[32];
	Cryptoki::MechanismInfo mInfo;
	mInfo._param 	= keyVal;
	mInfo._paramLen = sizeof(keyVal);

	Cryptoki::KeyAttribute kAttr;
	kAttr._label 	= aesKeyName;
	kAttr._keyType 	= KT_AES;
	Cryptoki::Key aesKey = _pCryptoki->createSecretKey(aesKeyName, kAttr, mInfo);
	kcv = aesKey.getKcv();

	Cryptoki::MechanismInfo mInfoForWrap;
	mInfoForWrap._type = MT_AES_CBC;

	//key = lmk.wrap(mInfoForWrap, aesKey);

	return SUCCESS;
}

int SafenetHelperImpl::getLastLmkIndex()
{
	Cryptoki::DataObject d = _pCryptoki->getDataByName(GIB_APPNAME, GIB_ACTIVE_LMK_INDEX);
	VectorUChar val = d.getValue();
	int activeLmkIndex = atol((char*)val.data());
	return activeLmkIndex;
}

int SafenetHelperImpl::setLastLmkIndex(std::string val)
{
	Cryptoki::DataObject d = _pCryptoki->getDataByName(GIB_APPNAME, GIB_ACTIVE_LMK_INDEX);
	d.setValue(val.c_str(), val.length());
	return SUCCESS;
}

int SafenetHelperImpl::getFisCalNo(const VectorUChar inData, VectorUChar& outData)
{
	Cryptoki::Key priKey = _pCryptoki->getKeyByName(OC_PRIVATE_KEY,  GIB_PRIVATE_KEY_NAME);
	Cryptoki::MechanismInfo mInfo;
	mInfo._type = MT_RSA_PKCS;
	outData = priKey.decrypt(mInfo, inData);

	return SUCCESS;
}
int SafenetHelperImpl::getTraek(const VectorUChar& pgTrmk, KeyExchangeResponse& outData)
{
	// 2.13. C' => TRMK          Sg ile decrypt edilir.
	char 					keyVal[32];
	Cryptoki::MechanismInfo mInfo;

	mInfo._type 		= MT_RSA_PKCS;
	mInfo._param 		= keyVal;
	mInfo._paramLen 	= sizeof(keyVal);

	Cryptoki::KeyAttribute kAttr;
	kAttr._keyType 		= KT_AES;

	Cryptoki::Key sg 	= _pCryptoki->getKeyByName(OC_PRIVATE_KEY, GIB_PRIVATE_KEY_NAME);

	mInfo._param = NULL;
	mInfo._paramLen = 0L;
	mInfo._type = MT_RSA_PKCS;
	Cryptoki::Key trmk 	=  sg.unwrap(mInfo, pgTrmk, kAttr);

	// 2.14. E: TRAK create      AES256, session based
//	Cryptoki::KeyAttribute kAttr;
//	kAttr._label 		= GIB_TRAK_NAME;
//	kAttr._keyType 		= KT_AES;
//	kAttr._token 		= FALSE;
//	Cryptoki::Key trak 	= _pCryptoki->createSecretKey(GIB_TRAK_NAME, kAttr, mInfo);
//
//	// 2.15. F: TREK create      AES256, session based
//	kAttr._label 		= GIB_TREK_NAME;
//	Cryptoki::Key trek 	= _pCryptoki->createSecretKey(GIB_TREK_NAME, kAttr, mInfo);
//
//	// 2.16. G: active Lmk Index ActiveLmkIndex dataObject'te tutuluyor.
//	outData._lmkIndex 	= SafenetHelperUtil::getActiveLmkIndex(*_pCryptoki);
//	Cryptoki::Key lmk 	= SafenetHelperUtil::getActiveLmk(*_pCryptoki);
//
//	// 2.17. H: LMK(TRAK)        Bulunan LMK ile wrap yapilir.
//	outData._lmk_TRAK 	= lmk.wrap(mInfo, trak);
//
//	// 2.18. I: LMK(TREK)        Bulunan LMK ile wrap yapilir.
//	outData._lmk_TREK 	= lmk.wrap(mInfo, trek);
//
//	// 2.19. J: Kcv TRAK         Kcv hesaplanir.
//	outData._kcv_TRAK 	= trak.getKcv();
//
//	// 2.20. K: Kcv TREK         Kcv hesaplanir.
//	outData._kcv_TREK 	= trek.getKcv();
//
//	// 2.21. L: TRMK(TRAK)       wrap
//	outData._TRMK_TRAK 	= trmk.wrap(mInfo, trak);
//
//	// 2.22. M: TRMK(TREK)       wrap
//	outData._TRMK_TREK 	= trmk.wrap(mInfo, trek);

	// 2.23. N: Sg(L+M)          sign
	return SUCCESS;
}
int SafenetHelperImpl::processFirst(const ProcessFirstRequest& inData, ProcessFirstResponse& outData)
{
	// TODO implement this
	throw "Not implemented yet!";
	return SUCCESS;
}

/**
 *
 * */
int SafenetHelperImpl::processNext(const ProcessNextRequest& inData, ProcessNextResponse& outData)
{
	// TODO implement this
	throw "Not implemented yet!";
	return SUCCESS;
}


