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
#include "SafenetHelperUtil.h"

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

//	Cryptoki::KeyAttribute kAttr;
//	kAttr._decrypt 		= TRUE;
//	kAttr._encrypt 		= TRUE;
//	kAttr._extractable 	= FALSE;
//	kAttr._keyType 		= KT_DES2;
//	kAttr._private 		= TRUE;
//	kAttr._sensitive 	= TRUE;
//	kAttr._token 		= TRUE;
//	kAttr._unwrap 		= TRUE;
//	kAttr._wrap 		= TRUE;

	SafenetHelperUtil::createDES2Key(_pCryptoki, keyName);
//	_pCryptoki->createKey(keyName, kAttr, mInfo);

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
	SafenetHelperUtil::createDES2Key(_pCryptoki, keyName);

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
	char trekIV[32];
	char trakIV[32];
	char 					keyVal[32];
	Cryptoki::MechanismInfo mInfo;

	mInfo._type 		= MT_RSA_PKCS;
	mInfo._param 		= keyVal;
	mInfo._paramLen 	= sizeof(keyVal);

	Cryptoki::KeyAttribute kAttr;
	kAttr._keyType 		= KT_AES;

	Cryptoki::Key sg 	= _pCryptoki->getKeyByName(OC_PRIVATE_KEY, GIB_PRIVATE_KEY_NAME);

	mInfo._param 		= NULL;
	mInfo._paramLen 	= 0L;
	mInfo._type 		= MT_RSA_PKCS;
	Cryptoki::Key trmk 	=  sg.unwrap(mInfo, pgTrmk, kAttr);

// 2.14. E: TRAK create      AES256, session based
	std::stringstream ss("");
	srand(time(NULL) ^ getpid());
	// TODO isim random olmali. Test amacli olarak belirli bir isim secildi. Test case'de key'e tekrar erisilebilsin diye
	// ss << "TRAK_" << setfill('0') << setw(4) << random() % 10000 + 1;
	ss << GIB_TRAK_NAME;
	kAttr._label 		= ss.str();
	kAttr._keyType 		= KT_AES;
	kAttr._token 		= FALSE;

	mInfo._type = MT_AES_KEY_GEN;
	mInfo._param = trakIV;
	mInfo._paramLen = sizeof(trakIV);
	Cryptoki::Key trak 	= _pCryptoki->createSecretKey(ss.str(), kAttr, mInfo);

// 2.15. F: TREK create      AES256, session based
	ss.str("");
	srand(time(NULL) ^ getpid());
	// TODO isim random olmali. Test amacli olarak belirli bir isim secildi. Test case'de key'e tekrar erisilebilsin diye
	// ss << "TREK_" << setfill('0') << setw(4) << random() % 10000 + 1;
	ss << GIB_TREK_NAME;
	kAttr._label 		= ss.str();
	kAttr._keyType 		= KT_AES;
	kAttr._token 		= FALSE;
	mInfo._type 		= MT_AES_KEY_GEN;
	mInfo._param 		= trekIV;
	mInfo._paramLen 	= sizeof(trekIV);
	Cryptoki::Key trek 	= _pCryptoki->createSecretKey(ss.str(), kAttr, mInfo);

// 2.16. G: active Lmk Index ActiveLmkIndex dataObject'te tutuluyor.
	outData._lmkIndex 	= SafenetHelperUtil::getActiveLmkIndex(*_pCryptoki);
	Cryptoki::Key lmk 	= SafenetHelperUtil::getActiveLmk(*_pCryptoki);

// 2.17. H: LMK(TRAK)        Bulunan LMK ile wrap yapilir.
	mInfo._param 		= NULL;
	mInfo._paramLen 	= 0;
	mInfo._type 		= MT_DES3_ECB;
	outData._lmk_TRAK 	= lmk.wrap(mInfo, trak);

// 2.18. I: LMK(TREK)        Bulunan LMK ile wrap yapilir.
	mInfo._param 		= NULL;
	mInfo._paramLen 	= 0;
	mInfo._type 		= MT_DES3_ECB;
	outData._lmk_TREK 	= lmk.wrap(mInfo, trek);

// 2.19. J: Kcv TRAK         Kcv hesaplanir.
	outData._kcv_TRAK 	= trak.getKcv();

// 2.20. K: Kcv TREK         Kcv hesaplanir.
	outData._kcv_TREK 	= trek.getKcv();

// 2.21. L: TRMK(TRAK)       wrap
	mInfo._param 		= NULL;
	mInfo._paramLen 	= 0;
	mInfo._type 		= MT_AES_ECB;
	outData._TRMK_TRAK 	= trmk.wrap(mInfo, trak);

// 2.22. M: TRMK(TREK)       wrap
	mInfo._param 		= NULL;
	mInfo._paramLen 	= 0;
	mInfo._type 		= MT_AES_ECB;
	outData._TRMK_TREK 	= trmk.wrap(mInfo, trek);

// 2.23. N: Sg(L+M)          sign
	// TODO

	return SUCCESS;
}


int SafenetHelperImpl::processFirst(const ProcessFirstRequest& inData, ProcessFirstResponse& outData)
{
// 3.6. G ile LMK bulunur.
	Cryptoki::Key lmk = SafenetHelperUtil::getLmk(*_pCryptoki, inData._lmkIndex);

// 3.7. H' => TRAK elde edilir.   Unwrap
	Cryptoki::MechanismInfo mInfo;
	Cryptoki::KeyAttribute kAttr;
	mInfo._param 	= NULL;
	mInfo._paramLen = 0L;
	mInfo._type 	= MT_DES3_ECB;
	kAttr._keyType 	= KT_AES;
	Cryptoki::Key trak = lmk.unwrap(mInfo, inData._lmk_TRAK, kAttr);

// 3.8. I' => TREK elde edilir.   Unwrap
	mInfo._param 	= NULL;
	mInfo._paramLen = 0L;
	mInfo._type 	= MT_DES3_ECB;
	kAttr._keyType 	= KT_AES;
	Cryptoki::Key trek = lmk.unwrap(mInfo, inData._lmk_TREK, kAttr);

// 3.9. Kcv(H') == J ?  .         Hesaplanan H' kcv ile J esit mi?
	VectorUChar kcvTRAK = trak.getKcv();
	if (kcvTRAK != inData._kcv_TRAK) {
		throw ExceptionCryptoki(ERR_TRAK_KCV_INVALID, __FILE__, __LINE__);
		// TODO
	}

// 3.10. Kcv(I') == K ?           Hesaplanan I' kcv ile K esit mi?
	VectorUChar kcvTREK = trek.getKcv();
	if (kcvTREK != inData._kcv_TREK) {
		throw ExceptionCryptoki(ERR_TREK_KCV_INVALID, __FILE__, __LINE__);
		// TODO
	}

// 3.11. P' => Data elde edilir.  Decrypt
	mInfo._param 	= NULL;
	mInfo._paramLen = 0;
	mInfo._type 	= MT_AES_ECB;
	outData._clearData = trek.decrypt(mInfo, inData._trek_data);

// 3.12. R: SHA256(P')            Sha hesaplanır
	VectorUChar calcdSha256 = _pCryptoki->generateSHA256(outData._clearData);

// 3.13. Q' => SHA256(Data)       Decrypt
	mInfo._param 	= NULL;
	mInfo._paramLen = 0;
	mInfo._type 	= MT_AES_ECB;
	VectorUChar inSha256 = trak.decrypt(mInfo, inData._trak_sha256Data);

// 3.14. R == Q' ?                Hesaplanan SHA ile gelen SHA karsilastirilir.
	if (calcdSha256 != inSha256) {
		throw ExceptionCryptoki(ERR_SHA256DATA_INVALID, __FILE__, __LINE__);
	}

	return SUCCESS;
}

/**
 *
 * */
int SafenetHelperImpl::processNext(const ProcessNextRequest& inData, ProcessNextResponse& outData)
{
// 3.18. G ile LMK bulunur
	Cryptoki::Key lmk = SafenetHelperUtil::getLmk(*_pCryptoki, inData._lmkIndex);

// 3.19. H' => TRAK elde edilir.   Unwrap
	Cryptoki::MechanismInfo mInfo;
	Cryptoki::KeyAttribute kAttr;
	mInfo._param 	= NULL;
	mInfo._paramLen = 0L;
	mInfo._type 	= MT_DES3_ECB;
	kAttr._keyType 	= KT_AES;
	Cryptoki::Key trak = lmk.unwrap(mInfo, inData._lmk_TRAK, kAttr);

// 3.20. I' => TREK elde edilir.   Unwrap
	mInfo._param 	= NULL;
	mInfo._paramLen = 0L;
	mInfo._type 	= MT_DES3_ECB;
	kAttr._keyType 	= KT_AES;
	Cryptoki::Key trek = lmk.unwrap(mInfo, inData._lmk_TREK, kAttr);

// 3.21. Kcv(H') == J ?            Hesaplanan H' kcv ile J esit mi?
	VectorUChar kcvTRAK = trak.getKcv();
	if (kcvTRAK != inData._kcv_TRAK) {
		// TODO
	}

// 3.22. Kcv(I') == K ?            Hesaplanan I' kcv ile K esit mi?
	VectorUChar kcvTREK = trek.getKcv();
	if (kcvTREK != inData._kcv_TREK) {
		// TODO
	}
// 3.23. T: SHA256(S)              Verinin ozeti hesaplanir.
	VectorUChar calcdSha256 = _pCryptoki->generateSHA256(inData._data);

// 3.24. U: H'(T)                  Encrypt, ozet sifrelenir.
	mInfo._param 	= NULL;
	mInfo._paramLen = 0L;
	mInfo._type 	= MT_AES_ECB;
	outData._trak_sha256_data = trak.encrypt(mInfo, calcdSha256);

// 3.25. V: I'(S)                  Encrypt, veri sifrelenir.
	outData._treckData = trek.encrypt(mInfo, inData._data);

	return SUCCESS;
}


