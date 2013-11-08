//---------------------------------------------------------
// Mehmet Suyuti Dindar
// 30.10.2013
// SmartSoft
//---------------------------------------------------------

#include "SafenetHelperUtil.h"
#include "cryptokiHelper/DataObject.h"
#include "../include/SafenetHelperTypes.h"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <stdlib.h>

#include <algorithm>
#include <iterator>

using namespace Cryptoki;
using namespace std;

log4cxx::LoggerPtr g_logger(log4cxx::Logger::getLogger("main"));
log4cxx::LoggerPtr g_loggerCryptoki(log4cxx::Logger::getLogger("Cryptoki"));
log4cxx::LoggerPtr g_loggerKey(log4cxx::Logger::getLogger("Key"));
log4cxx::LoggerPtr g_loggerDataObject(log4cxx::Logger::getLogger("DataObject"));
log4cxx::LoggerPtr g_loggerTest(log4cxx::Logger::getLogger("Test"));


Cryptoki::Key SafenetHelperUtil::getActiveLmk(Cryptoki::CryptokiHelper& session)
{
	int lmkIndex = SafenetHelperUtil::getActiveLmkIndex(session);
	LOG4CXX_DEBUG(g_logger, "ActiveLMKIndex: " << lmkIndex);
	return getLmk(session, lmkIndex);
}

int SafenetHelperUtil::getActiveLmkIndex(Cryptoki::CryptokiHelper& session)
{
	DataObject d = session.getDataByName(GIB_APPNAME, GIB_ACTIVE_LMK_INDEX);
	VectorUChar val = d.getValue();
	val.push_back((unsigned char)NULL);
	int activeLmkIndex = atol((char*)val.data());
	return activeLmkIndex;
}

void SafenetHelperUtil::setActiveLmkIndex(Cryptoki::CryptokiHelper* pSession, int val)
{
	Cryptoki::DataObject d = pSession->getDataByName(GIB_APPNAME, GIB_ACTIVE_LMK_INDEX);
	stringstream ss;
	ss << std::setfill('0') << std::setw(4) << val;
	d.setValue(ss.str().c_str(), ss.str().length());
}

Cryptoki::Key SafenetHelperUtil::getLmk(Cryptoki::CryptokiHelper& session, int lmkIndex)
{
	std::stringstream ss;
	ss << "LMK_" << setfill('0') << setw(3) << lmkIndex;
	LOG4CXX_DEBUG(g_logger, "GetLmk: " << ss.str());
	return session.getKeyByName(OC_SECRET_KEY, ss.str());
}

Cryptoki::Key SafenetHelperUtil::createDES2Key(Cryptoki::CryptokiHelper* pSession, std::string keyName, Cryptoki::KeyAttribute attr)
{
	Cryptoki::Key 			key;

	Cryptoki::MechanismInfo mInfo;
	mInfo._type = MT_DES2_KEY_GEN;

	Cryptoki::KeyAttribute kAttr;
	kAttr._decrypt 		= TRUE & attr._decrypt;
	kAttr._encrypt 		= TRUE & attr._encrypt;
	kAttr._extractable 	= TRUE & attr._extractable;
	kAttr._keyType 		= KT_DES2;
	kAttr._private 		= TRUE & attr._private;
	kAttr._sensitive 	= TRUE & attr._sensitive;
	kAttr._token 		= TRUE & attr._token;
	kAttr._unwrap 		= TRUE & attr._unwrap;
	kAttr._wrap 		= TRUE & attr._wrap;
	kAttr._label		= attr._label.size() == 0 ?
													keyName :
													attr._label;

	key = pSession->createKey(keyName, kAttr, mInfo);
	return key;
}


Cryptoki::Key SafenetHelperUtil::createDES2Key(Cryptoki::CryptokiHelper* pSession, std::string keyName)
{
	Cryptoki::KeyAttribute kAttr;
	kAttr._decrypt 		= TRUE;
	kAttr._encrypt 		= TRUE;
	kAttr._extractable 	= TRUE;
	kAttr._keyType 		= KT_DES2;
	kAttr._private 		= TRUE;
	kAttr._sensitive 	= TRUE;
	kAttr._token 		= TRUE;
	kAttr._unwrap 		= TRUE;
	kAttr._wrap 		= TRUE;
	kAttr._label		= keyName;

	return createDES2Key(pSession, keyName, kAttr);
}

Cryptoki::Key SafenetHelperUtil::createAES256Key(Cryptoki::CryptokiHelper* pSession, std::string keyName)
{
	Cryptoki::KeyAttribute kAttr;
	kAttr._decrypt 		= TRUE;
	kAttr._encrypt 		= TRUE;
	kAttr._extractable 	= TRUE;
	kAttr._keyType 		= KT_AES;
	kAttr._private 		= TRUE;
	kAttr._sensitive 	= TRUE;
	kAttr._token 		= TRUE;
	kAttr._unwrap 		= TRUE;
	kAttr._wrap 		= TRUE;
	kAttr._label		= keyName;

	return createAES256Key(pSession, keyName, kAttr);
}

Cryptoki::Key SafenetHelperUtil::createAES256Key(Cryptoki::CryptokiHelper* pSession, std::string keyName, Cryptoki::KeyAttribute attr)
{
	Cryptoki::MechanismInfo mInfo;
	char 					iv[32];

	mInfo._type 		= MT_AES_KEY_GEN;
	mInfo._param 		= iv;
	mInfo._paramLen 	= sizeof(iv);

	Cryptoki::KeyAttribute kAttr;
	kAttr._decrypt 		= TRUE & attr._decrypt;
	kAttr._encrypt 		= TRUE & attr._encrypt;
	kAttr._extractable 	= TRUE & attr._extractable;
	kAttr._keyType 		= KT_AES;
	kAttr._private 		= TRUE & attr._private;
	kAttr._sensitive 	= TRUE & attr._sensitive;
	kAttr._token 		= TRUE & attr._token;
	kAttr._unwrap 		= TRUE & attr._unwrap;
	kAttr._wrap 		= TRUE & attr._wrap;
	kAttr._label		= attr._label.size() == 0 ?
													keyName :
													attr._label;

	return pSession->createSecretKey(keyName, kAttr, mInfo);
}
