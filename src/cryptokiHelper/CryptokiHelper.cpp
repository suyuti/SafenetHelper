#include <exception>
#include <iostream>
#include <cstdlib>
#include <vector>
#include <iterator>
#include <cstring>
#include <iomanip>
#include <sstream>

#include "Key.h"
#include "CryptokiHelper.h"
#include "ExceptionCryptoki.h"
#include "CryptokiHelperTypes.h"
#include "../util/Buffer.h"

#include "cryptoki.h"
#include "ctvdef.h"
#include "ctutil.h"
#include "genmacro.h"
#include "hex2bin.h"

using namespace std;
using namespace Util;

STATIC CryptokiHelper* CryptokiHelper::pInstance = NULL;

PUBLIC CryptokiHelper* CryptokiHelper::instance()
{
   if (!pInstance)
   {
	pInstance = new CryptokiHelper();
	pInstance->initialize();
	pInstance->openSession(0, FLG_RW_SESSION);
	pInstance->login(UT_USER, (uchar *)"1234", 4);
   }

   return pInstance;
}

PRIVATE CryptokiHelper::CryptokiHelper()
{
	mLog = Util::Logger::instance();

	mSessionHndl = CK_INVALID_HANDLE;
	rv = CKR_OK;
	pAdminPIN = (CK_CHAR *) ADMIN_PIN;
	adminPINLen = 0;
}

PUBLIC CryptokiHelper::~CryptokiHelper()
{
    if (mSessionHndl != CK_INVALID_HANDLE) C_CloseSession(mSessionHndl);
    C_Finalize(NULL);
}

PUBLIC void CryptokiHelper::initialize()
{
#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("Cryptoki initializing...");
#endif
	rv = C_Initialize(NULL);

	if(rv != CKR_OK)
		throw ExceptionCryptoki(rv, "Cryptoki not initialized", __FILE__, __LINE__);

#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("Cryptoki Initialized...");
#endif
}

PUBLIC void CryptokiHelper::openSession(ulong slotId, enum CKFlag sessionType)
{
#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("Opening session on slot " + util::toStr(slotId, "H2"));
#endif

    rv = C_OpenSession(slotId, (CK_FLAGS)sessionType, NULL, NULL, &mSessionHndl);
    if (rv != CKR_OK)
    	throw ExceptionCryptoki(rv, "Session not opened", __FILE__, __LINE__);

#ifdef DIAGNOSTIC_ENABLED
    mLog->writeLn("Session " + util::toStr(mSessionHndl, "H2") + " is opened on slot " + util::toStr(slotId, "H2"));
#endif
}

PUBLIC void CryptokiHelper::closeSession()
{
#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("Session " + util::toStr(mSessionHndl, "H2") + " is closing...");
#endif

	C_CloseSession(mSessionHndl);

#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("Session closed...");
#endif
}
PUBLIC void CryptokiHelper::login(std::string& pin, enum UserType userType)
{
	this->login(userType, (uchar*)pin.c_str(), pin.size());
}

PUBLIC void CryptokiHelper::login(enum UserType userType, uchar *pinCode, ulong pinLen)
{
#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("User login...");
#endif

	rv = C_Login(mSessionHndl, (CK_USER_TYPE)userType, pinCode, pinLen);
    if (rv != CKR_OK)
    	throw ExceptionCryptoki(rv,  "can not log in", __FILE__, __LINE__);

#ifdef DIAGNOSTIC_ENABLED
    mLog->writeLn("User logged in...");
#endif
}

PUBLIC ulong CryptokiHelper::getAdminSlotId()
{
    CK_RV rv = CKR_OK;
    CK_SLOT_ID* pSlots = NULL;
    CK_SLOT_ID adminSlotId = 0x00000000;
    CK_NUMERIC count = 0;

    uint deviceNum = 0;

    uint adminSlotCount = 0;

    C_GetSlotList(FALSE, NULL, &count); // Once kac tane slot olduguna bakalim (2. parametreyi null gectik)

    pSlots = (CK_SLOT_ID_PTR) malloc(sizeof(CK_SLOT_ID) * count); // slot id'ler icin yeteri kadar yer ayiralim.

    if(pSlots == NULL)
    	throw ExceptionCryptoki(ExceptionCryptoki::ERROR_MEMORY_ALLOCATION, "Slot count zero", __FILE__, __LINE__);

    rv = C_GetSlotList(FALSE, pSlots, &count);
    if (rv != CKR_OK)
    {
    	free(pSlots);
    	throw ExceptionCryptoki(rv,  "Could not get slot list", __FILE__, __LINE__);
    }


    for (uint i=0; i< count; ++i)
    {
    	CK_SLOT_INFO slotInfo;
    	rv = C_GetSlotInfo(pSlots[i], &slotInfo);
        if (rv != CKR_OK)
        	throw ExceptionCryptoki(rv,  "Could not get slot info", __FILE__, __LINE__);

		if ((slotInfo.flags & CKF_REMOVABLE_DEVICE) == 0)
        {
			CK_TOKEN_INFO tokenInfo;
			rv = C_GetTokenInfo(pSlots[i], &tokenInfo);
	        if (rv != CKR_OK)
	        	throw ExceptionCryptoki(rv,  "Could not get token info", __FILE__, __LINE__);

			if (tokenInfo.flags & CKF_ADMIN_TOKEN)
            {
                ++adminSlotCount;

                if ((adminSlotCount-1) == deviceNum)
                {
				    adminSlotId = pSlots[i];

				    free(pSlots);
                    pSlots = NULL;
                    break;
                }
			}
        }
    }

    return adminSlotId;
}

PUBLIC ulong CryptokiHelper::createSlot()
{
#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("Creating slot...");
#endif
    CK_OBJECT_HANDLE hObject = CK_INVALID_HANDLE;

    static CK_OBJECT_CLASS objClass = CKO_SLOT; // A slot is represented by a CKO_SLOT object on the admin token.
    static CK_BBOOL bTrue = TRUE;

    CK_ATTRIBUTE slotTpl[] =
    {
        {CKA_CLASS, &objClass,  sizeof(CK_OBJECT_CLASS)},
        {CKA_TOKEN, &bTrue,     sizeof(CK_BBOOL)},
    };

    CK_COUNT slotTplSize = sizeof(slotTpl)/sizeof(CK_ATTRIBUTE);

    CK_RV rv = C_CreateObject(mSessionHndl, slotTpl, slotTplSize, &hObject);
	if(rv != CKR_OK)
		throw ExceptionCryptoki(rv, "Could not create object",__FILE__, __LINE__);

#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("Slot created...");
#endif

    return hObject;
}

PUBLIC Key CryptokiHelper::getKeyByName(ObjectClass objClass,	const std::string keyName)
{
#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("Finding key " + keyName);
#endif

	Key retKey(mSessionHndl);

    CK_ATTRIBUTE objectTemplate[] =
    {
        {CKA_CLASS,         NULL,       0},
        {CKA_LABEL,         NULL,       0},
    };

    CK_SIZE templateSize = sizeof(objectTemplate) / sizeof(CK_ATTRIBUTE);

    CK_ULONG numObjectsToFind = 1;
    CK_ULONG numObjectsFound = 0;

    CK_ATTRIBUTE* pAttr = NULL;

    pAttr = FindAttribute(CKA_CLASS, objectTemplate, templateSize); /* First set the object class ... */
    pAttr->pValue = &objClass;
    pAttr->ulValueLen = sizeof(CK_OBJECT_CLASS);

    pAttr = FindAttribute(CKA_LABEL, objectTemplate, templateSize); /* Set the Label */
    pAttr->pValue = (CK_VOID_PTR) keyName.c_str();
    pAttr->ulValueLen = keyName.length();;

    rv = C_FindObjectsInit(mSessionHndl, objectTemplate, templateSize);
    if (rv != CKR_OK)
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);

    rv = C_FindObjects(mSessionHndl, &(retKey.mObjectHandle), numObjectsToFind,  &numObjectsFound);
    if (rv != CKR_OK)
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);

    rv = C_FindObjectsFinal(mSessionHndl);
    if (rv != CKR_OK)
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);

    if (numObjectsFound == 0)
    {
		#ifdef DIAGNOSTIC_ENABLED
			mLog->writeLn(keyName + " key NOT found ");
		#endif

        throw ExceptionCryptoki(ExceptionCryptoki::OBJECT_NOT_FOUND, keyName, __FILE__, __LINE__);
    }

#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn(keyName + " key found ");
#endif

	return retKey;
}

Key CryptokiHelper::generateSecretKey(const std::string keyName, bool isTokenObj)
{
#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("Generating 3DESKey  " + keyName);
#endif

	CK_BBOOL isTokenObject = (isTokenObj)? TRUE : FALSE;

	Key retKey(mSessionHndl);

    static CK_BBOOL ckTrue = TRUE;

    retKey.mMech.mechanism =  CKM_DES2_KEY_GEN;
    retKey.mMech.pParameter = NULL_PTR;
    retKey.mMech.parameterLen =0;


    CK_ATTRIBUTE tpl[] =
    {
        {CKA_TOKEN,         &isTokenObject,   sizeof(CK_BBOOL)},
        {CKA_LABEL,			(CK_VOID_PTR)keyName.c_str(), 	keyName.length()},
        {CKA_WRAP,          &ckTrue,    sizeof(CK_BBOOL)},
        {CKA_ENCRYPT,       &ckTrue,    sizeof(CK_BBOOL)},
        {CKA_DECRYPT,       &ckTrue,    sizeof(CK_BBOOL)},
        {CKA_UNWRAP,        &ckTrue,    sizeof(CK_BBOOL)},
        {CKA_EXTRACTABLE,   &ckTrue,    sizeof(CK_BBOOL)},
        {CKA_SENSITIVE,     &ckTrue,    sizeof(CK_BBOOL)},
        {CKA_PRIVATE, 		&ckTrue, 	sizeof(CK_BBOOL)},
    };

    CK_COUNT tplSize = sizeof(tpl)/sizeof(CK_ATTRIBUTE);

    rv = C_GenerateKey(mSessionHndl, &retKey.mMech, tpl, tplSize, &retKey.mObjectHandle);
    if (rv != CKR_OK)
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);

#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn(keyName + " generated");
#endif

	return retKey;
}

KeyPair CryptokiHelper::generateKeyPair(std::string pbKeyName, std::string prKeyName, bool isTokenObj)
{
#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("Generating KeyPair  " + pbKeyName + " and " + prKeyName);
#endif

    CK_OBJECT_HANDLE hPublicKey;
    CK_OBJECT_HANDLE hPrivateKey;

    CK_BBOOL isTokenObject = (isTokenObj)? TRUE : FALSE;

	CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};

	CK_ULONG modulusBits = 2048; // keyLength
	CK_BYTE publicExponent[3] = { 0x01, 0x00, 0x01};
	CK_BYTE subject[] = "TESTKEY";
	CK_BYTE id[] = {0x01};

	CK_BBOOL ckTRUE = TRUE;
	CK_BBOOL ckFALSE = FALSE;

    CK_ATTRIBUTE publicKeyTemplate[] =
	{
		{CKA_TOKEN,				&isTokenObject,					sizeof(CK_BBOOL)},
		{CKA_LABEL, 			(CK_VOID_PTR)pbKeyName.c_str(),	pbKeyName.length()},
		{CKA_PRIVATE, 			&ckFALSE, 						sizeof(CK_BBOOL)},
	    {CKA_ENCRYPT, 			&ckTRUE,						sizeof(CK_BBOOL)},
	    {CKA_VERIFY, 			&ckTRUE,						sizeof(CK_BBOOL)},
	    {CKA_WRAP, 				&ckTRUE,						sizeof(CK_BBOOL)},
	    {CKA_MODULUS_BITS, 		&modulusBits,					sizeof(modulusBits)},
	    {CKA_PUBLIC_EXPONENT, 	publicExponent,					sizeof(publicExponent)},
	};
    CK_COUNT pbkTACount = sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE);


	CK_ATTRIBUTE privateKeyTemplate[] =
	{
		{CKA_TOKEN,             &isTokenObject,    				sizeof(CK_BBOOL)},
		{CKA_LABEL, 			(CK_VOID_PTR)prKeyName.c_str(), prKeyName.length()},
	    {CKA_TOKEN, 			&ckTRUE, 						sizeof(CK_BBOOL)},
	    {CKA_PRIVATE, 			&ckTRUE, 						sizeof(CK_BBOOL)},
	    {CKA_SUBJECT, 			subject, 						sizeof(subject)},
	    {CKA_ID, 				id, 							sizeof(id)},
	    {CKA_SENSITIVE, 		&ckTRUE, 						sizeof(CK_BBOOL)},
	    {CKA_DECRYPT, 			&ckTRUE, 						sizeof(CK_BBOOL)},
	    {CKA_SIGN,	 			&ckTRUE, 						sizeof(CK_BBOOL)},
	    {CKA_UNWRAP, 			&ckTRUE, 						sizeof(CK_BBOOL)},
		{CKA_EXTRACTABLE,       &ckTRUE,    					sizeof(CK_BBOOL)},
		{CKA_EXPORTABLE,        &ckTRUE,    					sizeof(CK_BBOOL)},
		{CKA_MODIFIABLE,      	&ckFALSE,    					sizeof(CK_BBOOL)}
	};
	CK_COUNT prkTACount = sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE);

	rv = C_GenerateKeyPair(mSessionHndl, &mechanism, publicKeyTemplate, pbkTACount, privateKeyTemplate, prkTACount, &hPublicKey, &hPrivateKey);
    if (rv != CKR_OK)
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);

	KeyPair kp;
	kp.privateKey.mSessionHndl = mSessionHndl;
	kp.publicKey.mSessionHndl = mSessionHndl;
	kp.privateKey.mObjectHandle = hPrivateKey;
	kp.publicKey.mObjectHandle = 	hPublicKey;

#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("KeyPair  " + pbKeyName + " and " + prKeyName + " generated...");
#endif

	return kp;
}

PUBLIC Key CryptokiHelper::createSecretKey(const uchar* keyVal, ulong keyLen, const std::string keyName, bool isTokenObj)
{
#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("Creating secret Key  " + keyName +" ...");
#endif

	CK_OBJECT_CLASS _keyClass = CKO_SECRET_KEY;
	CK_KEY_TYPE 	_keyType = CKK_DES2;
	CK_BBOOL ckTrue = TRUE;
	CK_BBOOL isTokenObject = (isTokenObj)? TRUE : FALSE;
	CK_BYTE* _keyVal = new uchar[keyLen]; // parametre ile gecilen key'in parite bilgisini degistirmemek lazım

	memcpy(_keyVal, keyVal, keyLen);

	SetOddParity(_keyVal, keyLen); // cutil.a kutuphanesinde var, kendimiz bu rutini yazalim.

	CK_ATTRIBUTE keyTemplate[] =
	{
		{CKA_VALUE, 		_keyVal, 				keyLen            },
	    {CKA_CLASS, 		&_keyClass, 		    sizeof(_keyClass) },
	    {CKA_KEY_TYPE, 		&_keyType, 				sizeof(_keyType)  },
        {CKA_TOKEN,        	&isTokenObject,   		sizeof(CK_BBOOL)  },
        {CKA_PRIVATE,      	&ckTrue,   				sizeof(CK_BBOOL)  },
        {CKA_WRAP,          &ckTrue,    			sizeof(CK_BBOOL)  },
        {CKA_UNWRAP,        &ckTrue,    			sizeof(CK_BBOOL)  },
        {CKA_EXTRACTABLE,	&ckTrue,    			sizeof(CK_BBOOL)  },
        {CKA_SENSITIVE,     &ckTrue,    			sizeof(CK_BBOOL)  },
        {CKA_LABEL,			(CK_VOID_PTR)keyName.c_str(), 	keyName.length()},
	};
	CK_COUNT atrCount = sizeof(keyTemplate)/sizeof(CK_ATTRIBUTE);

	Key retKey;
	retKey.mSessionHndl = mSessionHndl;
	rv = C_CreateObject(mSessionHndl, keyTemplate, atrCount, &retKey.mObjectHandle);
	delete[]_keyVal;
	if (rv != CKR_OK)
		throw ExceptionCryptoki(rv, __FILE__, __LINE__);

#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn(keyName + " key created...");
#endif

	return retKey;
}

Key CryptokiHelper::createRSAPublicKey(uchar* modulus, ulong modulusLen, uchar* exponent, ulong exponentLen, const std::string keyName, bool isTokenObj)
{
#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("Creating RSA Public Key  " + keyName + " ...");
#endif

	CK_OBJECT_CLASS _objClass = CKO_PUBLIC_KEY;
	CK_KEY_TYPE _keyType = CKK_RSA;
	CK_BBOOL isTokenObject = (isTokenObj)? TRUE : FALSE;
	CK_BBOOL ckTRUE = TRUE;

	CK_ATTRIBUTE pbkTemplate[] =
	{
	    {CKA_CLASS, 			&_objClass, 					sizeof(_objClass)},
	    {CKA_KEY_TYPE, 			&_keyType, 						sizeof(_keyType)},
	    {CKA_TOKEN, 			&isTokenObject, 				sizeof(CK_BBOOL)},
	    {CKA_WRAP, 				&ckTRUE, 						sizeof(CK_BBOOL)},
	    {CKA_ENCRYPT, 			&ckTRUE, 						sizeof(CK_BBOOL)},
	    {CKA_EXTRACTABLE,		&ckTRUE,    					sizeof(CK_BBOOL)},
	    {CKA_MODULUS, 			modulus, 						modulusLen},
	    {CKA_PUBLIC_EXPONENT, 	exponent, 						exponentLen},
	    {CKA_LABEL, 			(CK_VOID_PTR)keyName.c_str(), 	keyName.length()}
	};

	CK_COUNT atrCount = sizeof(pbkTemplate)/sizeof(CK_ATTRIBUTE);

	Key retKey;
	retKey.mSessionHndl = mSessionHndl;
	rv = C_CreateObject(mSessionHndl, pbkTemplate, atrCount, &retKey.mObjectHandle);

	if (rv != CKR_OK)
		throw ExceptionCryptoki(rv, __FILE__, __LINE__);

#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("RSA Public Key  " + keyName + " created...");
#endif

	return retKey;
}

PUBLIC Key CryptokiHelper::createRSAPrivateKey(const std::string keyName)
{
#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("Creating RSA Private Key  " + keyName + " ...");
#endif

	//TODO implement createRSAPrivateKey
	Key retKey;

#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("RSA Private Key  " + keyName + " created...");
#endif

	return retKey;
}

PRIVATE uchar* CryptokiHelper::calculateDerivationData(const uchar* termId,	const uchar* fiscalNo, const uchar* tuks)
{
	static uchar derivationData[16] ={0};
	static uchar tmpBuf[16] = {0x00};

	memmove(derivationData + 0x00, fiscalNo + 0x00, 12);
	memmove(derivationData + 0x0C, fiscalNo + 0x00, 4);

	memmove(tmpBuf + 0x00, termId + 0x00, 8);
	memmove(tmpBuf + 0x08, termId + 0x00, 8);
	Buffer::Xor(derivationData, tmpBuf, 16);

	memmove(tmpBuf + 0x00, tuks + 0x00, 4);
	memmove(tmpBuf + 0x04, tuks + 0x00, 4);
	memmove(tmpBuf + 0x08, tuks + 0x00, 4);
	memmove(tmpBuf + 0x0C, tuks + 0x00, 4);
	Buffer::Xor(derivationData, tmpBuf, 16);

	return derivationData;
}

PUBLIC std::vector<CK_BYTE> CryptokiHelper::deriveKey(ushort idxCMK, const uchar* derivationData, ulong derDataLen, bool test)
{
#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("Deriving new key...");
#endif

	std::stringstream ss;
	uchar initVector[8];
	memset(initVector, 0x00, 8);
	if(test==true)
	{
		ss << "T_CMK_" << setfill('0')<<setw(2) << (int)idxCMK;
	}
	else
	{
		ss << "CMK_" << setfill('0')<<setw(2) << (int)idxCMK;
	}

	std::string keyNameCK = ss.str();

	Key rootKey = getKeyByName(OC_SECRET_KEY, keyNameCK);

	std::vector<uchar> vecDerivedKey = rootKey.encryptData(MT_DES3_ECB, (uchar*)derivationData, derDataLen);

#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("New key" + ss.str() + " derived...");
#endif

	return vecDerivedKey;
}

PUBLIC void CryptokiHelper::generateCMK(ushort idx, bool test)
{
#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("Generating CMKs...");
#endif

	std::stringstream ss;
	uchar initVector[8];
	memset(initVector, 0x00, 8);
	uchar *ckaID;
	uint ckaIDSize=0;
	if(test==true)
	{
		ss << "T_CMK_" << setfill('0')<<setw(2) << (int)idx;
		ckaID = new uchar[5];
		ckaIDSize = 5;
		memcpy(ckaID, "T_CMK", 5);
	}
	else
	{
		ss << "CMK_" << setfill('0')<<setw(2) << (int)idx;
		ckaID = new uchar[3];
		ckaIDSize = 3;
		memcpy(ckaID, "CMK", 3);
	}

	std::string keyNameCK = ss.str();

	try
	{
		this->getKeyByName(OC_SECRET_KEY, keyNameCK);
#ifdef DIAGNOSTIC_ENABLED
		mLog->writeLn(keyNameCK +" is already created, skipping" );
#endif
	}
	catch (ExceptionCryptoki &ex)
	{
		if(ex.mExceptionType == ExceptionCryptoki::OBJECT_NOT_FOUND)
		{
#ifdef DIAGNOSTIC_ENABLED
			mLog->writeLn(keyNameCK +" is not found, now creating...");
#endif
		    static CK_BBOOL ckTrue = TRUE;
		    CK_OBJECT_HANDLE hKey;
		    CK_MECHANISM mech;
		    mech.mechanism = MT_DES2_KEY_GEN;
		    mech.pParameter = NULL_PTR;
		    mech.parameterLen = 0;

		    CK_ATTRIBUTE tpl[] =
		    {
		        {CKA_TOKEN,         &ckTrue,   sizeof(CK_BBOOL)},
		        {CKA_LABEL,			(CK_VOID_PTR)keyNameCK.c_str(), keyNameCK.length()},
		        {CKA_ID,			(CK_VOID_PTR)ckaID, ckaIDSize}, //CMK ların ID degeri prod için "CMK" test için "T_CMK" olarak set edilir.
		        {CKA_WRAP,          &ckTrue,    sizeof(CK_BBOOL)},
		        {CKA_UNWRAP,        &ckTrue,    sizeof(CK_BBOOL)},
		        {CKA_EXTRACTABLE,   &ckTrue,    sizeof(CK_BBOOL)},
		        {CKA_SENSITIVE,     &ckTrue,    sizeof(CK_BBOOL)},
		        {CKA_PRIVATE,       &ckTrue,   	sizeof(CK_BBOOL)},
		    };

		    CK_COUNT tplSize = sizeof(tpl)/sizeof(CK_ATTRIBUTE);

		    rv = C_GenerateKey(mSessionHndl, &mech, tpl, tplSize, &hKey);

#ifdef DIAGNOSTIC_ENABLED
			mLog->writeLn(keyNameCK +" created...");
#endif
		}
		else
		{
			//Eğer başka bir hata varsa ckaID alanını bırakıp exceptionu rethrow edelim.
			delete[] ckaID;
			throw;
		}
	}

	delete[] ckaID;

#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("CMKs created...");
#endif
}

/**
 * CMK lar uretilirken ID attribute degerleri {'C','M','K'} olarak set ediliyor. CMK ları bulurken de ismine gore degil ID'sine
 * göre araniyor.
 */
PUBLIC ulong CryptokiHelper::getCMKCount(bool test)
{
#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("Finding CMK count...");
#endif

	CK_ULONG numObjectsToFind = 20;
	CK_ULONG nbObjectFound=0;
	CK_OBJECT_HANDLE hObjects = 0;

	uchar *ckaID;
	uint ckaIDSize=0;
	if(test==true)
	{
		ckaID = new uchar[5];
		ckaIDSize = 5;
		memcpy(ckaID, "T_CMK", 5);
	}
	else
	{
		ckaID = new uchar[3];
		ckaIDSize = 3;
		memcpy(ckaID, "CMK", 3);
	}

	try
	{
		CK_OBJECT_CLASS ckClass = CKO_SECRET_KEY;

		CK_ATTRIBUTE objectTemplate[] =
		{
			{CKA_CLASS,         &ckClass,       sizeof(CK_OBJECT_CLASS)},
			{CKA_ID,			ckaID, 			ckaIDSize},
		};

		CK_SIZE templateSize = sizeof(objectTemplate) / sizeof(CK_ATTRIBUTE);

		rv = C_FindObjectsInit(mSessionHndl, objectTemplate, templateSize);
		if (rv != CKR_OK)
			throw ExceptionCryptoki(rv, __FILE__, __LINE__);

		rv = C_FindObjects(mSessionHndl, &hObjects, numObjectsToFind,  &nbObjectFound);
		if (rv != CKR_OK)
			throw ExceptionCryptoki(rv, __FILE__, __LINE__);

		rv = C_FindObjectsFinal(mSessionHndl);
		if (rv != CKR_OK)
			throw ExceptionCryptoki(rv, __FILE__, __LINE__);

		if (nbObjectFound == 0)
			throw ExceptionCryptoki(ExceptionCryptoki::OBJECT_NOT_FOUND, __FILE__, __LINE__);
	}
	catch(...) {}

	delete [] ckaID;

#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("CMK count found...");
#endif

	return nbObjectFound;
}

PUBLIC uint CryptokiHelper::createDataObject(std::string appName, std::string objName, uchar* pData, int dataLen)
{
#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("Creating data object " + objName +"...");
#endif

	CK_OBJECT_HANDLE hData;

	hData = this->getDataObject(appName, objName);

	if (hData != 0)
	{
#ifdef DIAGNOSTIC_ENABLED
		mLog->writeLn(appName + "::" + objName + " object is already exsit, skiping..." );
#endif
		return hData; //Eğer daha once bu isimde bir obje uretilmişse onun handle'ini döneriz.
	}

	CK_OBJECT_CLASS tClass = CKO_DATA;
	CK_BBOOL ckTrue = TRUE;
	CK_ATTRIBUTE dTemplate[] =
	{
	    {CKA_CLASS, 		&tClass, 					sizeof(tClass)	},
	    {CKA_TOKEN, 		&ckTrue, 					sizeof(CK_BBOOL)},
	    {CKA_APPLICATION, 	(void *)appName.c_str(), 	appName.length()},
	    {CKA_PRIVATE, 		&ckTrue, 					sizeof(CK_BBOOL)},
	    {CKA_LABEL, 		(void *)objName.c_str(), 	objName.length()},
	    {CKA_VALUE, 		pData, 						dataLen			},
	};

	CK_COUNT attributeCount = sizeof(dTemplate)/sizeof(CK_ATTRIBUTE);

    rv = C_CreateObject(mSessionHndl, dTemplate, attributeCount, &hData);
	if (rv != CKR_OK)
		throw ExceptionCryptoki(rv, __FILE__, __LINE__);

#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("Data object" + objName + " created...");
#endif

	return hData;
}

PUBLIC void CryptokiHelper::setDataObjectValue(std::string appName, std::string objName, const uchar* pData, int dataLen)
{
#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("Setting value of data object " + objName +"...");
#endif

	CK_ATTRIBUTE dTemplate[] = {{CKA_VALUE, (void *)pData, dataLen}};

	CK_OBJECT_HANDLE hObject =getDataObject(appName, objName);

	rv = C_SetAttributeValue(mSessionHndl, hObject, dTemplate, 1);
	if (rv != CKR_OK)
		throw ExceptionCryptoki(rv, __FILE__, __LINE__);

#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("Value of data object" + objName + " is set...");
#endif

	return;
}

PUBLIC void CryptokiHelper::getDataObjectValue(std::string appName, std::string objName, uchar* outBuf, int* outLen)
{
#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("Getting value of data object " + objName +"...");
#endif
	CK_OBJECT_HANDLE hObject =getDataObject(appName, objName);

	CK_ATTRIBUTE oTemplate[] = {{CKA_VALUE, NULL, 0}};

	rv = C_GetAttributeValue(mSessionHndl, hObject, oTemplate, 1); // Sadece attribute size öğrenmek için
	if (rv != CKR_OK)
		throw ExceptionCryptoki(rv, __FILE__, __LINE__);

	uchar *pValue = (CK_BYTE_PTR) malloc(oTemplate[0].valueLen);
	oTemplate[0].pValue = pValue;

	rv = C_GetAttributeValue(mSessionHndl, hObject, oTemplate, 1);
	if (rv != CKR_OK)
	{
		delete(pValue);
		throw ExceptionCryptoki(rv, __FILE__, __LINE__);
	}

	*outLen = oTemplate[0].valueLen;
	memcpy(outBuf, oTemplate[0].pValue, oTemplate[0].valueLen);

	delete(pValue);

#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("Value of data object" + objName + " is got...");
#endif

	return;
}

PUBLIC int CryptokiHelper::getDataObject(std::string appName, std::string objName)
{
#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("Finding Object " + appName +"::" +objName);
#endif

	CK_OBJECT_HANDLE hData;

    CK_ATTRIBUTE objectTemplate[] =
    {
        {CKA_CLASS,         NULL,       0},
        {CKA_APPLICATION, 	NULL, 		0},
        {CKA_LABEL,         NULL,       0},
    };

    CK_SIZE templateSize = sizeof(objectTemplate) / sizeof(CK_ATTRIBUTE);

    CK_ULONG numObjectsToFind = 1;
    CK_ULONG numObjectsFound = 0;

    CK_OBJECT_CLASS oClass = CKO_DATA;

    CK_ATTRIBUTE* pAttr = NULL;

    pAttr = FindAttribute(CKA_CLASS, objectTemplate, templateSize); /* First set the object class ... */
    pAttr->pValue = &oClass;
    pAttr->ulValueLen = sizeof(CK_OBJECT_CLASS);

    pAttr = FindAttribute(CKA_APPLICATION, objectTemplate, templateSize); /* Set the Application */
    pAttr->pValue = (CK_VOID_PTR) appName.c_str();
    pAttr->ulValueLen = appName.length();;

    pAttr = FindAttribute(CKA_LABEL, objectTemplate, templateSize); /* Set the Label */
    pAttr->pValue = (CK_VOID_PTR) objName.c_str();
    pAttr->ulValueLen = objName.length();;

    rv = C_FindObjectsInit(mSessionHndl, objectTemplate, templateSize);
    if (rv != CKR_OK)
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);

    rv = C_FindObjects(mSessionHndl, &hData, numObjectsToFind,  &numObjectsFound);
    if (rv != CKR_OK)
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);

    rv = C_FindObjectsFinal(mSessionHndl);
    if (rv != CKR_OK)
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);

    if (numObjectsFound == 0)
        return 0;

#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("Object " +appName + "::" + objName + " is found ");
#endif

	return hData;
}

PUBLIC std::vector<uchar> CryptokiHelper::getWrappedCMKList(std::string wrapKeyName, bool test)
{
	std::vector<uchar> outVec;
	CK_ULONG maxNumObjectsToFind = 20;
	CK_ULONG nbObjectFound = 0;
	CK_OBJECT_HANDLE *phObjects= (ulong*)new uchar[maxNumObjectsToFind * sizeof(CK_OBJECT_HANDLE_PTR)];
	uchar iv[8] = {0,0,0,0,0,0,0,0};

	uchar *ckaID;
	uint ckaIDSize=0;
	if(test==true)
	{
		ckaID = new uchar[5];
		ckaIDSize = 5;
		memcpy(ckaID, "T_CMK", 5);
	}
	else
	{
		ckaID = new uchar[3];
		ckaIDSize = 3;
		memcpy(ckaID, "CMK", 3);
	}

	try
	{
		CK_OBJECT_CLASS ckClass = CKO_SECRET_KEY;

		CK_ATTRIBUTE objectTemplate[] =
		{
			{CKA_CLASS,         &ckClass,       sizeof(CK_OBJECT_CLASS)},
			{CKA_ID,			ckaID, 		ckaIDSize},
		};

		CK_SIZE templateSize = sizeof(objectTemplate) / sizeof(CK_ATTRIBUTE);


		rv = C_FindObjectsInit(mSessionHndl, objectTemplate, templateSize);
		if (rv != CKR_OK)
			throw ExceptionCryptoki(rv, __FILE__, __LINE__);

		rv = C_FindObjects(mSessionHndl, phObjects, maxNumObjectsToFind,  &nbObjectFound);
		if (rv != CKR_OK)
			throw ExceptionCryptoki(rv, __FILE__, __LINE__);

		rv = C_FindObjectsFinal(mSessionHndl);
		if (rv != CKR_OK)
			throw ExceptionCryptoki(rv, __FILE__, __LINE__);

		if (nbObjectFound == 0)
			throw ExceptionCryptoki(ExceptionCryptoki::OBJECT_NOT_FOUND, __FILE__, __LINE__);


		Key zmk = getKeyByName(OC_SECRET_KEY, wrapKeyName);

		for(uint i=0; i<nbObjectFound; ++i)
		{
			Key cmk(mSessionHndl);
			cmk.mObjectHandle = phObjects[i];
			std::vector<uchar>  vecWCMK = zmk.wrapKey(MT_DES3_ECB, cmk);
			outVec.insert(outVec.end(), vecWCMK.begin(),  vecWCMK.end());
		}
	}
	catch(exception &ex){}

	delete [] phObjects;
	delete[] ckaID;
	return outVec;
}
