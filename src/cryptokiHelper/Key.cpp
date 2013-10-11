/*
 * Key.cpp
 *
 *  Created on: 1 Eyl 2013
 *      Author: hakilic
 */
#include <iostream>
#include <string>
#include <string.h>

#include "CryptokiHelperTypes.h"
#include "Key.h"
#include "ExceptionCryptoki.h"

#include "ctutil.h"
#include "cryptoki.h"


using namespace std;

PUBLIC Key::Key()
{
	rv				= 0;
	mObjectHandle 	= 0;
	mSessionHndl 	= 0;
	mLog 			= Util::Logger::instance();
	mMechType 		= MT_DES3_ECB;
}

PUBLIC Key::Key(CK_SESSION_HANDLE hndl)
{
	rv				= 0;
	mSessionHndl 	= hndl;
	mObjectHandle 	= 0;
	mLog 			= Util::Logger::instance();
	//TODO MechanismType nasıl set edilecek
	mMechType = MT_DES3_ECB;
}

PUBLIC Key::~Key()
{

}

PUBLIC void Key::rename(const std::string newName)
{
#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("Renaming key handle " + util::toStr(mObjectHandle, "H4"));
#endif

	CK_ATTRIBUTE _templapte[] = { {CKA_LABEL, (CK_VOID_PTR)newName.c_str(), newName.length()} };

	CK_RV rv = C_SetAttributeValue(mSessionHndl, mObjectHandle, _templapte, 1);
	if(rv != CKR_OK)
		throw ExceptionCryptoki(rv, __FILE__, __LINE__);

#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("KeyHandle " + util::toStr(mObjectHandle, "H4") + " renamed as " + newName + "...");
#endif
	return;
}

PUBLIC uchar* Key::getKCV(uchar* pKCV, int lenKCV)
{
#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("Calculating KCV...");
#endif

	MechanismType mechanismType = MT_DES3_ECB;
	uchar zeroData[8] = {0x00};
	std::vector<uchar> resVec = this->encryptData(mechanismType, zeroData, 8);
	memcpy(pKCV, resVec.data(), lenKCV);
#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("KCV Calculated...");
#endif

	return pKCV;
}

PUBLIC void Key::destroy()
{
#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("Destroying key handle " + util::toStr(mObjectHandle, "H4") + "...");
#endif

	rv = C_DestroyObject(mSessionHndl, mObjectHandle);
    if (rv != CKR_OK)
        throw ExceptionCryptoki(rv, __FILE__, __LINE__);

#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("Key handle " + util::toStr(mObjectHandle, "H4") + " destroyed...");
#endif

    return;
}

PUBLIC std::vector<CK_BYTE> Key::encryptData(MechanismType mechType, uchar* pData, ulong dataLen, void* iv, ulong ivLen)
{
#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("Encrypting data...");
#endif

	this->setMechanism(mechType, iv, ivLen);

	std::vector<CK_BYTE> vecEncryptedData;

    rv = C_EncryptInit(mSessionHndl, &mMech, mObjectHandle);
    if (rv != CKR_OK)
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);

    CK_SIZE encryptedDataLen;

    rv = C_Encrypt(mSessionHndl, pData, dataLen, NULL, &encryptedDataLen); /* Do a length prediction so we allocate enough memory for the ciphertext */
    if (rv != CKR_OK)
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);

    CK_BYTE *pEncData = (CK_BYTE*) new CK_BYTE[encryptedDataLen];
    if (pEncData == NULL)
    	throw ExceptionCryptoki(ExceptionCryptoki::ERROR_MEMORY_ALLOCATION, __FILE__, __LINE__);


    rv = C_Encrypt(mSessionHndl, pData, dataLen, pEncData, &encryptedDataLen);
    if (rv != CKR_OK)
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);

    vecEncryptedData.assign(pEncData, pEncData+encryptedDataLen);
    delete[] pEncData;

#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("Encryption Done...");
#endif

    return vecEncryptedData;
}

PUBLIC std::vector<CK_BYTE> Key::decryptData(MechanismType mechType, uchar* pEncData, ulong encDataLen, void* iv, ulong ivLen)
{
#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("Decrypting data...");
#endif

	this->setMechanism(mechType, iv, ivLen);

	std::vector<CK_BYTE> vecDecryptedData;

    rv = C_DecryptInit(mSessionHndl, &mMech, mObjectHandle);
    if (rv != CKR_OK)
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);

    CK_SIZE decryptedDataLen;

    rv = C_Decrypt(mSessionHndl, pEncData, encDataLen, NULL, &decryptedDataLen);
    if (rv != CKR_OK)
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);

    CK_BYTE *pDecData = (CK_BYTE*) new CK_BYTE[decryptedDataLen];
    if (pDecData == NULL)
    	throw ExceptionCryptoki(ExceptionCryptoki::ERROR_MEMORY_ALLOCATION, __FILE__, __LINE__);

    rv = C_Decrypt(mSessionHndl, pEncData, encDataLen, pDecData, &decryptedDataLen);
    if (rv != CKR_OK)
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);

    vecDecryptedData.assign(pDecData, pDecData+decryptedDataLen);
    delete[] pDecData;

#ifdef DIAGNOSTIC_ENABLED
    mLog->writeLn("Decryption Done...");
#endif
	return vecDecryptedData;
}

PUBLIC std::vector<CK_BYTE> Key::wrapKey(MechanismType mechType, Key &key, void* iv, ulong ivLen)
{
#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("Wrapping key...");
#endif

	CK_OBJECT_HANDLE hKey = key.mObjectHandle;

	this->setMechanism(mechType, iv, ivLen);

	std::vector<CK_BYTE> vecWrappeddKey;

    CK_ULONG wrappedKeyLen = 0;

    if ((mObjectHandle == CK_INVALID_HANDLE) || (hKey == CK_INVALID_HANDLE)) /* check arguments */
    	throw ExceptionCryptoki(CKR_ARGUMENTS_BAD, __FILE__, __LINE__);


    rv = C_WrapKey(mSessionHndl, &mMech, mObjectHandle, hKey, NULL, &wrappedKeyLen); //Wrapped Key uzunlugunu bulmak icin
    if (rv != CKR_OK)
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);

    CK_BYTE *pWrappedKey = new CK_BYTE[wrappedKeyLen];

    if (pWrappedKey == NULL)
    	throw ExceptionCryptoki(ExceptionCryptoki::ERROR_MEMORY_ALLOCATION, __FILE__, __LINE__);


    rv = C_WrapKey(mSessionHndl, &mMech, mObjectHandle, hKey, pWrappedKey, &wrappedKeyLen);

    if (rv != CKR_OK)
    {
    	delete[] pWrappedKey;
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);
    }

    vecWrappeddKey.assign(pWrappedKey, pWrappedKey+wrappedKeyLen);
    delete[] pWrappedKey;

#ifdef DIAGNOSTIC_ENABLED
    mLog->writeLn("Key Wrapped...");
#endif

    return vecWrappeddKey;
}

PUBLIC Key Key::unWrapKey(MechanismType mechType, KeyType keyType, CK_BYTE* pWrappedKey, CK_ULONG wrappedKeyLen, void* iv, ulong ivLen, CK_BBOOL isTokenObject)
{
#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("UnWrapping key...");
	mLog->writeHex("Wrapped Key", pWrappedKey, wrappedKeyLen);
#endif

	this->setMechanism(mechType, iv, ivLen);

	CK_OBJECT_HANDLE unwrappedKeyHandle;

    static CK_BBOOL ckTrue = TRUE;
    static CK_BBOOL ckFalse = FALSE;


    //TODO Olusturulan her bir key için farklı attribute set edebilecek bir mekanizma yapalım.
    CK_ATTRIBUTE tpl[] =
    {
        {CKA_TOKEN,         &isTokenObject,	sizeof(CK_BBOOL)},
        {CKA_PRIVATE,       &ckTrue,		sizeof(CK_BBOOL)},
        {CKA_ENCRYPT,		&ckTrue,		sizeof(CK_BBOOL)},
        {CKA_DECRYPT,		&ckTrue,		sizeof(CK_BBOOL)},
        {CKA_WRAP,          &ckTrue,    	sizeof(CK_BBOOL)},
        {CKA_UNWRAP,        &ckTrue,    	sizeof(CK_BBOOL)},
        {CKA_EXTRACTABLE,   &ckTrue,    	sizeof(CK_BBOOL)},
        {CKA_SENSITIVE,     &ckTrue,     	sizeof(CK_BBOOL)},
        {CKA_KEY_TYPE,      &keyType,    	sizeof(CK_KEY_TYPE)},
    };

    CK_COUNT tplSize = sizeof(tpl)/sizeof(CK_ATTRIBUTE);

    if (pWrappedKey == NULL) {
#ifdef DIAGNOSTIC_ENABLED
    	mLog->writeLn("pWrappedKey NULL");
#endif
    	throw ExceptionCryptoki(CKR_ARGUMENTS_BAD, __FILE__, __LINE__);
    }

    if (mObjectHandle == CK_INVALID_HANDLE) {
#ifdef DIAGNOSTIC_ENABLED
    	mLog->writeLn("mObjectHandle == CK_INVALID_HANDLE");
#endif
        throw ExceptionCryptoki(CKR_ARGUMENTS_BAD, __FILE__, __LINE__);
    }

    rv = C_UnwrapKey(mSessionHndl, &mMech, mObjectHandle, pWrappedKey, wrappedKeyLen, tpl, tplSize, &unwrappedKeyHandle);
    if (rv != CKR_OK) {
#ifdef DIAGNOSTIC_ENABLED
    	mLog->writeLn("C_UnwrapKey error " + util::toStr(rv, "D6"));
#endif
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);
    }

	Key retKey(mSessionHndl);
	retKey.mObjectHandle = unwrappedKeyHandle;

#ifdef DIAGNOSTIC_ENABLED
    mLog->writeLn("Key UnWrapped...");
#endif

    return retKey;
}
PUBLIC Key Key::unWrapKey2(MechanismType mechType, KeyType keyType, CK_BYTE* pWrappedKey, CK_ULONG wrappedKeyLen, void* iv, ulong ivLen, CK_BBOOL isTokenObject)
{
#ifdef DIAGNOSTIC_ENABLED
	mLog->writeLn("UnWrapping key...");
	mLog->writeHex("Wrapped Key", pWrappedKey, wrappedKeyLen);
#endif

	this->setMechanism(mechType, iv, ivLen);

	CK_OBJECT_HANDLE unwrappedKeyHandle;

    static CK_BBOOL ckTrue = TRUE;
    static CK_BBOOL ckFalse = FALSE;


    //TODO Olusturulan her bir key için farklı attribute set edebilecek bir mekanizma yapalım.
    CK_ATTRIBUTE tpl[] =
    {
        {CKA_TOKEN,         &isTokenObject,	sizeof(CK_BBOOL)},
        {CKA_PRIVATE,       &ckFalse,		sizeof(CK_BBOOL)},
        {CKA_ENCRYPT,		&ckTrue,		sizeof(CK_BBOOL)},
        {CKA_DECRYPT,		&ckTrue,		sizeof(CK_BBOOL)},
        {CKA_WRAP,          &ckTrue,    	sizeof(CK_BBOOL)},
        {CKA_UNWRAP,        &ckTrue,    	sizeof(CK_BBOOL)},
        {CKA_EXTRACTABLE,   &ckTrue,    	sizeof(CK_BBOOL)},
        {CKA_SENSITIVE,     &ckTrue,     	sizeof(CK_BBOOL)},
        {CKA_KEY_TYPE,      &keyType,    	sizeof(CK_KEY_TYPE)},
    };

    CK_COUNT tplSize = sizeof(tpl)/sizeof(CK_ATTRIBUTE);

    if (pWrappedKey == NULL) {
#ifdef DIAGNOSTIC_ENABLED
    	mLog->writeLn("pWrappedKey NULL");
#endif
    	throw ExceptionCryptoki(CKR_ARGUMENTS_BAD, __FILE__, __LINE__);
    }

    if (mObjectHandle == CK_INVALID_HANDLE) {
#ifdef DIAGNOSTIC_ENABLED
    	mLog->writeLn("mObjectHandle == CK_INVALID_HANDLE");
#endif
        throw ExceptionCryptoki(CKR_ARGUMENTS_BAD, __FILE__, __LINE__);
    }

    rv = C_UnwrapKey(mSessionHndl, &mMech, mObjectHandle, pWrappedKey, wrappedKeyLen, tpl, tplSize, &unwrappedKeyHandle);
    if (rv != CKR_OK) {
#ifdef DIAGNOSTIC_ENABLED
    	mLog->writeLn("C_UnwrapKey error " + util::toStr(rv, "D6"));
#endif
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);
    }

	Key retKey(mSessionHndl);
	retKey.mObjectHandle = unwrappedKeyHandle;

#ifdef DIAGNOSTIC_ENABLED
    mLog->writeLn("Key UnWrapped...");
#endif

    return retKey;
}

PRIVATE void Key::setMechanism(MechanismType mechType, void *param, ulong paramLen)
{
	mMech.mechanism = (CK_MECHANISM_TYPE) mechType;
	mMech.pParameter = param;
	mMech.parameterLen = paramLen;
}
