#include "Key.h"
#include "cryptoki.h"
#include "ExceptionCryptoki.h"

namespace Cryptoki {

Key::Key(CK_SESSION_HANDLE sessionHandle)
{
	_sessionHandle = sessionHandle;
}

VectorUChar Key::getKcv()
{
	VectorUChar ret;
	return ret;
}

VectorUChar Key::encrypt(const MechanismInfo& mech, const char* pData, int len)
{
	this->setMechanism(mech);

	VectorUChar vecEncryptedData;

    int rv = C_EncryptInit(_sessionHandle, &_mech, _objectHandle);
    if (rv != CKR_OK)
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);

    CK_SIZE encryptedDataLen;

    rv = C_Encrypt(_sessionHandle, (unsigned char*)pData, len, NULL, &encryptedDataLen); /* Do a length prediction so we allocate enough memory for the ciphertext */
    if (rv != CKR_OK)
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);

    CK_BYTE *pEncData = (CK_BYTE*) new CK_BYTE[encryptedDataLen];
    if (pEncData == NULL)
    	throw ExceptionCryptoki(ExceptionCryptoki::ERROR_MEMORY_ALLOCATION, __FILE__, __LINE__);


    rv = C_Encrypt(_sessionHandle, (unsigned char*)pData, len, pEncData, &encryptedDataLen);
    if (rv != CKR_OK)
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);

    vecEncryptedData.assign(pEncData, pEncData+encryptedDataLen);
    delete[] pEncData;


    return vecEncryptedData;
}


VectorUChar Key::encrypt(const MechanismInfo& mech, const VectorUChar& data)
{
	return this->encrypt(mech, (char*)data.data(), data.size());
}

VectorUChar Key::decrypt(const MechanismInfo& mech, const VectorUChar& data)
{
	return this->decrypt(mech, (char*)data.data(), data.size());
}

VectorUChar Key::decrypt(const MechanismInfo& mech, const char* pData, int len)
{
	this->setMechanism(mech);

	VectorUChar vecDecryptedData;

    int rv = C_DecryptInit(_sessionHandle, &_mech, _objectHandle);
    if (rv != CKR_OK)
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);

    CK_SIZE decryptedDataLen;

    rv = C_Decrypt(_sessionHandle, (unsigned char*)pData, len, NULL, &decryptedDataLen);
    if (rv != CKR_OK)
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);

    CK_BYTE *pDecData = (CK_BYTE*) new CK_BYTE[decryptedDataLen];
    if (pDecData == NULL)
    	throw ExceptionCryptoki(ExceptionCryptoki::ERROR_MEMORY_ALLOCATION, __FILE__, __LINE__);

    rv = C_Decrypt(_sessionHandle, (unsigned char*)pData, len, pDecData, &decryptedDataLen);
    if (rv != CKR_OK)
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);

    vecDecryptedData.assign(pDecData, pDecData+decryptedDataLen);
    delete[] pDecData;

	return vecDecryptedData;
}

VectorUChar Key::wrap(const MechanismInfo& mech, const Key& other)
{
	this->setMechanism(mech);

	VectorUChar vecWrappeddKey;

    CK_ULONG wrappedKeyLen = 0;

    int rv = C_WrapKey(_sessionHandle, &_mech, _objectHandle, other._objectHandle, NULL, &wrappedKeyLen); //Wrapped Key uzunlugunu bulmak icin
    if (rv != CKR_OK)
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);

    CK_BYTE *pWrappedKey = new CK_BYTE[wrappedKeyLen];

    if (pWrappedKey == NULL)
    	throw ExceptionCryptoki(ExceptionCryptoki::ERROR_MEMORY_ALLOCATION, __FILE__, __LINE__);


    rv = C_WrapKey(_sessionHandle, &_mech, _objectHandle, other._objectHandle, pWrappedKey, &wrappedKeyLen);

    if (rv != CKR_OK) {
    	delete[] pWrappedKey;
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);
    }

    vecWrappeddKey.assign(pWrappedKey, pWrappedKey+wrappedKeyLen);
    delete[] pWrappedKey;


    return vecWrappeddKey;
}

Key	Key::unwrap(const MechanismInfo& mech, const char* pData, int len)
{
	KeyAttribute attr;
	return this->unwrap(mech, pData, len, attr);
}

Key	Key::unwrap(const MechanismInfo& mech, VectorUChar& data)
{
	KeyAttribute attr;
	return this->unwrap(mech, data, attr);
}

Key	Key::unwrap(const MechanismInfo& mech, VectorUChar& data, const KeyAttribute& attr)
{
	return this->unwrap(mech, (char*)data.data(), data.size(), attr);
}

Key	Key::unwrap(const MechanismInfo& mech, const char* pWrappedKey, int wrappedKeyLen, const KeyAttribute& attr)
{
	this->setMechanism(mech);

	CK_OBJECT_HANDLE unwrappedKeyHandle;

    CK_ATTRIBUTE tpl[] =
    {
        {CKA_TOKEN,         (CK_VOID_PTR)&attr._token,			sizeof(CK_BBOOL)},
        {CKA_PRIVATE,       (CK_VOID_PTR)&attr._private,		sizeof(CK_BBOOL)},
        {CKA_ENCRYPT,		(CK_VOID_PTR)&attr._encrypt,		sizeof(CK_BBOOL)},
        {CKA_DECRYPT,		(CK_VOID_PTR)&attr._decrypt,		sizeof(CK_BBOOL)},
        {CKA_WRAP,          (CK_VOID_PTR)&attr._wrap,    		sizeof(CK_BBOOL)},
        {CKA_UNWRAP,        (CK_VOID_PTR)&attr._unwrap,    		sizeof(CK_BBOOL)},
        {CKA_EXTRACTABLE,   (CK_VOID_PTR)&attr._extractable, 	sizeof(CK_BBOOL)},
        {CKA_SENSITIVE,     (CK_VOID_PTR)&attr._sensitive,   	sizeof(CK_BBOOL)},
        {CKA_KEY_TYPE,      (CK_VOID_PTR)&attr._keyType,    	sizeof(CK_KEY_TYPE)},
    };

    CK_COUNT tplSize = sizeof(tpl)/sizeof(CK_ATTRIBUTE);

    if (pWrappedKey == NULL) {
    	throw ExceptionCryptoki(CKR_ARGUMENTS_BAD, __FILE__, __LINE__);
    }

    //if (mObjectHandle == CK_INVALID_HANDLE) {
    //    throw ExceptionCryptoki(CKR_ARGUMENTS_BAD, __FILE__, __LINE__);
    //}

    int rv = C_UnwrapKey(_sessionHandle, &_mech, _objectHandle, (unsigned char*)pWrappedKey, wrappedKeyLen, tpl, tplSize, &unwrappedKeyHandle);
    if (rv != CKR_OK) {
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);
    }

	Key retKey(_sessionHandle);
	retKey._objectHandle = unwrappedKeyHandle;

    return retKey;
}

void Key::setMechanism(const MechanismInfo& mInfo)
{
	_mech.mechanism 	= (CK_MECHANISM_TYPE) mInfo._type;
	_mech.pParameter 	= mInfo._param;
	_mech.parameterLen 	= mInfo._paramLen;
}

}
