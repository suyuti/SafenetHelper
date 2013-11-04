#include "CryptokiHelper.h"
#include <stdio.h>
#include <iostream>
#include "cryptoki.h"
#include "ctvdef.h"
#include "ctutil.h"
#include "ExceptionCryptoki.h"

namespace Cryptoki {

CryptokiHelper* CryptokiHelper::_instance = NULL;

CryptokiHelper* CryptokiHelper::instance()
{
	if (_instance == NULL) {
		_instance = new CryptokiHelper();
	}
	return _instance;
}

CryptokiHelper::CryptokiHelper() :
	_sessionHandle(CK_INVALID_HANDLE)
{
	initialize();
}

CryptokiHelper::~CryptokiHelper()
{
	C_Finalize(NULL);
}

void CryptokiHelper::initialize()
{
	int rv = C_Initialize(NULL);
	if (rv != CKR_OK) {
		LOG4CXX_ERROR(g_logger, "Cryptoki not initialized");
		throw ExceptionCryptoki(rv, "Cryptoki not initialized", __FILE__, __LINE__);
	}
	LOG4CXX_INFO(g_logger, "Cryptoki initialized");
}

void CryptokiHelper::open(unsigned long slotId, std::string pin, int sessionType)
{
	if (_sessionHandle != CK_INVALID_HANDLE) {
		LOG4CXX_DEBUG(g_logger, "session already open.");
		return;
	}
    int rv = C_OpenSession(slotId, (CK_FLAGS)sessionType, NULL, NULL, &_sessionHandle);
    if (rv != CKR_OK) {
		LOG4CXX_ERROR(g_logger, "Cryptoki not open");
		throw ExceptionCryptoki(rv, "Cryptoki not initialized", __FILE__, __LINE__);
    }
    login(pin, UT_USER);
	LOG4CXX_DEBUG(g_logger, "session opened.");
}

void CryptokiHelper::close()
{
	if (_sessionHandle != CK_INVALID_HANDLE) {
		C_Logout(_sessionHandle);
		C_CloseSession(_sessionHandle);
		_sessionHandle = CK_INVALID_HANDLE;
		LOG4CXX_DEBUG(g_logger, "session closed.");
	}
	else {
		LOG4CXX_ERROR(g_logger, "session invalid on closing.");
	}
}

void CryptokiHelper::login(std::string& pin, int userType)
{
	int rv = C_Login(_sessionHandle, (CK_USER_TYPE)userType, (CK_CHAR_PTR)pin.c_str(), pin.size());
    if (rv != CKR_OK) {
		LOG4CXX_ERROR(g_logger, "Could not login");
		throw ExceptionCryptoki(rv, "", __FILE__, __LINE__);
    }
	LOG4CXX_DEBUG(g_logger, "User logged in.");
}

Key CryptokiHelper::getKeyByName(ObjectClass objClass, const std::string& name)
{
	Key k(_sessionHandle);
    CK_ATTRIBUTE objectTemplate[] =
    {
        {CKA_CLASS,         NULL,       0},
        {CKA_LABEL,         NULL,       0},
    };

    CK_SIZE templateSize = sizeof(objectTemplate) / sizeof(CK_ATTRIBUTE);

    CK_ULONG numObjectsToFind = 1;
    CK_ULONG numObjectsFound  = 0;

    CK_ATTRIBUTE* pAttr = NULL;

    pAttr = FindAttribute(CKA_CLASS, objectTemplate, templateSize); /* First set the object class ... */
    pAttr->pValue = &objClass;
    pAttr->ulValueLen = sizeof(CK_OBJECT_CLASS);

    pAttr = FindAttribute(CKA_LABEL, objectTemplate, templateSize); /* Set the Label */
    pAttr->pValue = (CK_VOID_PTR) name.c_str();
    pAttr->ulValueLen = name.length();;

    int rv = C_FindObjectsInit(_sessionHandle, objectTemplate, templateSize);
    if (rv != CKR_OK) {
		LOG4CXX_ERROR(g_logger, "FindObjectInit error. " << name);
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);
    }
    rv = C_FindObjects(_sessionHandle, &(k._objectHandle), numObjectsToFind,  &numObjectsFound);
    if (rv != CKR_OK) {
		LOG4CXX_ERROR(g_logger, "FindObject error. " << name);
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);
    }
    rv = C_FindObjectsFinal(_sessionHandle);
    if (rv != CKR_OK) {
		LOG4CXX_ERROR(g_logger, "FindObjectFinal error. "  << name);
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);
    }
    if (numObjectsFound == 0) {
		LOG4CXX_ERROR(g_logger, "Object not found. " << name);
        throw ExceptionCryptoki(ExceptionCryptoki::OBJECT_NOT_FOUND, name, __FILE__, __LINE__);
    }
	LOG4CXX_DEBUG(g_logger, "Object found. " << name);

	return k;
}

Key CryptokiHelper::createKey(const std::string& name)
{
	MechanismInfo mInfo;
	KeyAttribute attr;
	return this->createKey(name, attr, mInfo);
}

Key CryptokiHelper::createKey(const std::string& name, const MechanismInfo& mech)
{
	KeyAttribute attr;
	return this->createKey(name, attr, mech);
}

Key CryptokiHelper::createKey(const std::string& name, const KeyAttribute& attr, const MechanismInfo& mech)
{
	Key k(_sessionHandle);
    CK_ATTRIBUTE tpl[] =
    {
        {CKA_LABEL,			(CK_VOID_PTR)name.c_str(), 			name.length()},
        {CKA_TOKEN,         (CK_VOID_PTR)&attr._token,   		sizeof(CK_BBOOL			)},
        {CKA_WRAP,          (CK_VOID_PTR)&attr._wrap,    		sizeof(CK_BBOOL			)},
        {CKA_ENCRYPT,       (CK_VOID_PTR)&attr._encrypt,    	sizeof(CK_BBOOL			)},
        {CKA_DECRYPT,       (CK_VOID_PTR)&attr._decrypt,    	sizeof(CK_BBOOL			)},
        {CKA_UNWRAP,        (CK_VOID_PTR)&attr._unwrap,    		sizeof(CK_BBOOL			)},
        {CKA_EXTRACTABLE,   (CK_VOID_PTR)&attr._extractable,  	sizeof(CK_BBOOL			)},
        {CKA_SENSITIVE,     (CK_VOID_PTR)&attr._sensitive,    	sizeof(CK_BBOOL			)},
        {CKA_PRIVATE, 		(CK_VOID_PTR)&attr._private, 		sizeof(CK_BBOOL			)},
	    {CKA_CLASS, 		(CK_VOID_PTR)&attr._class, 			sizeof(CK_OBJECT_CLASS	)},
    };

    k.setMechanism(mech);

    CK_COUNT tplSize = sizeof(tpl)/sizeof(CK_ATTRIBUTE);

    int rv = C_GenerateKey(_sessionHandle, &k._mech, tpl, tplSize, &k._objectHandle);
    if (rv != CKR_OK) {
		LOG4CXX_ERROR(g_logger, "Generate key error. " << name << " err: " << rv);
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);
    }
	LOG4CXX_DEBUG(g_logger, "Key created. " << name);
	return k;
}

Key CryptokiHelper::createSecretKey(const std::string& name, const KeyAttribute& attr, const MechanismInfo& mech)
{
	Key k(_sessionHandle);

	CK_OBJECT_CLASS _class = CKO_SECRET_KEY;

	CK_ATTRIBUTE _template[] = {
		{CKA_CLASS, 	(CK_VOID_PTR)&_class, 				sizeof(_class)			},
		{CKA_KEY_TYPE, 	(CK_VOID_PTR)&attr._keyType, 		sizeof(attr._keyType)	},
		{CKA_TOKEN, 	(CK_VOID_PTR)&attr._token, 			sizeof(attr._token)		},
		{CKA_LABEL, 	(CK_VOID_PTR)attr._label.c_str(), 	attr._label.size()		},
		{CKA_ENCRYPT, 	(CK_VOID_PTR)&attr._encrypt, 		sizeof(attr._encrypt)	},
		{CKA_VALUE, 	(CK_VOID_PTR)mech._param, 			mech._paramLen			},
		{CKA_PRIVATE, 	(CK_VOID_PTR)&attr._private, 		sizeof(attr._private)	},
	};

	int rv = C_CreateObject(_sessionHandle, _template, sizeof(_template)/sizeof(CK_ATTRIBUTE), &k._objectHandle);

    if (rv != CKR_OK) {
		LOG4CXX_ERROR(g_logger, "CreateObject error. " << name << ", err: " << rv);
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);
    }
	LOG4CXX_DEBUG(g_logger, "Object created. " << name);
	return k;
}


void CryptokiHelper::deleteKey(const std::string& name)
{
	throw "Not implemented yet!";
}

// Data objects
DataObject CryptokiHelper::getDataByName(const std::string& appName, const std::string& name)
{
	DataObject d(_sessionHandle);

	CK_ATTRIBUTE objectTemplate[] =
    {
        {CKA_CLASS,         NULL,       0},
        {CKA_APPLICATION, 	NULL, 		0},
        {CKA_LABEL,         NULL,       0},
    };

    CK_SIZE templateSize = sizeof(objectTemplate) / sizeof(CK_ATTRIBUTE);

    CK_ULONG numObjectsToFind = 1;
    CK_ULONG numObjectsFound  = 0;

    CK_OBJECT_CLASS oClass = CKO_DATA;

    CK_ATTRIBUTE* pAttr = NULL;

    pAttr = FindAttribute(CKA_CLASS, objectTemplate, templateSize); /* First set the object class ... */
    pAttr->pValue = &oClass;
    pAttr->ulValueLen = sizeof(CK_OBJECT_CLASS);

    pAttr = FindAttribute(CKA_APPLICATION, objectTemplate, templateSize); /* Set the Application */
    pAttr->pValue = (CK_VOID_PTR) appName.c_str();
    pAttr->ulValueLen = appName.length();

    pAttr = FindAttribute(CKA_LABEL, objectTemplate, templateSize); /* Set the Label */
    pAttr->pValue = (CK_VOID_PTR) name.c_str();
    pAttr->ulValueLen = name.length();

    int rv = C_FindObjectsInit(_sessionHandle, objectTemplate, templateSize);
    if (rv != CKR_OK) {
		LOG4CXX_ERROR(g_logger, "FindObjectInit error. err: " << rv);
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);
    }

    rv = C_FindObjects(_sessionHandle, &d._objectHandle, numObjectsToFind,  &numObjectsFound);
    if (rv != CKR_OK) {
		LOG4CXX_ERROR(g_logger, "FindObjects error. err: " << rv);
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);
    }

    rv = C_FindObjectsFinal(_sessionHandle);
    if (rv != CKR_OK) {
		LOG4CXX_ERROR(g_logger, "FindObjectFinal error. err: " << rv);
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);
    }

    if (numObjectsFound == 0) {
		LOG4CXX_ERROR(g_logger, "Object not found. " << appName << " : " << name);
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);
    }

    LOG4CXX_DEBUG(g_logger, "Object found." << appName << " : " << name);

    return d;
}

DataObject CryptokiHelper::createData(const std::string& appName, const std::string& name, const VectorUChar& data)
{
	return createData(appName, name, data.data(), data.size());
}

DataObject CryptokiHelper::createData(const std::string& appName, const std::string& name, const DataAttribute& attr)
{
	DataObject d(_sessionHandle);
	CK_OBJECT_CLASS tClass = CKO_DATA;
	CK_ATTRIBUTE dTemplate[] =
	{
	    {CKA_CLASS, 		(CK_VOID_PTR)&tClass, 			sizeof(tClass)},
	    {CKA_TOKEN, 		(CK_VOID_PTR)&attr._token, 		sizeof(CK_BBOOL)},
	    {CKA_PRIVATE, 		(CK_VOID_PTR)&attr._private, 	sizeof(CK_BBOOL)},
	    {CKA_APPLICATION, 	(CK_VOID_PTR)appName.c_str(), 	appName.length()},
	    {CKA_LABEL, 		(CK_VOID_PTR)name.c_str(), 		name.length()},
	    {CKA_VALUE, 		(CK_VOID_PTR)attr._data, 		attr._dataLen}
	};

	CK_COUNT attributeCount = sizeof(dTemplate)/sizeof(CK_ATTRIBUTE);

    int rv = C_CreateObject(_sessionHandle, dTemplate, attributeCount, &d._objectHandle);
	if (rv != CKR_OK) {
		LOG4CXX_ERROR(g_logger, "CreateObject error. err: " << rv);
		throw ExceptionCryptoki(rv, __FILE__, __LINE__);
	}
	LOG4CXX_DEBUG(g_logger, "Data created. " << appName << " : " << name);
	return d;
}

DataObject CryptokiHelper::createData(const std::string& appName, const std::string& name, const unsigned char* pData, int dataLen)
{
	DataAttribute attr;

	attr._data 			= (char*)pData;
	attr._dataLen 		= dataLen;
	attr._label 		= name;
	attr._application 	= appName;
	attr._private 		= TRUE;
	attr._token 		= TRUE;

	return createData(appName, name, attr);
}

void CryptokiHelper::deleteData(const std::string& name)
{
	throw "Not implemented yet!";
}

VectorUChar CryptokiHelper::generateSHA256(const char* pData, int len)
{
    Cryptoki::MechanismInfo mInfo;
    mInfo._type = MT_SHA256;
    return this->digest(mInfo, pData, len);
}

VectorUChar CryptokiHelper::generateSHA256(const VectorUChar& data)
{
    return this->generateSHA256((char*)data.data(), data.size());
}

VectorUChar CryptokiHelper::generateSHA1(const char* pData, int len)
{
    Cryptoki::MechanismInfo mInfo;
    mInfo._type = MT_SHA_1;
    return this->digest(mInfo, pData, len);
}

VectorUChar CryptokiHelper::generateSHA1(const VectorUChar& data)
{
    return this->generateSHA1((char*)data.data(), data.size());
}

VectorUChar CryptokiHelper::digest(const MechanismInfo& mInfo, const char* pData, int len)
{
    VectorUChar vecDigestData;
    
    CK_MECHANISM _mech;
    _mech.mechanism 	= (CK_MECHANISM_TYPE) mInfo._type;
    _mech.pParameter 	= mInfo._param;
    _mech.parameterLen 	= mInfo._paramLen;

    int rv = C_DigestInit(_sessionHandle, &_mech);
    if (rv != CKR_OK)
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);

    CK_SIZE digestLen;

    rv = C_Digest(_sessionHandle, (unsigned char*)pData, len, NULL, &digestLen);
    if (rv != CKR_OK)
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);

    CK_BYTE *pDigestData = (CK_BYTE*) new CK_BYTE[digestLen];
    if (pDigestData == NULL)
    	throw ExceptionCryptoki(ExceptionCryptoki::ERROR_MEMORY_ALLOCATION, __FILE__, __LINE__);

    rv = C_Digest(_sessionHandle, (unsigned char*)pData, len, pDigestData, &digestLen);
    if (rv != CKR_OK) {
        delete[] pDigestData;
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);
    }

    vecDigestData.assign(pDigestData, pDigestData+digestLen);
    delete[] pDigestData;

    return vecDigestData;
}

KeyPair CryptokiHelper::generateKeyPair(ulong keyLength, std::string pbKeyName, std::string prKeyName, bool isTokenObj)
{
    CK_OBJECT_HANDLE hPublicKey;
    CK_OBJECT_HANDLE hPrivateKey;

    CK_BBOOL isTokenObject = (isTokenObj)? TRUE : FALSE;

	CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};

	CK_ULONG modulusBits = keyLength;
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

	int rv = C_GenerateKeyPair(_sessionHandle,
								&mechanism,
								publicKeyTemplate,
								pbkTACount,
								privateKeyTemplate,
								prkTACount,
								&hPublicKey,
								&hPrivateKey);
    if (rv != CKR_OK) {
		LOG4CXX_ERROR(g_logger, "GenerateKeyPair error. err: " << rv);
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);
    }
	KeyPair kp;
	kp.privateKey._sessionHandle = _sessionHandle;
	kp.publicKey._sessionHandle  = _sessionHandle;
	kp.privateKey._objectHandle  = hPrivateKey;
	kp.publicKey._objectHandle   = hPublicKey;

	LOG4CXX_DEBUG(g_logger, "KeyPair generated." << pbKeyName << " : " << prKeyName);
	return kp;
}

}
