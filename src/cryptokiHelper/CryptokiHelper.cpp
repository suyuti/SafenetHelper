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

CryptokiHelper::CryptokiHelper()
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
		throw ExceptionCryptoki(rv, "Cryptoki not initialized", __FILE__, __LINE__);
	}
}

void CryptokiHelper::open(unsigned long slotId, std::string& pin, int sessionType)
{
    int rv = C_OpenSession(slotId, (CK_FLAGS)sessionType, NULL, NULL, &_sessionHandle);
    if (rv != CKR_OK) {
		throw ExceptionCryptoki(rv, "Cryptoki not initialized", __FILE__, __LINE__);
    }
    login(pin, UT_USER);
}

void CryptokiHelper::close()
{
	C_Logout(_sessionHandle);
	C_CloseSession(_sessionHandle);
}

void CryptokiHelper::login(std::string& pin, int userType)
{
	int rv = C_Login(_sessionHandle, (CK_USER_TYPE)userType, (CK_CHAR_PTR)pin.c_str(), pin.size());
    if (rv != CKR_OK) {
		throw ExceptionCryptoki(rv, "", __FILE__, __LINE__);
    }
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
    if (rv != CKR_OK)
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);

    rv = C_FindObjects(_sessionHandle, &(k._objectHandle), numObjectsToFind,  &numObjectsFound);
    if (rv != CKR_OK)
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);

    rv = C_FindObjectsFinal(_sessionHandle);
    if (rv != CKR_OK)
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);

    if (numObjectsFound == 0) {
        throw ExceptionCryptoki(ExceptionCryptoki::OBJECT_NOT_FOUND, name, __FILE__, __LINE__);
    }

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
        {CKA_TOKEN,         (CK_VOID_PTR)&attr._token,   		sizeof(CK_BBOOL)},
        {CKA_WRAP,          (CK_VOID_PTR)&attr._wrap,    		sizeof(CK_BBOOL)},
        {CKA_ENCRYPT,       (CK_VOID_PTR)&attr._encrypt,    	sizeof(CK_BBOOL)},
        {CKA_DECRYPT,       (CK_VOID_PTR)&attr._decrypt,    	sizeof(CK_BBOOL)},
        {CKA_UNWRAP,        (CK_VOID_PTR)&attr._unwrap,    		sizeof(CK_BBOOL)},
        {CKA_EXTRACTABLE,   (CK_VOID_PTR)&attr._extractable,  	sizeof(CK_BBOOL)},
        {CKA_SENSITIVE,     (CK_VOID_PTR)&attr._sensitive,    	sizeof(CK_BBOOL)},
        {CKA_PRIVATE, 		(CK_VOID_PTR)&attr._private, 		sizeof(CK_BBOOL)},
    };

    k.setMechanism(mech);

    CK_COUNT tplSize = sizeof(tpl)/sizeof(CK_ATTRIBUTE);

    int rv = C_GenerateKey(_sessionHandle, &k._mech, tpl, tplSize, &k._objectHandle);
    if (rv != CKR_OK)
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);
	return k;
}

void CryptokiHelper::deleteKey(const std::string& name)
{
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
    if (rv != CKR_OK)
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);

    rv = C_FindObjects(_sessionHandle, &d._objectHandle, numObjectsToFind,  &numObjectsFound);
    if (rv != CKR_OK)
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);

    rv = C_FindObjectsFinal(_sessionHandle);
    if (rv != CKR_OK)
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);

    if (numObjectsFound == 0)
    	throw ExceptionCryptoki(rv, __FILE__, __LINE__);

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
	if (rv != CKR_OK)
		throw ExceptionCryptoki(rv, __FILE__, __LINE__);
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
}
}
