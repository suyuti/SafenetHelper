#include "DataObject.h"
#include "ExceptionCryptoki.h"
#include <iostream>
#include <string.h>

namespace Cryptoki {

DataObject::DataObject(CK_SESSION_HANDLE sessionHandle)
{
	_sessionHandle = sessionHandle;
}

std::string DataObject::getValueAsStr()
{
	VectorUChar val = this->getValue();
	std::string str(val.begin(), val.end());

	LOG4CXX_DEBUG(g_logger, "get value: " << str);

	return str;
}

VectorUChar DataObject::getValue()
{
	LOG4CXX_INFO(g_logger, "getting value...");
	VectorUChar val;

	CK_ATTRIBUTE oTemplate[] = {{CKA_VALUE, NULL, 0}};

	int rv = C_GetAttributeValue(_sessionHandle, _objectHandle, oTemplate, 1);
	if (rv != CKR_OK) {
		LOG4CXX_ERROR(g_logger, "GetAttributeValue error. err: " << rv);
		throw ExceptionCryptoki(rv, __FILE__, __LINE__);
	}

	uchar *pValue = new CK_BYTE[oTemplate[0].valueLen ];
	oTemplate[0].pValue = pValue;
	memset(pValue, 0x00, (oTemplate[0].valueLen));

	rv = C_GetAttributeValue(_sessionHandle, _objectHandle, oTemplate, 1);
	if (rv != CKR_OK) {
		LOG4CXX_ERROR(g_logger, "GetAttributeValue error. err: " << rv);
		delete[] pValue;
		throw ExceptionCryptoki(rv, __FILE__, __LINE__);
	}

	val.assign((unsigned char*)oTemplate[0].pValue, (unsigned char*)((unsigned char*)oTemplate[0].pValue + oTemplate[0].valueLen));

	delete(pValue);

	LOG4CXX_INFO(g_logger, "getting value done.");

	return val;
}

void DataObject::setValue(const VectorUChar& data)
{
	setValue((char*)data.data(), data.size());
}

void DataObject::setValue(const char* pData, int len)
{
	LOG4CXX_INFO(g_logger, "Setting Value...");
	CK_ATTRIBUTE dTemplate[] = {{CKA_VALUE, (void *)pData, len}};

	int rv = C_SetAttributeValue(_sessionHandle, _objectHandle, dTemplate, 1);
	if (rv != CKR_OK) {
		LOG4CXX_ERROR(g_logger, "SetAttributeValue error. err: " << rv);
		throw ExceptionCryptoki(rv, __FILE__, __LINE__);
	}
	LOG4CXX_INFO(g_logger, "Setting Value done.");
}

}
