#include "DataObject.h"
#include "ExceptionCryptoki.h"
#include <iostream>

namespace Cryptoki {

DataObject::DataObject(CK_SESSION_HANDLE sessionHandle)
{
	_sessionHandle = sessionHandle;
}

std::string DataObject::getValueAsStr()
{
	VectorUChar val = this->getValue();
	//std::cout << val.size() << endl;
	std::string str(val.begin(), val.end());

	return str;
}

VectorUChar DataObject::getValue()
{
	VectorUChar val;

	CK_ATTRIBUTE oTemplate[] = {{CKA_VALUE, NULL, 0}};

	int rv = C_GetAttributeValue(_sessionHandle, _objectHandle, oTemplate, 1);
	if (rv != CKR_OK)
		throw ExceptionCryptoki(rv, __FILE__, __LINE__);

	uchar *pValue = new CK_BYTE[oTemplate[0].valueLen];
	oTemplate[0].pValue = pValue;

	rv = C_GetAttributeValue(_sessionHandle, _objectHandle, oTemplate, 1);
	if (rv != CKR_OK) {
		delete[] pValue;
		throw ExceptionCryptoki(rv, __FILE__, __LINE__);
	}

	val.assign((unsigned char*)oTemplate[0].pValue, (unsigned char*)((unsigned char*)oTemplate[0].pValue + oTemplate[0].valueLen));

	delete(pValue);

	return val;
}

void DataObject::setValue(const VectorUChar& data)
{
	setValue((char*)data.data(), data.size());
}

void DataObject::setValue(const char* pData, int len)
{
	CK_ATTRIBUTE dTemplate[] = {{CKA_VALUE, (void *)pData, len}};

	int rv = C_SetAttributeValue(_sessionHandle, _objectHandle, dTemplate, 1);
	if (rv != CKR_OK)
		throw ExceptionCryptoki(rv, __FILE__, __LINE__);
}

}
