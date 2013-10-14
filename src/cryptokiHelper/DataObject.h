#ifndef _DATAOBJECT_H_
#define _DATAOBJECT_H_

#include <string>
#include "../../include/SafenetHelperTypes.h"
#include "cryptoki.h"

namespace Cryptoki {

typedef struct {
	std::string 	_application;
	std::string 	_label;
	CK_BBOOL		_token;
	CK_BBOOL		_private;
	char* 			_data;
	int 			_dataLen;
} DataAttribute;

class CryptokiHelper;

class DataObject
{
	friend class CryptokiHelper;
private:
	DataObject() {};
public:
	DataObject(CK_SESSION_HANDLE sessionHandle);
	VectorUChar getValue();
	void setValue(const VectorUChar& data);
	void setValue(const char* pData, int len);
private:
	CK_OBJECT_HANDLE	_objectHandle;
	CK_SESSION_HANDLE	_sessionHandle;
};
}

#endif// _DATAOBJECT_H_
