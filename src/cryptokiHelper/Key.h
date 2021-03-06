#ifndef _KEY_H_
#define _KEY_H_
#include <string>
#include "CryptokiHelperTypes.h"
#include "../../include/SafenetHelperTypes.h"
#include "cryptoki.h"

namespace Cryptoki {

typedef struct MechanismInfo {
	MechanismType	_type;
	void* 			_param;
	unsigned long 	_paramLen;
	MechanismInfo() :
		_param(NULL),
		_paramLen(0L)
	{
	};
} MechanismInfo;

typedef struct KeyAttribute {
	std::string _label;
	CK_BBOOL 	_wrap;
	CK_BBOOL	_unwrap;
	CK_BBOOL	_encrypt;
	CK_BBOOL	_decrypt;
	CK_BBOOL	_sensitive;
	CK_BBOOL	_private;
	CK_BBOOL	_extractable;
	CK_BBOOL	_token;
	CK_KEY_TYPE	_keyType;

	KeyAttribute() :
		_wrap		(TRUE),
		_unwrap		(TRUE),
		_encrypt	(TRUE),
		_decrypt	(TRUE),
		_sensitive	(TRUE),
		_private	(TRUE),
		_extractable(TRUE),
		_token		(TRUE)
	{
	};

} KeyAttribute, *HKeyAttribute;

class CryptokiHelper;

class Key
{
	friend class CryptokiHelper;
private:
	Key() {};
public:
	Key(CK_SESSION_HANDLE sessionHandle);
	VectorUChar getKcv();

	VectorUChar encrypt(const MechanismInfo& mech, const VectorUChar& data);
	VectorUChar encrypt(const MechanismInfo& mech, const char* pData, int len);

	VectorUChar decrypt(const MechanismInfo& mech, const VectorUChar& data);
	VectorUChar decrypt(const MechanismInfo& mech, const char* pData, int len);

	VectorUChar wrap(const MechanismInfo& mech, const Key& other);
	Key			unwrap(const MechanismInfo& mech, const char* pData, int len);
	Key			unwrap(const MechanismInfo& mech, const char* pData, int len, const KeyAttribute& attr);
	Key			unwrap(const MechanismInfo& mech, VectorUChar& data);
	Key			unwrap(const MechanismInfo& mech, VectorUChar& data, const KeyAttribute& attr);

private:
	void 		setMechanism(const MechanismInfo& mInfo);

private:
	CK_MECHANISM 		_mech;
	CK_OBJECT_HANDLE	_objectHandle;
	CK_SESSION_HANDLE	_sessionHandle;
};
}
#endif// _KEY_H_
