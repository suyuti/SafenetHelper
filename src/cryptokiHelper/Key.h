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
	MechanismInfo(MechanismType _i, void* _p, unsigned long _l) :
		_type(_i),
		_param(_p),
		_paramLen(_l)
	{
	};
} MechanismInfo;

typedef struct KeyAttribute {
	std::string 	_label;
	CK_BBOOL 		_wrap;
	CK_BBOOL		_unwrap;
	CK_BBOOL		_encrypt;
	CK_BBOOL		_decrypt;
	CK_BBOOL		_sensitive;
	CK_BBOOL		_private;
	CK_BBOOL		_extractable;
	CK_BBOOL		_token;
	CK_KEY_TYPE		_keyType;
	CK_OBJECT_CLASS _class;

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
public:
	Key() {};
	Key(CK_SESSION_HANDLE sessionHandle);
	VectorUChar getKcv(MechanismType mt = MT_AES_CBC_PAD);

	VectorUChar encrypt(const MechanismInfo& mech, const VectorUChar& data);
	VectorUChar encrypt(const MechanismInfo& mech, const char* pData, int len);

	VectorUChar decrypt(const MechanismInfo& mech, const VectorUChar& data);
	VectorUChar decrypt(const MechanismInfo& mech, const char* pData, int len);

	VectorUChar sign(const MechanismInfo& mech, const VectorUChar& data);
	VectorUChar sign(const MechanismInfo& mech, const char* pData, int len);

	bool verify(const MechanismInfo& mech, const VectorUChar& data, const VectorUChar& signature);
	bool verify(const MechanismInfo& mech, const char* pData, int dataLen, const char* pSignature, int signatureLen);

	VectorUChar wrap(const MechanismInfo& mech, const Key& other);
	Key			unwrap(const MechanismInfo& mech, const char* pData, int len);
	Key			unwrap(const MechanismInfo& mech, const char* pData, int len, const KeyAttribute& attr);
	Key			unwrap(const MechanismInfo& mech, VectorUChar& data);
	Key			unwrap(const MechanismInfo& mech, VectorUChar& data, const KeyAttribute& attr);

private:
	void 		setMechanism(const MechanismInfo& mInfo);

private:
public:
	CK_MECHANISM 		_mech;
	CK_OBJECT_HANDLE	_objectHandle;
	CK_SESSION_HANDLE	_sessionHandle;
};

struct KeyPair
{
	Key publicKey;
	Key privateKey;
};

}
#endif// _KEY_H_
