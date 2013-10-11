/*
 * Key.h
 *
 *  Created on: 1 Eyl 2013
 *      Author: hakilic
 */

#ifndef KEY_H_
#define KEY_H_

#include <string>
#include <vector>

#include "cryptoki.h"

#include "CryptokiHelperTypes.h"
#include "../util/logger.h"


using namespace std;

class Key {
public:
	Key();

	Key(CK_SESSION_HANDLE hndl);
	virtual ~Key();

	/**
	 * Replaces the label of the key object with newname
	 * @param newName new key label
	 */
	void rename(const std::string newName);

	/**
	 * Destroys the key object
	 */
	void destroy();

	uchar*  getKCV(uchar *pKCV, int lenKCV);

	/**
	 * Encrypts data given in parameters
	 * @param mechType Mechanism Type (MT_DES_CBC, MT_DES2_CBC, MT_DES3_CBC, MT_RSA_PKCS)
	 * @param pData address of the data to be encrypted
	 * @param dataLen length of data
	 * @param iv address of initialize vector for CBC mode encryption, default value for ECB mode
	 * @param ivLen length of initialize vector
	 * @return a vector containing encrypted data
	 */
	std::vector<CK_BYTE> encryptData(MechanismType mechType, uchar* pData, ulong dataLen, void* iv = NULL_PTR, ulong ivLen=0);

	/**
	 * Decrypts data given in parameters
	 * @param mechType Mechanism Type (MT_DES_CBC, MT_DES2_CBC, MT_DES3_CBC, MT_RSA_PKCS)
	 * @param pData address of the data to be decrypted
	 * @param dataLen length of data
	 * @param iv iv address of initialize vector for CBC mode encryption, default value for ECB mode or RSA
	 * @param ivLen length of initialize vector
	 * @return a vector containing decrypted data
	 */
	std::vector<CK_BYTE> decryptData(MechanismType mechType, uchar* pData, ulong dataLen, void* iv = NULL_PTR, ulong ivLen=0);

	/**
	 * Wraps out a key given in parameter
	 * @param mechType Mechanism Type (MT_DES_CBC, MT_DES2_CBC, MT_DES3_CBC, MT_RSA_PKCS)
	 * @param key reference of the key to be wrapped
	 * @param iv iv address of initialize vector for CBC mode encryption, default value for ECB mode
	 * @param ivLen ivLen length of initialize vector
	 * @return a vector containing wrapped key
	 */
	std::vector<CK_BYTE> wrapKey(MechanismType mechType, Key &key, void* iv = NULL_PTR, ulong ivLen=0);

	/**
	 * Unwrap a wrapped key given in parameters, build a new key inside HSM
	 * @param mechType Mechanism Type (MT_DES_CBC, MT_DES2_CBC, MT_DES3_CBC, MT_RSA_PKCS)
	 * @param keyType Type of key tobe unwrapped
	 * @param pWrappedKey address of the wrapped key to be unwrapped
	 * @param wrappedKeyLen length of wrapped key
	 * @param iv iv address of initialize vector for CBC mode encryption, default value for ECB mode or RSA
	 * @param ivLen ivLen length of initialize vector
	 * @param isTokenObject if true permanent token object otherwise temporary session object
	 * @return
	 */
	Key unWrapKey(MechanismType mechType, KeyType keyType, CK_BYTE* pWrappedKey, CK_ULONG wrappedKeyLen, void* iv = NULL_PTR, ulong ivLen=0, CK_BBOOL isTokenObject=false);
	Key unWrapKey2(MechanismType mechType, KeyType keyType, CK_BYTE* pWrappedKey, CK_ULONG wrappedKeyLen, void* iv = NULL_PTR, ulong ivLen=0, CK_BBOOL isTokenObject=false);

	CK_OBJECT_HANDLE 	mObjectHandle;
	MechanismType 		mMechType;
	CK_MECHANISM 		mMech;
	CK_SESSION_HANDLE 	mSessionHndl;
	CK_RV 				rv;

private:
	void setMechanism(MechanismType mechType, void *param = NULL_PTR, ulong paramLen=0);
	Util::Logger* mLog;
};


struct KeyPair
{
	Key publicKey;
	Key privateKey;
};

#endif /* KEY_H_ */
