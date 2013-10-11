#include <vector>
#include <string>
#include <algorithm>

#include "CryptokiHelperTypes.h"
#include "../util/logger.h"
#include "Key.h"
//Cryptoki related includes
#include "cryptoki.h"
#include "ctvdef.h"
#include "ctutil.h"
#include "genmacro.h"


#ifndef CRYPTOKIHELPER_H_
#define CRYPTOKIHELPER_H_

using namespace std;

#define ADMIN_PIN "1234"

class CryptokiHelper {

private:
	CryptokiHelper();
	static CryptokiHelper *pInstance;

public:

	virtual ~CryptokiHelper();
	static CryptokiHelper *instance();

	/**
	 * Initializes cryptoki library
	 */
	void initialize();

	/**
	 * Open a session on given slot id
	 * @param slotId slot id
	 * @param sessionTypes (FLG_RW_SESSION, FLG_SERIAL_SESSION, FLG_EXCLUSIVE_SESSION )
	 */
	void openSession(ulong slotId, enum CKFlag sessionTypes = FLG_RW_SESSION);

	/**
	 * Closes the session
	 */
	void closeSession();

	/**
	 * Logs in to an open session
	 * @param userType User Type (UT_USER, UT_SO)
	 * @param pinCode address of alphanumeric pincode value
	 * @param pinLen length of pincode
	 */
	void login(enum UserType userType, uchar *pinCode, ulong pinLen);
	void login(std::string& pin, enum UserType userType = UT_USER);


	/*
	 * Creates a slot object in hsm (İhtiyacımız olmayacak)
	 * returns clot id;
	 */
	ulong createSlot();

	/**
	 * Search for Admin Slot (İhtiyacımız olmayacak)
	 * @return admin slot id
	 */
	ulong getAdminSlotId(); //CK_SLOT_ID

	/**
	 * Returns the key object referenced by given label
	 * @param objClass Object Class information (OC_SECRET_KEY, OC_PUBLIC_KEY, OC_PRIVATE_KEY)
	 * @param keyName label of key to be searched
	 * @return Key object if found otherwise throws ExceptionCryptoki::OBJECT_NOT_FOUND exception
	 */
	Key getKeyByName(ObjectClass objClass, const std::string keyName);

	/**
	 * Generates an Symmetric key object specified by MechanismType
	 * @param mechType Symmetric key generation mechanism (MT_DES_KEY_GEN, MT_DES2_KEY_GEN, MT_DES3_KEY_GEN)
	 * @param keyName Key Label
	 * @param isTokenObj if true permanent token object otherwise temporary session object
	 * @return new Key object
	 */
	Key generateSecretKey(const std::string keyName, bool isTokenObj);

	/**
	 * Generates and RSA key pair
	 * @param pbKeyName label of public key
	 * @param prKeyName label of private key
	 * @param isTokenObj if true permanent token object otherwise temporary session object
	 * @return new KeyPair object carrying public key & private key
	 */
	KeyPair generateKeyPair(std::string pbKeyName, std::string prKeyName, bool isTokenObj);

	/**
	 * Creates a new Symmetric key object from given key value
	 * @param keyVal value of key (odd parity adjustment is inside function)
	 * @param keyLen length of key value
	 * @param keyName label of key
	 * @param isTokenObj if true permanent token object otherwise temporary session object
	 * @return new Key object
	 */
	Key createSecretKey(const uchar* keyVal, ulong keyLen, const std::string keyName, bool isTokenObj);

	/**
	 * Creates a new public key object from given public key value
	 * @param modulus
	 * @param modulusLen
	 * @param exponent
	 * @param exponentLen
	 * @param keyName Label of new key
	 * @param isTokenObj  if true permanent token object otherwise temporary session object
	 * @return new Key object
	 */
	Key createRSAPublicKey(uchar* modulus, ulong modulusLen, uchar* exponent, ulong exponentLen, const std::string keyName, bool isTokenObj);

	/**
	 * Creates new RSA private key object (We dont need, not implemented)
	 * @param keyName label of key
	 * @return a new Key object with garbage value
	 */
	Key createRSAPrivateKey(const std::string keyName);

	/**
	 * Creates a CMK specified by idx
	 * @param idx CMK index to create new CMK
	 */
	void generateCMK(ushort idx, bool test=false);

	/**
	 * Gets the number of CMK, HSM contain CMK keys with CMK_ prefix  (CMK_00, CMK_01, CMK_01....)
	 * @return number of CMK, HSM contains
	 */
	ulong getCMKCount(bool test=false);

	/**
	 *
	 * @param idxCK Derivation Root Key index (1-10)
	 * @param derivationData =  TUKS, terrmId, fiscalNo (total 16 bytes)
	 * @param derDataLen length of derivationData
	 * @return DUK-KEK[i] = Enc_3DES_CBC(CMKi[], derivationData)
	 */
	std::vector<CK_BYTE> deriveKey(ushort idxCMK,	const uchar* derivationData, ulong derDataLen, bool test=false);

	/**
	 * Generates derivation data input for DUK-KEK calculation
	 * @param termId 16 bytes Terminal Id
	 * @param fiscalNo 16 bytes Fiscal No
	 * @param tuks 16 bytes TUKS
	 * @return pointer to 16 byte static array keeping derivation data
	 */
	uchar* calculateDerivationData(const uchar *termId, const uchar *fiscalNo, const uchar *tuks);


	std::vector<uchar> getWrappedCMKList(std::string wrapKeyName, bool test=false);

	uint createDataObject(std::string appName, std::string objName, uchar* pData, int dataLen);
	void setDataObjectValue(std::string appName, std::string objName, const uchar* pData, int dataLen);
	void getDataObjectValue(std::string appName, std::string objName, uchar* outBuf, int* outLen);
	int getDataObject(std::string appName, std::string objName);


	CK_RV rv;
	uchar *pAdminPIN; 	//CK_CHAR
	ulong adminPINLen;  //CK_COUNT
	ulong mSessionHndl; //CK_SESSION_HANDLE
	Util::Logger* mLog;
};

#endif /* CRYPTOKIHELPER_H_ */
