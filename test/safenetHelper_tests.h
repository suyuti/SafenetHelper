//---------------------------------------------------------
// Mehmet Suyuti Dindar
// 11.10.2013
// SmartSoft
//---------------------------------------------------------

#ifndef _SAFENET_HELPER_TESTS_H_
#define _SAFENET_HELPER_TESTS_H_

#include <string>
#include <algorithm>

#include "gtest/gtest.h"
#include "../src/SafenetHelper.h"
#include "../include/SafenetHelperErr.h"
#include "../src/cryptokiHelper/ExceptionCryptoki.h"
#include "cryptoHelper_Tests/cryptokiHelper_tests.h"
#include "cryptoHelper_Tests/cryptokiHelperTestUtil.h"
#include "../src/SafenetHelperUtil.h"

#ifdef __GNUC__
   #define __UNUSED__ __attribute__((unused))
#else
   #define __UNUSED__
#endif

//-----------------------------------------------------------------------
// NOTICE
//
// Slot 1 should be exist on HSM also pin must be '1234'
//-----------------------------------------------------------------------

class SafenetHelperTests : public ::testing::Test {
public:
	SafenetHelperTests() :
		_pin("1234"),
		_slot(1L)
	{
		_pSafenet = SafenetHelper::instance();
		_pSafenet->login(_slot, _pin);
	}
	virtual ~SafenetHelperTests() {
    	CryptokiHelperTestUtil::ClearSlot(_slot, _pin);
	}

	virtual void SetUp() {
    }

    virtual void TearDown() {
    	//std::string pin("1234");
    	//CryptokiHelperTestUtil::ClearSlot(1L, pin);
    }

protected:
    SafenetHelper* 	_pSafenet;
    std::string 	_pin;
    int 			_slot;
};

//-----------------------------------------------------------------------

TEST_F(SafenetHelperTests, negative_you_cannot_login_into_nonexistent_slot) {
	unsigned long nonExistentSlot = 9999L;

	EXPECT_THROW({
		_pSafenet->login(nonExistentSlot, _pin);
	}, ExceptionCryptoki);
}

//-----------------------------------------------------------------------

TEST_F(SafenetHelperTests, negative_wrong_pin_should_throw_exception) {
	std::string wrongPin("9999");

	EXPECT_THROW({
		_pSafenet->login(_slot, wrongPin);
	}, ExceptionCryptoki);
}

//-----------------------------------------------------------------------

TEST_F(SafenetHelperTests, should_login) {
	EXPECT_NO_THROW({
		_pSafenet->login(_slot, _pin);
	});
}

//-----------------------------------------------------------------------

TEST_F(SafenetHelperTests, can_be_relogin) {
	EXPECT_NO_THROW({
		_pSafenet->login(_slot, _pin);
		_pSafenet->login(_slot, _pin);
	});
}

//-----------------------------------------------------------------------

TEST_F(SafenetHelperTests, create_key_token) {
	EXPECT_NO_THROW({
		VectorUChar outKey;
		VectorUChar outKcv;
		int err;
		err = _pSafenet->GenerateAES256Key(outKey, outKcv);

		EXPECT_EQ(SUCCESS, err);
		//EXPECT_TRUE(outKey.size() != 0);
		EXPECT_TRUE(outKcv.size() != 0);
	});
}

//-----------------------------------------------------------------------

TEST_F(SafenetHelperTests, setup) {
	EXPECT_NO_THROW({
		Cryptoki::CryptokiHelper* pC = Cryptoki::CryptokiHelper::instance();

		Cryptoki::DataObject d = pC->getDataByName(GIB_APPNAME, GIB_ACTIVE_LMK_INDEX);
		std::string data = d.getValueAsStr();
		//std::string expectedIndexData("0000");
		//EXPECT_EQ(0, data.compare(expectedIndexData));

		Cryptoki::Key k __UNUSED__  = pC->getKeyByName(OC_SECRET_KEY,  "LMK_000");
		Cryptoki::Key publicKey __UNUSED__ = pC->getKeyByName(OC_PUBLIC_KEY,  GIB_PUBLIC_KEY_NAME);
		Cryptoki::Key privateKey __UNUSED__ = pC->getKeyByName(OC_PRIVATE_KEY, GIB_PRIVATE_KEY_NAME);
	});
}

//-----------------------------------------------------------------------

TEST_F(SafenetHelperTests, addLmk) {
	EXPECT_NO_THROW({
		int err;
		std::string expectedData;

		err = _pSafenet->addLmk();
		EXPECT_EQ(SUCCESS, err);

		Cryptoki::CryptokiHelper* pC = Cryptoki::CryptokiHelper::instance();
		Cryptoki::DataObject d = pC->getDataByName(GIB_APPNAME, GIB_ACTIVE_LMK_INDEX);
		Cryptoki::Key k =  pC->getKeyByName(OC_SECRET_KEY, "LMK_001");
		std::string dataValue = d.getValueAsStr();
		expectedData = string("0001");
		EXPECT_EQ(0, dataValue.compare(expectedData));
//		k.getKcv();
//
		// add again
		err = _pSafenet->addLmk();
		EXPECT_EQ(SUCCESS, err);
		d = pC->getDataByName(GIB_APPNAME, GIB_ACTIVE_LMK_INDEX);
		dataValue = d.getValueAsStr();
		expectedData = string("0002");
		EXPECT_EQ(0, dataValue.compare(expectedData));
		k =  pC->getKeyByName(OC_SECRET_KEY, "LMK_002");

		// add again
		err = _pSafenet->addLmk();
		EXPECT_EQ(SUCCESS, err);
		d = pC->getDataByName(GIB_APPNAME, GIB_ACTIVE_LMK_INDEX);
		dataValue = d.getValueAsStr();
		expectedData = string("0003");
		EXPECT_EQ(0, dataValue.compare(expectedData));
		k =  pC->getKeyByName(OC_SECRET_KEY, "LMK_003");
	});
}

//-----------------------------------------------------------------------

TEST_F(SafenetHelperTests, getFisCalNo) {
	EXPECT_NO_THROW({
		char _fisCalNo[] = "1234567890";
		VectorUChar fisCalNo;
		fisCalNo.assign(_fisCalNo, _fisCalNo + sizeof(_fisCalNo));

		Cryptoki::CryptokiHelper* pC = Cryptoki::CryptokiHelper::instance();
		Cryptoki::Key pubKey = pC->getKeyByName(OC_PUBLIC_KEY, GIB_PUBLIC_KEY_NAME);
		Cryptoki::MechanismInfo mInfo;
		mInfo._type = MT_RSA_PKCS;
		VectorUChar pgFisCalNo = pubKey.encrypt(mInfo, fisCalNo);

		VectorUChar response;
		int err = _pSafenet->getFisCalNo(pgFisCalNo, response);

		EXPECT_EQ(SUCCESS, err);
		EXPECT_TRUE(response.size() > 0);
		EXPECT_EQ(fisCalNo, response);
	});
}

//-----------------------------------------------------------------------

TEST_F(SafenetHelperTests, getTraek) {
	EXPECT_NO_THROW({
		Cryptoki::CryptokiHelper* pC = Cryptoki::CryptokiHelper::instance();

		char keyVal[32];
		Cryptoki::MechanismInfo mInfo;
		mInfo._param 	= keyVal;
		mInfo._paramLen = sizeof(keyVal);

		Cryptoki::KeyAttribute kAttr;
		kAttr._label 	= "Test_TRMK";
		kAttr._keyType 	= KT_AES;
		kAttr._token 	= FALSE;
		Cryptoki::Key 	trmk 	= pC->createSecretKey("Test_TRMK", kAttr, mInfo);
		Cryptoki::Key 	pubGib 	= pC->getKeyByName(OC_PUBLIC_KEY, GIB_PUBLIC_KEY_NAME);
		mInfo._param 	= NULL;
		mInfo._paramLen = 0;
		mInfo._type 	= MT_RSA_PKCS;
		VectorUChar 	pgTrmk 	= pubGib.wrap(mInfo, trmk);

		KeyExchangeResponse resp;
		int err = _pSafenet->getTraek(pgTrmk, resp);

		EXPECT_EQ(SUCCESS, err);
		EXPECT_TRUE(resp._lmk_TREK.size()  > 0);
		EXPECT_TRUE(resp._lmk_TRAK.size()  > 0);
		EXPECT_TRUE(resp._kcv_TREK.size()  > 0);
		EXPECT_TRUE(resp._kcv_TRAK.size()  > 0);
		EXPECT_TRUE(resp._TRMK_TREK.size() > 0);
		EXPECT_TRUE(resp._TRMK_TRAK.size() > 0);

		// TODO Signature testi
		//EXPECT_TRUE(resp._Signature.size() > 0);

		EXPECT_EQ(SafenetHelperUtil::getActiveLmkIndex(*pC), resp._lmkIndex);

		Cryptoki::Key lmk 	= SafenetHelperUtil::getActiveLmk(*pC);
		Cryptoki::Key trak 	= pC->getKeyByName(OC_SECRET_KEY, GIB_TRAK_NAME);
		mInfo._param 		= NULL;
		mInfo._paramLen 	= 0;
		mInfo._type 		= MT_DES3_ECB;
		VectorUChar lmk_trak = lmk.wrap(mInfo, trak);
		EXPECT_EQ(lmk_trak, resp._lmk_TRAK);

		Cryptoki::Key trek = pC->getKeyByName(OC_SECRET_KEY, GIB_TREK_NAME);
		VectorUChar lmk_trek = lmk.wrap(mInfo, trek);
		EXPECT_EQ(lmk_trek, resp._lmk_TREK);

		EXPECT_NE(resp._lmk_TRAK, resp._lmk_TREK);

		VectorUChar trekKcv = trek.getKcv();
		EXPECT_EQ(trekKcv, resp._kcv_TREK);

		VectorUChar trakKcv = trak.getKcv();
		EXPECT_EQ(trakKcv, resp._kcv_TRAK);


		mInfo._param 		= NULL;
		mInfo._paramLen 	= 0;
		mInfo._type 		= MT_AES_ECB;
		VectorUChar trmkTrek = trmk.wrap(mInfo, trek);
		EXPECT_EQ(trmkTrek, resp._TRMK_TREK);

		VectorUChar trmkTrak = trmk.wrap(mInfo, trak);
		EXPECT_EQ(trmkTrak, resp._TRMK_TRAK);

		// TODO signature check
	});
}

//-----------------------------------------------------------------------

TEST_F(SafenetHelperTests, processFirst) {
	char _data[] = {
			'T','H','I','S',' ',
			'I','S',' ',
			'T','E','S','T',' ',
			'D','A','T','A',' ',
			'N','O','T',' ',
			'S','P','A','R','T','A',' ',' ',' ',' '
	};
	LOG4CXX_INFO(g_loggerTest, "Test: processFirst");
	EXPECT_NO_THROW({
		// test preperation
		Cryptoki::CryptokiHelper* pC = Cryptoki::CryptokiHelper::instance();
		VectorUChar data;
		data.assign(_data, _data + sizeof(_data));

		ProcessFirstRequest req;
		Cryptoki::Key lmk = SafenetHelperUtil::getActiveLmk(*pC);

		Cryptoki::KeyAttribute kAttr;
		kAttr._token 	= FALSE;
		Cryptoki::Key trak = SafenetHelperUtil::createAES256Key(pC, "TRAK", kAttr);
		Cryptoki::Key trek = SafenetHelperUtil::createAES256Key(pC, "TREK", kAttr);

		char keyVal[32];
		Cryptoki::MechanismInfo mInfo;
		mInfo._param 	= keyVal;
		mInfo._paramLen = sizeof(keyVal);

		req._lmkIndex 	= SafenetHelperUtil::getActiveLmkIndex(*pC);
		mInfo._param 	= NULL;
		mInfo._paramLen = 0;
		mInfo._type 	= MT_DES3_ECB;
		req._lmk_TRAK	= lmk.wrap(mInfo, trak);
		req._lmk_TREK	= lmk.wrap(mInfo, trek);
		req._kcv_TRAK 	= trak.getKcv();
		req._kcv_TREK 	= trek.getKcv();

		mInfo._param 	= NULL;
		mInfo._paramLen = 0;
		mInfo._type 	= MT_AES_ECB;
		req._trek_data 	= trek.encrypt(mInfo, data);

		req._sha256Data = pC->generateSHA256(data);
		req._trak_sha256Data = trak.encrypt(mInfo, req._sha256Data);

		// testee
		LOG4CXX_INFO(g_loggerTest, "Test prepared");
		ProcessFirstResponse resp;
		int err = _pSafenet->processFirst(req, resp);

		// result check
		EXPECT_EQ(SUCCESS, err);
		EXPECT_TRUE(resp._clearData.size() > 0);
		EXPECT_EQ(data, resp._clearData);
	});
}

TEST_F(SafenetHelperTests, negative_processFirst_invalid_lmk_index) {
	char _data[] = {
			'T','H','I','S',' ',
			'I','S',' ',
			'T','E','S','T',' ',
			'D','A','T','A',' ',
			'N','O','T',' ',
			'S','P','A','R','T','A',' ',' ',' ',' '
	};
	LOG4CXX_INFO(g_loggerTest, "Test: processFirst");
	EXPECT_THROW({
		// test preperation
		Cryptoki::CryptokiHelper* pC = Cryptoki::CryptokiHelper::instance();
		VectorUChar data;
		data.assign(_data, _data + sizeof(_data));

		ProcessFirstRequest req;
		Cryptoki::Key lmk = SafenetHelperUtil::getActiveLmk(*pC);

		Cryptoki::KeyAttribute kAttr;
		kAttr._token 	= FALSE;
		Cryptoki::Key trak = SafenetHelperUtil::createAES256Key(pC, "TRAK", kAttr);
		Cryptoki::Key trek = SafenetHelperUtil::createAES256Key(pC, "TREK", kAttr);

		char keyVal[32];
		Cryptoki::MechanismInfo mInfo;
		mInfo._param 	= keyVal;
		mInfo._paramLen = sizeof(keyVal);

		req._lmkIndex 	= SafenetHelperUtil::getActiveLmkIndex(*pC) + 100; // invalid LMK
		mInfo._param 	= NULL;
		mInfo._paramLen = 0;
		mInfo._type 	= MT_DES3_ECB;
		req._lmk_TRAK	= lmk.wrap(mInfo, trak);
		req._lmk_TREK	= lmk.wrap(mInfo, trek);
		req._kcv_TRAK 	= trak.getKcv();
		req._kcv_TREK 	= trek.getKcv();

		mInfo._param 	= NULL;
		mInfo._paramLen = 0;
		mInfo._type 	= MT_AES_ECB;
		req._trek_data 	= trek.encrypt(mInfo, data);

		req._sha256Data = pC->generateSHA256(data);
		req._trak_sha256Data = trak.encrypt(mInfo, req._sha256Data);

		// testee
		LOG4CXX_INFO(g_loggerTest, "Test prepared");
		ProcessFirstResponse resp;
		int err __UNUSED__ = _pSafenet->processFirst(req, resp); // Should throw exception here
	}, ExceptionCryptoki);
}


TEST_F(SafenetHelperTests, negative_processFirst_invalid_kcv_of_trak) {
	char _data[] = {
			'T','H','I','S',' ',
			'I','S',' ',
			'T','E','S','T',' ',
			'D','A','T','A',' ',
			'N','O','T',' ',
			'S','P','A','R','T','A',' ',' ',' ',' '
	};
	LOG4CXX_INFO(g_loggerTest, "Test: processFirst");
	EXPECT_THROW({
		// test preperation
		Cryptoki::CryptokiHelper* pC = Cryptoki::CryptokiHelper::instance();
		VectorUChar data;
		data.assign(_data, _data + sizeof(_data));

		ProcessFirstRequest req;
		Cryptoki::Key lmk = SafenetHelperUtil::getActiveLmk(*pC);

		Cryptoki::KeyAttribute kAttr;
		kAttr._token 	= FALSE;
		Cryptoki::Key trak = SafenetHelperUtil::createAES256Key(pC, "TRAK", kAttr);
		Cryptoki::Key trek = SafenetHelperUtil::createAES256Key(pC, "TREK", kAttr);

		char keyVal[32];
		Cryptoki::MechanismInfo mInfo;
		mInfo._param 	= keyVal;
		mInfo._paramLen = sizeof(keyVal);

		req._lmkIndex 	= SafenetHelperUtil::getActiveLmkIndex(*pC);
		mInfo._param 	= NULL;
		mInfo._paramLen = 0;
		mInfo._type 	= MT_DES3_ECB;
		req._lmk_TRAK	= lmk.wrap(mInfo, trak);
		req._lmk_TREK	= lmk.wrap(mInfo, trek);
		req._kcv_TRAK 	= trak.getKcv();
		std::rotate(req._kcv_TRAK.begin(), req._kcv_TRAK.begin() + 1, req._kcv_TRAK.end()); // KCV of TRAK changed!
		req._kcv_TREK 	= trek.getKcv();

		mInfo._param 	= NULL;
		mInfo._paramLen = 0;
		mInfo._type 	= MT_AES_ECB;
		req._trek_data 	= trek.encrypt(mInfo, data);

		req._sha256Data = pC->generateSHA256(data);
		req._trak_sha256Data = trak.encrypt(mInfo, req._sha256Data);

		// testee
		LOG4CXX_INFO(g_loggerTest, "Test prepared");
		ProcessFirstResponse resp;
		int err __UNUSED__ = _pSafenet->processFirst(req, resp); // Should throw exception here
	}, ExceptionCryptoki);
}

TEST_F(SafenetHelperTests, negative_processFirst_invalid_kcv_of_trek) {
	char _data[] = {
			'T','H','I','S',' ',
			'I','S',' ',
			'T','E','S','T',' ',
			'D','A','T','A',' ',
			'N','O','T',' ',
			'S','P','A','R','T','A',' ',' ',' ',' '
	};
	LOG4CXX_INFO(g_loggerTest, "Test: negative_processFirst_invalid_kcv_of_trek");
	EXPECT_THROW({
		// test preperation
		Cryptoki::CryptokiHelper* pC = Cryptoki::CryptokiHelper::instance();
		VectorUChar data;
		data.assign(_data, _data + sizeof(_data));

		ProcessFirstRequest req;
		Cryptoki::Key lmk = SafenetHelperUtil::getActiveLmk(*pC);

		Cryptoki::KeyAttribute kAttr;
		kAttr._token 	= FALSE;
		Cryptoki::Key trak = SafenetHelperUtil::createAES256Key(pC, "TRAK", kAttr);
		Cryptoki::Key trek = SafenetHelperUtil::createAES256Key(pC, "TREK", kAttr);

		char keyVal[32];
		Cryptoki::MechanismInfo mInfo;
		mInfo._param 	= keyVal;
		mInfo._paramLen = sizeof(keyVal);

		req._lmkIndex 	= SafenetHelperUtil::getActiveLmkIndex(*pC);
		mInfo._param 	= NULL;
		mInfo._paramLen = 0;
		mInfo._type 	= MT_DES3_ECB;
		req._lmk_TRAK	= lmk.wrap(mInfo, trak);
		req._lmk_TREK	= lmk.wrap(mInfo, trek);
		req._kcv_TRAK 	= trak.getKcv();
		req._kcv_TREK 	= trek.getKcv();

		std::rotate(req._kcv_TREK.begin(), req._kcv_TREK.begin() + 1, req._kcv_TREK.end()); // KCV of TREK changed!

		mInfo._param 	= NULL;
		mInfo._paramLen = 0;
		mInfo._type 	= MT_AES_ECB;
		req._trek_data 	= trek.encrypt(mInfo, data);

		req._sha256Data = pC->generateSHA256(data);
		req._trak_sha256Data = trak.encrypt(mInfo, req._sha256Data);

		// testee
		LOG4CXX_INFO(g_loggerTest, "Test prepared");
		ProcessFirstResponse resp;
		int err __UNUSED__ = _pSafenet->processFirst(req, resp); // Should throw exception here
	}, ExceptionCryptoki);
}


TEST_F(SafenetHelperTests, negative_processFirst_invalid_SHA256Data) {
	char _data[] = {
			'T','H','I','S',' ',
			'I','S',' ',
			'T','E','S','T',' ',
			'D','A','T','A',' ',
			'N','O','T',' ',
			'S','P','A','R','T','A',' ',' ',' ',' '
	};
	LOG4CXX_INFO(g_loggerTest, "Test: negative_processFirst_invalid_SHA256Data");
	EXPECT_THROW({
		// test preperation
		Cryptoki::CryptokiHelper* pC = Cryptoki::CryptokiHelper::instance();
		VectorUChar data;
		data.assign(_data, _data + sizeof(_data));

		ProcessFirstRequest req;
		Cryptoki::Key lmk = SafenetHelperUtil::getActiveLmk(*pC);

		Cryptoki::KeyAttribute kAttr;
		kAttr._token 	= FALSE;
		Cryptoki::Key trak = SafenetHelperUtil::createAES256Key(pC, "TRAK", kAttr);
		Cryptoki::Key trek = SafenetHelperUtil::createAES256Key(pC, "TREK", kAttr);

		char keyVal[32];
		Cryptoki::MechanismInfo mInfo;
		mInfo._param 	= keyVal;
		mInfo._paramLen = sizeof(keyVal);

		req._lmkIndex 	= SafenetHelperUtil::getActiveLmkIndex(*pC);
		mInfo._param 	= NULL;
		mInfo._paramLen = 0;
		mInfo._type 	= MT_DES3_ECB;
		req._lmk_TRAK	= lmk.wrap(mInfo, trak);
		req._lmk_TREK	= lmk.wrap(mInfo, trek);
		req._kcv_TRAK 	= trak.getKcv();
		req._kcv_TREK 	= trek.getKcv();


		mInfo._param 	= NULL;
		mInfo._paramLen = 0;
		mInfo._type 	= MT_AES_ECB;
		req._trek_data 	= trek.encrypt(mInfo, data);

		req._sha256Data = pC->generateSHA256(data);
		std::rotate(req._sha256Data.begin(), req._sha256Data.begin() + 1, req._sha256Data.end()); // SHA256Data changed!
		req._trak_sha256Data = trak.encrypt(mInfo, req._sha256Data);


		// testee
		LOG4CXX_INFO(g_loggerTest, "Test prepared");
		ProcessFirstResponse resp;
		int err __UNUSED__ = _pSafenet->processFirst(req, resp); // Should throw exception here
	}, ExceptionCryptoki);
}

TEST_F(SafenetHelperTests, negative_processFirst_invalid_key_type) {
	char _data[] = {
			'T','H','I','S',' ',
			'I','S',' ',
			'T','E','S','T',' ',
			'D','A','T','A',' ',
			'N','O','T',' ',
			'S','P','A','R','T','A',' ',' ',' ',' '
	};
	EXPECT_THROW({
		// test preperation
		Cryptoki::CryptokiHelper* pC = Cryptoki::CryptokiHelper::instance();
		VectorUChar data;
		data.assign(_data, _data + sizeof(_data));

		ProcessFirstRequest req;
		Cryptoki::Key lmk = SafenetHelperUtil::getActiveLmk(*pC);

		Cryptoki::KeyAttribute kAttr;
		kAttr._token = FALSE;
		Cryptoki::Key trak = SafenetHelperUtil::createDES2Key(pC, "TRAK", kAttr);
		Cryptoki::Key trek = SafenetHelperUtil::createDES2Key(pC, "TREK", kAttr);

		Cryptoki::MechanismInfo mInfo;
		req._lmkIndex 	= SafenetHelperUtil::getActiveLmkIndex(*pC);
		mInfo._param 	= NULL;
		mInfo._paramLen = 0;
		mInfo._type 	= MT_DES3_ECB;
		req._lmk_TRAK	= lmk.wrap(mInfo, trak);
		req._lmk_TREK	= lmk.wrap(mInfo, trek);
		req._kcv_TRAK 	= trak.getKcv(MT_DES3_ECB);
		req._kcv_TREK 	= trek.getKcv(MT_DES3_ECB);

		unsigned char iv[8] = {0x00};
		mInfo._type 	= MT_DES3_CBC;
		mInfo._param 	= iv;
		mInfo._paramLen = sizeof(iv);
		req._trek_data 	= trek.encrypt(mInfo, data);

		req._sha256Data = pC->generateSHA256(data);
		req._trak_sha256Data = trak.encrypt(mInfo, req._sha256Data);

		// testee
		ProcessFirstResponse resp;
		int err __UNUSED__ = _pSafenet->processFirst(req, resp);  // should throw here
	}, ExceptionCryptoki);
}

//-----------------------------------------------------------------------------

TEST_F(SafenetHelperTests, DISABLED_negative_processFirst_invalid_encrypt_type) {
	char _data[] = {
			'T','H','I','S',' ',
			'I','S',' ',
			'T','E','S','T',' ',
			'D','A','T','A',' ',
			'N','O','T',' ',
			'S','P','A','R','T','A',' ',' ',' ',' '
	};
	EXPECT_THROW({
		// test preperation
		Cryptoki::CryptokiHelper* pC = Cryptoki::CryptokiHelper::instance();
		VectorUChar data;
		data.assign(_data, _data + sizeof(_data));

		ProcessFirstRequest req;
		Cryptoki::Key lmk = SafenetHelperUtil::getActiveLmk(*pC);

		char keyVal[32];
		Cryptoki::MechanismInfo mInfo;
		mInfo._param 	= keyVal;
		mInfo._paramLen = sizeof(keyVal);

		Cryptoki::KeyAttribute kAttr;
		kAttr._token 	= FALSE;

		Cryptoki::Key trak = SafenetHelperUtil::createAES256Key(pC, "TRAK", kAttr);
		Cryptoki::Key trek = SafenetHelperUtil::createAES256Key(pC, "TREK", kAttr);

		req._lmkIndex 	= SafenetHelperUtil::getActiveLmkIndex(*pC);
		mInfo._param 	= NULL;
		mInfo._paramLen = 0;
		mInfo._type 	= MT_DES3_ECB;
		req._lmk_TRAK	= lmk.wrap(mInfo, trak);
		req._lmk_TREK	= lmk.wrap(mInfo, trek);
		req._kcv_TRAK 	= trak.getKcv();
		req._kcv_TREK 	= trek.getKcv();

		mInfo._param 	= NULL;
		mInfo._paramLen = 0;
		mInfo._type 	= MT_DES3_ECB;
		req._trek_data 	= trek.encrypt(mInfo, data);

		req._sha256Data = pC->generateSHA256(data);
		req._trak_sha256Data = trak.encrypt(mInfo, req._sha256Data);

		// testee
		ProcessFirstResponse resp;
		int err = _pSafenet->processFirst(req, resp);

		// result check
		EXPECT_EQ(SUCCESS, err);
		EXPECT_TRUE(resp._clearData.size() > 0);
		EXPECT_EQ(data, resp._clearData);
	},ExceptionCryptoki);
}
TEST_F(SafenetHelperTests, DISABLED_negative_processFirst_invalid_input_data_size) {
	char _data[] = {
			'H','I','S',' ',
			'I','S',' ',
			'T','E','S','T',' ',
			'D','A','T','A',' ',
			'N','O','T',' ',
			'S','P','A','R','T','A',' ',' ',' ',' '
	};
	EXPECT_THROW({
		// test preperation
		Cryptoki::CryptokiHelper* pC = Cryptoki::CryptokiHelper::instance();
		VectorUChar data;
		data.assign(_data, _data + sizeof(_data));

		ProcessFirstRequest req;
		Cryptoki::Key lmk = SafenetHelperUtil::getActiveLmk(*pC);

		char keyVal[32];
		Cryptoki::MechanismInfo mInfo;
		mInfo._param 	= keyVal;
		mInfo._paramLen = sizeof(keyVal);
		Cryptoki::KeyAttribute kAttr;
		kAttr._label 	= "TRAK";
		kAttr._keyType 	= KT_AES;
		kAttr._token 	= FALSE;
		Cryptoki::Key 	trak 	= pC->createSecretKey("TRAK", kAttr, mInfo);
		kAttr._label 	= "TREK";
		Cryptoki::Key 	trek 	= pC->createSecretKey("TREK", kAttr, mInfo);

		req._lmkIndex 	= SafenetHelperUtil::getActiveLmkIndex(*pC);
		mInfo._param 	= NULL;
		mInfo._paramLen = 0;
		mInfo._type 	= MT_DES3_ECB;
		req._lmk_TRAK	= lmk.wrap(mInfo, trak);
		req._lmk_TREK	= lmk.wrap(mInfo, trek);
		req._kcv_TRAK 	= trak.getKcv();
		req._kcv_TREK 	= trek.getKcv();

		mInfo._param 	= NULL;
		mInfo._paramLen = 0;
		mInfo._type 	= MT_AES_ECB;
		req._trek_data 	= trek.encrypt(mInfo, data);

		req._sha256Data = pC->generateSHA256(data);
		req._trak_sha256Data = trak.encrypt(mInfo, req._sha256Data);

		// testee
		ProcessFirstResponse resp;
		int err = _pSafenet->processFirst(req, resp);

		// result check
		EXPECT_EQ(SUCCESS, err);
		EXPECT_TRUE(resp._clearData.size() > 0);
		EXPECT_EQ(data, resp._clearData);
	},ExceptionCryptoki);
}
TEST_F(SafenetHelperTests, DISABLED_negative_processFirst_invalid_lmk) {
	char _data[] = {
			'T','H','I','S',' ',
			'I','S',' ',
			'T','E','S','T',' ',
			'D','A','T','A',' ',
			'N','O','T',' ',
			'S','P','A','R','T','A',' ',' ',' ',' '
	};
	EXPECT_THROW({
		// test preperation
		Cryptoki::CryptokiHelper* pC = Cryptoki::CryptokiHelper::instance();
		VectorUChar data;
		data.assign(_data, _data + sizeof(_data));

		ProcessFirstRequest req;
		Cryptoki::Key lmk = SafenetHelperUtil::getActiveLmk(*pC);

		char keyVal[32];
		Cryptoki::MechanismInfo mInfo;
		mInfo._param 	= keyVal;
		mInfo._paramLen = sizeof(keyVal);
		Cryptoki::KeyAttribute kAttr;
		kAttr._label 	= "TRAK";
		kAttr._keyType 	= KT_AES;
		kAttr._token 	= FALSE;
		Cryptoki::Key 	trak 	= pC->createSecretKey("TRAK", kAttr, mInfo);
		kAttr._label 	= "TREK";
		Cryptoki::Key 	trek 	= pC->createSecretKey("TREK", kAttr, mInfo);

		req._lmkIndex 	= -1;
		mInfo._param 	= NULL;
		mInfo._paramLen = 0;
		mInfo._type 	= MT_DES3_ECB;
		req._lmk_TRAK	= lmk.wrap(mInfo, trak);
		req._lmk_TREK	= lmk.wrap(mInfo, trek);
		req._kcv_TRAK 	= trak.getKcv();
		req._kcv_TREK 	= trek.getKcv();

		mInfo._param 	= NULL;
		mInfo._paramLen = 0;
		mInfo._type 	= MT_AES_ECB;
		req._trek_data 	= trek.encrypt(mInfo, data);

		req._sha256Data = pC->generateSHA256(data);
		req._trak_sha256Data = trak.encrypt(mInfo, req._sha256Data);

		// testee
		ProcessFirstResponse resp;
		int err = _pSafenet->processFirst(req, resp);

		// result check
		EXPECT_EQ(SUCCESS, err);
		EXPECT_TRUE(resp._clearData.size() > 0);
		EXPECT_EQ(data, resp._clearData);
	},ExceptionCryptoki);
}
TEST_F(SafenetHelperTests, DISABLED_negative_processFirst_invalid_trekkey) {
	char _data[] = {
			'T','H','I','S',' ',
			'I','S',' ',
			'T','E','S','T',' ',
			'D','A','T','A',' ',
			'N','O','T',' ',
			'S','P','A','R','T','A',' ',' ',' ',' '
	};
	EXPECT_THROW({
		// test preperation
		Cryptoki::CryptokiHelper* pC = Cryptoki::CryptokiHelper::instance();
		VectorUChar data;
		data.assign(_data, _data + sizeof(_data));

		ProcessFirstRequest req;
		Cryptoki::Key lmk = SafenetHelperUtil::getActiveLmk(*pC);

		char keyVal[32];
		Cryptoki::MechanismInfo mInfo;
		mInfo._param 	= keyVal;
		mInfo._paramLen = sizeof(keyVal);
		Cryptoki::KeyAttribute kAttr;
		kAttr._label 	= "TRAK";
		kAttr._keyType 	= KT_AES;
		kAttr._token 	= FALSE;
		Cryptoki::Key 	trak 	= pC->createSecretKey("TRAK", kAttr, mInfo);
		kAttr._label 	= "TREK";
		Cryptoki::Key 	trek;

		req._lmkIndex 	= SafenetHelperUtil::getActiveLmkIndex(*pC);
		mInfo._param 	= NULL;
		mInfo._paramLen = 0;
		mInfo._type 	= MT_DES3_ECB;
		req._lmk_TRAK	= lmk.wrap(mInfo, trak);
		req._lmk_TREK	= lmk.wrap(mInfo, trek);
		req._kcv_TRAK 	= trak.getKcv();
		req._kcv_TREK 	= trek.getKcv();

		mInfo._param 	= NULL;
		mInfo._paramLen = 0;
		mInfo._type 	= MT_AES_ECB;
		req._trek_data 	= trek.encrypt(mInfo, data);

		req._sha256Data = pC->generateSHA256(data);
		req._trak_sha256Data = trak.encrypt(mInfo, req._sha256Data);

		// testee
		ProcessFirstResponse resp;
		int err = _pSafenet->processFirst(req, resp);

		// result check
		EXPECT_EQ(SUCCESS, err);
		EXPECT_TRUE(resp._clearData.size() > 0);
		EXPECT_EQ(data, resp._clearData);
	},ExceptionCryptoki);
}
TEST_F(SafenetHelperTests, DISABLED_negative_processFirst_invalid_trakkey) {
	char _data[] = {
			'T','H','I','S',' ',
			'I','S',' ',
			'T','E','S','T',' ',
			'D','A','T','A',' ',
			'N','O','T',' ',
			'S','P','A','R','T','A',' ',' ',' ',' '
	};
	EXPECT_THROW({
		// test preperation
		Cryptoki::CryptokiHelper* pC = Cryptoki::CryptokiHelper::instance();
		VectorUChar data;
		data.assign(_data, _data + sizeof(_data));

		ProcessFirstRequest req;
		Cryptoki::Key lmk = SafenetHelperUtil::getActiveLmk(*pC);

		char keyVal[32];
		Cryptoki::MechanismInfo mInfo;
		mInfo._param 	= keyVal;
		mInfo._paramLen = sizeof(keyVal);
		Cryptoki::KeyAttribute kAttr;
		kAttr._label 	= "TRAK";
		kAttr._keyType 	= KT_AES;
		kAttr._token 	= FALSE;
		Cryptoki::Key trak;
		kAttr._label 	= "TREK";
		Cryptoki::Key 	trek 	= pC->createSecretKey("TREK", kAttr, mInfo);

		req._lmkIndex 	= SafenetHelperUtil::getActiveLmkIndex(*pC);
		mInfo._param 	= NULL;
		mInfo._paramLen = 0;
		mInfo._type 	= MT_DES3_ECB;
		req._lmk_TRAK	= lmk.wrap(mInfo, trak);
		req._lmk_TREK	= lmk.wrap(mInfo, trek);
		req._kcv_TRAK 	= trak.getKcv();
		req._kcv_TREK 	= trek.getKcv();

		mInfo._param 	= NULL;
		mInfo._paramLen = 0;
		mInfo._type 	= MT_AES_ECB;
		req._trek_data 	= trek.encrypt(mInfo, data);

		req._sha256Data = pC->generateSHA256(data);
		req._trak_sha256Data = trak.encrypt(mInfo, req._sha256Data);

		// testee
		ProcessFirstResponse resp;
		int err = _pSafenet->processFirst(req, resp);

		// result check
		EXPECT_EQ(SUCCESS, err);
		EXPECT_TRUE(resp._clearData.size() > 0);
		EXPECT_EQ(data, resp._clearData);
	},ExceptionCryptoki);
}

//-----------------------------------------------------------------------
/**
 * inputs:  G,H,I,J,K,S
 * */

TEST_F(SafenetHelperTests, processNext) {
	char _data[] = {
			'T','H','I','S',' ',
			'I','S',' ',
			'T','E','S','T',' ',
			'D','A','T','A',' ',
			'N','O','T',' ',
			'S','P','A','R','T','A',' ',' ',' ',' '
	};

	// Calculated by http://www.xorbin.com/tools/sha256-hash-calculator
	unsigned char _calculatedSha256[] = {
			0x0a, 0xdc, 0x70, 0xd2, 0x49, 0x3b, 0x50, 0xc1,
			0x63, 0x18, 0x7b, 0xdc, 0x2b, 0x14, 0x49, 0xc8,
			0xe3, 0xd8, 0x84, 0xf9, 0x81, 0x90, 0x76, 0xe9,
			0x28, 0x3b, 0x21, 0xfd, 0x3a, 0x43, 0x54, 0x6b,
	};

	EXPECT_NO_THROW({
		Cryptoki::CryptokiHelper* pC = Cryptoki::CryptokiHelper::instance();
		VectorUChar data;
		data.assign(_data, _data + sizeof(_data));

		VectorUChar calculatedSha256;
		calculatedSha256.assign(_calculatedSha256, _calculatedSha256 + sizeof(_calculatedSha256));
		ProcessNextRequest req;

		Cryptoki::Key lmk = SafenetHelperUtil::getActiveLmk(*pC);

		char trakIV[32];
		char trekIV[32];
		Cryptoki::MechanismInfo mInfo;
		mInfo._param 	= trakIV;
		mInfo._paramLen = sizeof(trakIV);
		Cryptoki::KeyAttribute kAttr;
		kAttr._label 	= "TRAK";
		kAttr._keyType 	= KT_AES;
		kAttr._token 	= FALSE;
		Cryptoki::Key 	trak 	= pC->createSecretKey("Test_TRAK", kAttr, mInfo);

		mInfo._param 	= trekIV;
		mInfo._paramLen = sizeof(trekIV);
		kAttr._label 	= "TREK";
		Cryptoki::Key 	trek 	= pC->createSecretKey("Test_TREK", kAttr, mInfo);

		req._lmkIndex 	= SafenetHelperUtil::getActiveLmkIndex(*pC);
		mInfo._param 	= NULL;
		mInfo._paramLen = 0;
		mInfo._type 	= MT_DES3_ECB;
		req._lmk_TRAK	= lmk.wrap(mInfo, trak);
		req._lmk_TREK	= lmk.wrap(mInfo, trek);
		req._kcv_TRAK 	= trak.getKcv();
		req._kcv_TREK 	= trek.getKcv();
		req._data		= data;

		EXPECT_NE(req._kcv_TRAK, req._kcv_TREK);

		ProcessNextResponse resp;
		int err = _pSafenet->processNext(req, resp);

		EXPECT_EQ(SUCCESS, err);
		EXPECT_TRUE(resp._trak_sha256_data.size()  	> 0);
		EXPECT_TRUE(resp._treckData.size()  		> 0);

		mInfo._param = NULL;
		mInfo._paramLen = 0L;
		mInfo._type = MT_AES_ECB;
		VectorUChar calcdTreckData = trek.encrypt(mInfo, data);
		EXPECT_EQ(calcdTreckData, resp._treckData);

		mInfo._param = NULL;
		mInfo._paramLen = 0L;
		mInfo._type = MT_AES_ECB;
		VectorUChar calcdTrakSha256Data = trak.encrypt(mInfo, calculatedSha256);
		EXPECT_EQ(calcdTrakSha256Data, resp._trak_sha256_data);
	});
}

//-----------------------------------------------------------------------

TEST_F(SafenetHelperTests, negative_processNext_invalid_lmk_index) {
	char _data[] = {
			'T','H','I','S',' ',
			'I','S',' ',
			'T','E','S','T',' ',
			'D','A','T','A',' ',
			'N','O','T',' ',
			'S','P','A','R','T','A',' ',' ',' ',' '
	};

	EXPECT_THROW({
		Cryptoki::CryptokiHelper* pC = Cryptoki::CryptokiHelper::instance();
		VectorUChar data;
		data.assign(_data, _data + sizeof(_data));

		ProcessNextRequest req;

		Cryptoki::Key lmk = SafenetHelperUtil::getActiveLmk(*pC);

		char trakIV[32] __UNUSED__;
		char trekIV[32] __UNUSED__;
		Cryptoki::MechanismInfo mInfo;
		mInfo._param 	= trakIV;
		mInfo._paramLen = sizeof(trakIV);
		Cryptoki::KeyAttribute kAttr;
		kAttr._token = FALSE;
		Cryptoki::Key trak = SafenetHelperUtil::createAES256Key(pC, "TRAK", kAttr);
		Cryptoki::Key trek = SafenetHelperUtil::createAES256Key(pC, "TREK", kAttr);

		req._lmkIndex 	= SafenetHelperUtil::getActiveLmkIndex(*pC) + 100; // LMK Index changed here
		mInfo._param 	= NULL;
		mInfo._paramLen = 0;
		mInfo._type 	= MT_DES3_ECB;
		req._lmk_TRAK	= lmk.wrap(mInfo, trak);
		req._lmk_TREK	= lmk.wrap(mInfo, trek);
		req._kcv_TRAK 	= trak.getKcv();
		req._kcv_TREK 	= trek.getKcv();
		req._data		= data;

		EXPECT_NE(req._kcv_TRAK, req._kcv_TREK);

		ProcessNextResponse resp;
		_pSafenet->processNext(req, resp); // Should throw exception here
	}, ExceptionCryptoki);
}

//-----------------------------------------------------------------------

TEST_F(SafenetHelperTests, negative_processNext_invalid_kcv_of_trak) {
	char _data[] = {
			'T','H','I','S',' ',
			'I','S',' ',
			'T','E','S','T',' ',
			'D','A','T','A',' ',
			'N','O','T',' ',
			'S','P','A','R','T','A',' ',' ',' ',' '
	};

	EXPECT_THROW({
		Cryptoki::CryptokiHelper* pC = Cryptoki::CryptokiHelper::instance();
		VectorUChar data;
		data.assign(_data, _data + sizeof(_data));

		ProcessNextRequest req;

		Cryptoki::Key lmk = SafenetHelperUtil::getActiveLmk(*pC);

		char trakIV[32] __UNUSED__;
		char trekIV[32] __UNUSED__;
		Cryptoki::MechanismInfo mInfo;
		mInfo._param 	= trakIV;
		mInfo._paramLen = sizeof(trakIV);
		Cryptoki::KeyAttribute kAttr;
		kAttr._token = FALSE;
		Cryptoki::Key trak = SafenetHelperUtil::createAES256Key(pC, "TRAK", kAttr);
		Cryptoki::Key trek = SafenetHelperUtil::createAES256Key(pC, "TREK", kAttr);

		req._lmkIndex 	= SafenetHelperUtil::getActiveLmkIndex(*pC);
		mInfo._param 	= NULL;
		mInfo._paramLen = 0;
		mInfo._type 	= MT_DES3_ECB;
		req._lmk_TRAK	= lmk.wrap(mInfo, trak);
		req._lmk_TREK	= lmk.wrap(mInfo, trek);
		req._kcv_TRAK 	= trak.getKcv();
		std::rotate(req._kcv_TRAK.begin(), req._kcv_TRAK.begin() + 1, req._kcv_TRAK.end()); // KCV of TRAK changed!
		req._kcv_TREK 	= trek.getKcv();
		req._data		= data;

		ProcessNextResponse resp;
		_pSafenet->processNext(req, resp); // Should throw exception here
	}, ExceptionCryptoki);
}

//-----------------------------------------------------------------------

TEST_F(SafenetHelperTests, negative_processNext_invalid_kcv_of_trek) {
	char _data[] = {
			'T','H','I','S',' ',
			'I','S',' ',
			'T','E','S','T',' ',
			'D','A','T','A',' ',
			'N','O','T',' ',
			'S','P','A','R','T','A',' ',' ',' ',' '
	};

	EXPECT_THROW({
		Cryptoki::CryptokiHelper* pC = Cryptoki::CryptokiHelper::instance();
		VectorUChar data;
		data.assign(_data, _data + sizeof(_data));

		ProcessNextRequest req;

		Cryptoki::Key lmk = SafenetHelperUtil::getActiveLmk(*pC);

		char trakIV[32] __UNUSED__;
		char trekIV[32] __UNUSED__;
		Cryptoki::MechanismInfo mInfo;
		mInfo._param 	= trakIV;
		mInfo._paramLen = sizeof(trakIV);
		Cryptoki::KeyAttribute kAttr;
		kAttr._token = FALSE;
		Cryptoki::Key trak = SafenetHelperUtil::createAES256Key(pC, "TRAK", kAttr);
		Cryptoki::Key trek = SafenetHelperUtil::createAES256Key(pC, "TREK", kAttr);

		req._lmkIndex 	= SafenetHelperUtil::getActiveLmkIndex(*pC);
		mInfo._param 	= NULL;
		mInfo._paramLen = 0;
		mInfo._type 	= MT_DES3_ECB;
		req._lmk_TRAK	= lmk.wrap(mInfo, trak);
		req._lmk_TREK	= lmk.wrap(mInfo, trek);
		req._kcv_TRAK 	= trak.getKcv();
		req._kcv_TREK 	= trek.getKcv();
		std::rotate(req._kcv_TREK.begin(), req._kcv_TREK.begin() + 1, req._kcv_TREK.end()); // KCV of TREK changed!
		req._data		= data;

		ProcessNextResponse resp;
		_pSafenet->processNext(req, resp); // Should throw exception here
	}, ExceptionCryptoki);
}
//-----------------------------------------------------------------------
//-----------------------------------------------------------------------


#endif //_SAFENET_HELPER_TESTS_H_
