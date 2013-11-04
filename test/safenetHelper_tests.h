//---------------------------------------------------------
// Mehmet Suyuti Dindar
// 11.10.2013
// SmartSoft
//---------------------------------------------------------

#ifndef _SAFENET_HELPER_TESTS_H_
#define _SAFENET_HELPER_TESTS_H_

#include <string>

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
		mInfo._param = NULL;
		mInfo._paramLen = 0;
		mInfo._type = MT_RSA_PKCS;
		VectorUChar 	pgTrmk 	= pubGib.wrap(mInfo, trmk);

		KeyExchangeResponse resp;
		int err = _pSafenet->getTraek(pgTrmk, resp);

//		EXPECT_EQ(SUCCESS, err);
//		EXPECT_TRUE(resp._lmk_TREK.size()  > 0);
//		EXPECT_TRUE(resp._lmk_TRAK.size()  > 0);
//		EXPECT_TRUE(resp._kcv_TREK.size()  > 0);
//		EXPECT_TRUE(resp._kcv_TRAK.size()  > 0);
//		EXPECT_TRUE(resp._TRMK_TREK.size() > 0);
//		EXPECT_TRUE(resp._TRMK_TRAK.size() > 0);
//		EXPECT_TRUE(resp._Signature.size() > 0);
//		EXPECT_EQ(SafenetHelperUtil::getActiveLmkIndex(*pC), resp._lmkIndex);
//
//		Cryptoki::Key lmk = SafenetHelperUtil::getActiveLmk(*pC);
//
//		Cryptoki::Key trek = pC->getKeyByName(OC_SECRET_KEY, GIB_TRAK_NAME);
//		VectorUChar lmk_trek = lmk.wrap(mInfo, trek);
//		EXPECT_EQ(lmk_trek, resp._lmk_TREK);
//
//		Cryptoki::Key trak = pC->getKeyByName(OC_SECRET_KEY, GIB_TREK_NAME);
//		VectorUChar lmk_trak = lmk.wrap(mInfo, trak);
//		EXPECT_EQ(lmk_trak, resp._lmk_TRAK);
//
//		VectorUChar trekKcv = trek.getKcv();
//		EXPECT_EQ(trekKcv, resp._kcv_TREK);
//
//		VectorUChar trakKcv = trak.getKcv();
//		EXPECT_EQ(trakKcv, resp._kcv_TRAK);
//
//		VectorUChar trmkTrek = trmk.wrap(mInfo, trek);
//		EXPECT_EQ(trmkTrek, resp._TRMK_TREK);
//
//		VectorUChar trmkTrak = trmk.wrap(mInfo, trak);
//		EXPECT_EQ(trmkTrak, resp._TRMK_TRAK);

		// TODO signature check
	});
}

//-----------------------------------------------------------------------

TEST_F(SafenetHelperTests, processFirst) {
	char _data[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	};
	EXPECT_NO_THROW({
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
		req._lmk_TRAK	= lmk.wrap(mInfo, trak);
		req._lmk_TREK	= lmk.wrap(mInfo, trek);
		req._kcv_TRAK 	= trak.getKcv();
		req._kcv_TREK 	= trek.getKcv();
		req._trek_data 	= trek.encrypt(mInfo, data);

		// TODO
		// req._sha256Data;
		// req._trak_sha256Data;

		ProcessFirstResponse resp;
		int err = _pSafenet->processFirst(req, resp);

		EXPECT_EQ(SUCCESS, err);
		EXPECT_TRUE(resp._clearData.size()  				> 0);

		EXPECT_EQ(data, resp._clearData);
		// TODO
		// check trak_sha256Data
		// check trek_data
	});
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
			'S','P','A','R','T','A',
	};
	char _calculatedSha256[] = {
			0xd0, 0xf9, 0x5c, 0x6e, 0x0c, 0xc9, 0xa0, 0x85,
			0x3c, 0xc9, 0x26, 0xa3, 0x3f, 0x7f, 0xb2, 0x50,
			0x30, 0xf1, 0x3c, 0xf4, 0xf3, 0xde, 0x04, 0x15,
			0x96, 0xf9, 0x7a, 0x22, 0x3f, 0x6e, 0xe9, 0x8b
	};
	EXPECT_NO_THROW({
		Cryptoki::CryptokiHelper* pC = Cryptoki::CryptokiHelper::instance();
		VectorUChar data;
		data.assign(_data, _data + sizeof(_data));

		VectorUChar calculatedSha256;
		calculatedSha256.assign(_calculatedSha256, _calculatedSha256 + sizeof(_calculatedSha256));
		ProcessNextRequest req;

		Cryptoki::Key lmk = SafenetHelperUtil::getActiveLmk(*pC);

		char keyVal[32];
		Cryptoki::MechanismInfo mInfo;
		mInfo._param 	= keyVal;
		mInfo._paramLen = sizeof(keyVal);
		Cryptoki::KeyAttribute kAttr;
		kAttr._label 	= "TRAK";
		kAttr._keyType 	= KT_AES;
		kAttr._token 	= FALSE;
		Cryptoki::Key 	trak 	= pC->createSecretKey("Test_TRAK", kAttr, mInfo);
		kAttr._label 	= "TREK";
		Cryptoki::Key 	trek 	= pC->createSecretKey("Test_TREK", kAttr, mInfo);

		req._lmkIndex 	= SafenetHelperUtil::getActiveLmkIndex(*pC);
		req._lmk_TRAK	= lmk.wrap(mInfo, trak);
		req._lmk_TREK	= lmk.wrap(mInfo, trek);
		req._kcv_TRAK 	= trak.getKcv();
		req._kcv_TREK 	= trek.getKcv();
		req._data		= data;

		ProcessNextResponse resp;
		int err = _pSafenet->processNext(req, resp);

		EXPECT_EQ(SUCCESS, err);
		EXPECT_TRUE(resp._trak_sha256_data.size()  	> 0);
		EXPECT_TRUE(resp._treckData.size()  		> 0);

		VectorUChar calcdTreckData = trek.encrypt(mInfo, data);
		EXPECT_EQ(calcdTreckData, resp._treckData);

		VectorUChar calcdTrakSha256Data = trak.encrypt(mInfo, calculatedSha256);
		EXPECT_EQ(calcdTrakSha256Data, resp._trak_sha256_data);

		// TODO
	});
}
//-----------------------------------------------------------------------
//-----------------------------------------------------------------------
//-----------------------------------------------------------------------
//-----------------------------------------------------------------------
//-----------------------------------------------------------------------


#endif //_SAFENET_HELPER_TESTS_H_
