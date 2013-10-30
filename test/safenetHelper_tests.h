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

		Cryptoki::DataObject d = pC->getDataByName("GIB", "ActiveLmkIndex");
		std::string data = d.getValueAsStr();
		//std::string expectedIndexData("0000");
		//EXPECT_EQ(0, data.compare(expectedIndexData));


		Cryptoki::Key k 			= pC->getKeyByName(OC_SECRET_KEY,  "LMK_000");
		Cryptoki::Key publicKey 	= pC->getKeyByName(OC_PUBLIC_KEY,  "PbK_GIB");
		Cryptoki::Key privateKey 	= pC->getKeyByName(OC_PRIVATE_KEY, "PrK_GIB");


		k.getKcv(MT_DES3_ECB); // To avoid get warning message
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
		Cryptoki::DataObject d = pC->getDataByName("GIB", "ActiveLmkIndex");
		Cryptoki::Key k =  pC->getKeyByName(OC_SECRET_KEY, "LMK_001");
		std::string dataValue = d.getValueAsStr();
		expectedData = string("0001");
		EXPECT_EQ(0, dataValue.compare(expectedData));
//		k.getKcv();
//
		// add again
		err = _pSafenet->addLmk();
		EXPECT_EQ(SUCCESS, err);
		d = pC->getDataByName("GIB", "ActiveLmkIndex");
		dataValue = d.getValueAsStr();
		expectedData = string("0002");
		EXPECT_EQ(0, dataValue.compare(expectedData));
		k =  pC->getKeyByName(OC_SECRET_KEY, "LMK_002");

		// add again
		err = _pSafenet->addLmk();
		EXPECT_EQ(SUCCESS, err);
		d = pC->getDataByName("GIB", "ActiveLmkIndex");
		dataValue = d.getValueAsStr();
		expectedData = string("0003");
		EXPECT_EQ(0, dataValue.compare(expectedData));
		k =  pC->getKeyByName(OC_SECRET_KEY, "LMK_003");
	});
}

//-----------------------------------------------------------------------

TEST_F(SafenetHelperTests, getFisCalNo) {
	EXPECT_NO_THROW({
//		std::string pin("1234");
//		SafenetHelper* pS = SafenetHelper::instance();
//		Cryptoki::CryptokiHelper* pC = Cryptoki::CryptokiHelper::instance();
//		Cryptoki::Key pubKey = pC->getKeyByName(OC_PUBLIC_KEY, "PbK_CAP");
//
//		pS->login(1L, pin);
//		int err = pS->setup();
//
//		// 1. Pg ile enc edilerek PgFisCalNo bulunur.
//		// 2. getFisCalNo()'ya bu verilir
//		// 3. Sonucta fsCalNo beklenir.
//
//		char PgFisCalNo[256]; // calculate!
//		char fisCalNo[256];
//		err = pS->getFisCalNo(PgFisCalNo, fisCalNo);
//		EXPECT_EQ(SUCCESS, err);
	});
}
//-----------------------------------------------------------------------
//-----------------------------------------------------------------------
//-----------------------------------------------------------------------
//-----------------------------------------------------------------------
//-----------------------------------------------------------------------
//-----------------------------------------------------------------------
//-----------------------------------------------------------------------
//-----------------------------------------------------------------------


#endif //_SAFENET_HELPER_TESTS_H_
