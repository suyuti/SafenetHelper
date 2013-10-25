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
    virtual void SetUp() {
    }

    virtual void TearDown() {
    	std::string pin("1234");
    	CryptokiHelperTestUtil::ClearSlot(1L, pin);
    }
};

//-----------------------------------------------------------------------

TEST_F(SafenetHelperTests, negative_you_cannot_login_into_nonexistent_slot) {
	unsigned long nonExistentSlot = 9999L;
	std::string pin("1234");
	SafenetHelper* pS = SafenetHelper::instance();

	EXPECT_THROW({
		pS->login(nonExistentSlot, pin);
	}, ExceptionCryptoki);
}

//-----------------------------------------------------------------------

TEST_F(SafenetHelperTests, negative_wrong_pin_should_throw_exception) {
	unsigned long nonExistentSlot = 1L;
	std::string pin("9999");
	SafenetHelper* pS = SafenetHelper::instance();

	EXPECT_THROW({
		pS->login(nonExistentSlot, pin);
	}, ExceptionCryptoki);
}

//-----------------------------------------------------------------------

TEST_F(SafenetHelperTests, should_login) {
	unsigned long existentSlot = 1L;
	std::string pin("1234");
	SafenetHelper* pS = SafenetHelper::instance();

	EXPECT_NO_THROW({
		pS->login(existentSlot, pin);
	});
}

//-----------------------------------------------------------------------

TEST_F(SafenetHelperTests, can_be_relogin) {
	unsigned long existentSlot = 1L;
	std::string pin("1234");
	SafenetHelper* pS = SafenetHelper::instance();

	EXPECT_NO_THROW({
		pS->login(existentSlot, pin);
		pS->login(existentSlot, pin);
	});
}

//-----------------------------------------------------------------------

TEST_F(SafenetHelperTests, create_key_token) {
	EXPECT_NO_THROW({
		VectorUChar outKey;
		VectorUChar outKcv;
		int err;
		std::string pin("1234");

		SafenetHelper* pS = SafenetHelper::instance();
		pS->login(1L, pin);
		pS->setup();
		err = pS->GenerateAES256Key(outKey, outKcv);

		EXPECT_EQ(SUCCESS, err);
		//EXPECT_TRUE(outKey.size() != 0);
		EXPECT_TRUE(outKcv.size() != 0);
	});
}

//-----------------------------------------------------------------------

TEST_F(SafenetHelperTests, setup) {
	EXPECT_NO_THROW({
		int err;
		std::string pin("1234");

		SafenetHelper* pS = SafenetHelper::instance();
		pS->login(1L, pin);
		err = pS->setup();

		EXPECT_EQ(SUCCESS, err);

		Cryptoki::CryptokiHelper* pC = Cryptoki::CryptokiHelper::instance();
		Cryptoki::DataObject d = pC->getDataByName("GIB", "ActiveLmkIndex");
		Cryptoki::Key k =  pC->getKeyByName(OC_SECRET_KEY, "LMK_000");
		std::string data = d.getValueAsStr();
		k.getKcv(MT_DES3_ECB); // To avoid get warning message

		std::string expectedIndexData("0000");
		EXPECT_EQ(0, data.compare(expectedIndexData));
	});
}

//-----------------------------------------------------------------------

TEST_F(SafenetHelperTests, addLmk) {
	EXPECT_NO_THROW({
		int err;
		std::string pin("1234");
		std::string expectedData;

		SafenetHelper* pS = SafenetHelper::instance();
		pS->login(1L, pin);
		err = pS->setup();
		EXPECT_EQ(SUCCESS, err);

		err = pS->addLmk();
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
		err = pS->addLmk();
		EXPECT_EQ(SUCCESS, err);
		d = pC->getDataByName("GIB", "ActiveLmkIndex");
		dataValue = d.getValueAsStr();
		expectedData = string("0002");
		EXPECT_EQ(0, dataValue.compare(expectedData));
		k =  pC->getKeyByName(OC_SECRET_KEY, "LMK_002");

		// add again
		err = pS->addLmk();
		EXPECT_EQ(SUCCESS, err);
		d = pC->getDataByName("GIB", "ActiveLmkIndex");
		dataValue = d.getValueAsStr();
		expectedData = string("0003");
		EXPECT_EQ(0, dataValue.compare(expectedData));
		k =  pC->getKeyByName(OC_SECRET_KEY, "LMK_003");
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
//-----------------------------------------------------------------------


#endif //_SAFENET_HELPER_TESTS_H_
