#ifndef _KEY_TESTS_H_
#define _KEY_TESTS_H_

#include "gtest/gtest.h"
#include "../../src/cryptokiHelper/CryptokiHelper.h"
#include "../../src/cryptokiHelper/Key.h"
#include "cryptokiHelper_tests.h"

class keyTests : public ::testing::Test {
public:
    virtual void SetUp() {
    }

    virtual void TearDown() {
    	std::string pin("1234");
		CryptokiHelperTests::CryptokiHelperEx::ClearSlot(1L, pin);
    }
};

TEST_F(keyTests, enc_dec) {
	Cryptoki::CryptokiHelper* p = Cryptoki::CryptokiHelper::instance();
	std::string pin("1234");
	unsigned long slot = 1L;
	p->open(slot, pin);

	Cryptoki::KeyAttribute attr;
	attr._token = TRUE;

	Cryptoki::MechanismInfo mInfo;
	mInfo._type = MT_DES2_KEY_GEN;
	Cryptoki::Key k = p->createKey("SessionBasedTestKey_for_encdec", attr, mInfo);

	unsigned char iv[8] = {0x00};
	mInfo._type = MT_DES3_CBC;
	mInfo._param = iv;
	mInfo._paramLen = sizeof(iv);
	char clearData[] = {
						0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
						0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
						};
	VectorUChar encData = k.encrypt(mInfo, clearData, sizeof(clearData));
	VectorUChar decData = k.decrypt(mInfo, encData);

	p->close();
	EXPECT_TRUE(encData.size() != 0);
	EXPECT_TRUE(decData.size() != 0);
	EXPECT_EQ(sizeof(clearData), decData.size());
	EXPECT_EQ(0, memcmp(clearData, decData.data(), decData.size()));
}

TEST_F(keyTests, negative_encrypt_not_permitted) {
	char clearData[] = {
						0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
						0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
						};
	EXPECT_THROW(
		{
			Cryptoki::CryptokiHelper* p = Cryptoki::CryptokiHelper::instance();
			std::string pin("1234");
			unsigned long slot = 1L;
			p->open(slot, pin);

			Cryptoki::KeyAttribute attr;
			attr._token = TRUE;
			attr._encrypt = FALSE;

			Cryptoki::MechanismInfo mInfo;
			mInfo._type = MT_DES2_KEY_GEN;
			Cryptoki::Key k = p->createKey("SessionBasedTestKey_for_encdec", attr, mInfo);

			unsigned char iv[8] = {0x00};
			mInfo._type = MT_DES3_CBC;
			mInfo._param = iv;
			mInfo._paramLen = sizeof(iv);
			VectorUChar encData = k.encrypt(mInfo, clearData, sizeof(clearData));
			VectorUChar decData = k.decrypt(mInfo, encData);

			p->close();
			EXPECT_TRUE(encData.size() != 0);
			EXPECT_TRUE(decData.size() != 0);
			EXPECT_EQ(sizeof(clearData), decData.size());
			EXPECT_EQ(0, memcmp(clearData, decData.data(), decData.size()));
		},
		ExceptionCryptoki);
}

TEST_F(keyTests, negative_decrypt_not_permitted) {
	char clearData[] = {
						0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
						0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
						};
	EXPECT_THROW(
		{
			Cryptoki::CryptokiHelper* p = Cryptoki::CryptokiHelper::instance();
			std::string pin("1234");
			unsigned long slot = 1L;
			p->open(slot, pin);

			Cryptoki::KeyAttribute attr;
			attr._token = TRUE;
			attr._decrypt = FALSE;

			Cryptoki::MechanismInfo mInfo;
			mInfo._type = MT_DES2_KEY_GEN;
			Cryptoki::Key k = p->createKey("SessionBasedTestKey_for_encdec", attr, mInfo);

			unsigned char iv[8] = {0x00};
			mInfo._type = MT_DES3_CBC;
			mInfo._param = iv;
			mInfo._paramLen = sizeof(iv);
			VectorUChar encData = k.encrypt(mInfo, clearData, sizeof(clearData));
			VectorUChar decData = k.decrypt(mInfo, encData);

			p->close();
			EXPECT_TRUE(encData.size() != 0);
			EXPECT_TRUE(decData.size() != 0);
			EXPECT_EQ(sizeof(clearData), decData.size());
			EXPECT_EQ(0, memcmp(clearData, decData.data(), decData.size()));
		},
		ExceptionCryptoki);
}

TEST_F(keyTests, wrap_unwrap) {
	Cryptoki::CryptokiHelper* p = Cryptoki::CryptokiHelper::instance();
	std::string pin("1234");
	unsigned long slot = 1L;
	p->open(slot, pin);

	Cryptoki::MechanismInfo mInfo;
	mInfo._type = MT_DES2_KEY_GEN;
	Cryptoki::Key kWrapper = p->createKey("Test_WrapperKey", mInfo);
	Cryptoki::Key k = p->createKey("Test_Key", mInfo);

	unsigned char iv[8] = {0x00};
	mInfo._type = MT_DES3_CBC;
	mInfo._param = iv;
	mInfo._paramLen = sizeof(iv);
	VectorUChar wrappedKey = kWrapper.wrap(mInfo, k);
	Cryptoki::KeyAttribute attr;
	attr._keyType = KT_DES2;
	Cryptoki::Key kTarget = kWrapper.unwrap(mInfo, wrappedKey, attr);

	mInfo._type = MT_DES3_CBC;
	mInfo._param = iv;
	mInfo._paramLen = sizeof(iv);
	char clearData[] = {
						0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
						0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
						};
	VectorUChar encData = k.encrypt(mInfo, clearData, sizeof(clearData));
	VectorUChar decData = kTarget.decrypt(mInfo, encData);

	p->close();
	EXPECT_TRUE(encData.size() != 0);
	EXPECT_TRUE(decData.size() != 0);
	EXPECT_EQ(sizeof(clearData), decData.size());
	EXPECT_EQ(0, memcmp(clearData, decData.data(), decData.size()));
}

TEST_F(keyTests, negative_wrap_not_permitted) {
	unsigned char iv[8] = {0x00};
	char clearData[] = {
						0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
						0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
						};
	EXPECT_THROW(
			{
				Cryptoki::CryptokiHelper* p = Cryptoki::CryptokiHelper::instance();
				std::string pin("1234");
				unsigned long slot = 1L;
				p->open(slot, pin);

				Cryptoki::MechanismInfo mInfo;
				mInfo._type = MT_DES2_KEY_GEN;
				Cryptoki::KeyAttribute attrForWraper;
				attrForWraper._wrap = FALSE;
				Cryptoki::Key kWrapper = p->createKey("Test_WrapperKey", attrForWraper, mInfo);
				Cryptoki::Key k = p->createKey("Test_Key", mInfo);

				mInfo._type = MT_DES3_CBC;
				mInfo._param = iv;
				mInfo._paramLen = sizeof(iv);
				VectorUChar wrappedKey = kWrapper.wrap(mInfo, k);
				Cryptoki::KeyAttribute attr;
				attr._keyType = KT_DES2;
				Cryptoki::Key kTarget = kWrapper.unwrap(mInfo, wrappedKey, attr);

				mInfo._type = MT_DES3_CBC;
				mInfo._param = iv;
				mInfo._paramLen = sizeof(iv);
				VectorUChar encData = k.encrypt(mInfo, clearData, sizeof(clearData));
				VectorUChar decData = kTarget.decrypt(mInfo, encData);

				p->close();
				EXPECT_TRUE(encData.size() != 0);
				EXPECT_TRUE(decData.size() != 0);
				EXPECT_EQ(sizeof(clearData), decData.size());
				EXPECT_EQ(0, memcmp(clearData, decData.data(), decData.size()));
			},
			ExceptionCryptoki);
}

TEST_F(keyTests, negative_unwrap_not_permitted) {
	unsigned char iv[8] = {0x00};
	char clearData[] = {
						0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
						0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
						};
	EXPECT_THROW(
			{
				Cryptoki::CryptokiHelper* p = Cryptoki::CryptokiHelper::instance();
				std::string pin("1234");
				unsigned long slot = 1L;
				p->open(slot, pin);

				Cryptoki::MechanismInfo mInfo;
				mInfo._type = MT_DES2_KEY_GEN;
				Cryptoki::KeyAttribute attrForWraper;
				attrForWraper._wrap = TRUE;
				attrForWraper._unwrap = FALSE;
				Cryptoki::Key kWrapper = p->createKey("Test_WrapperKey", attrForWraper, mInfo);
				Cryptoki::Key k = p->createKey("Test_Key", mInfo);

				mInfo._type = MT_DES3_CBC;
				mInfo._param = iv;
				mInfo._paramLen = sizeof(iv);
				VectorUChar wrappedKey = kWrapper.wrap(mInfo, k);
				Cryptoki::KeyAttribute attr;
				attr._keyType = KT_DES2;
				Cryptoki::Key kTarget = kWrapper.unwrap(mInfo, wrappedKey, attr);

				mInfo._type = MT_DES3_CBC;
				mInfo._param = iv;
				mInfo._paramLen = sizeof(iv);
				VectorUChar encData = k.encrypt(mInfo, clearData, sizeof(clearData));
				VectorUChar decData = kTarget.decrypt(mInfo, encData);

				p->close();
				EXPECT_TRUE(encData.size() != 0);
				EXPECT_TRUE(decData.size() != 0);
				EXPECT_EQ(sizeof(clearData), decData.size());
				EXPECT_EQ(0, memcmp(clearData, decData.data(), decData.size()));
			},
			ExceptionCryptoki);
}

#endif// _KEY_TESTS_H_
