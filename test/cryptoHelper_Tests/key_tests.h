#ifndef _KEY_TESTS_H_
#define _KEY_TESTS_H_

#include "gtest/gtest.h"
#include "../../src/cryptokiHelper/CryptokiHelper.h"
#include "../../src/cryptokiHelper/Key.h"
#include "cryptokiHelper_tests.h"
#include "cryptokiHelperTestUtil.h"

class keyTests : public ::testing::Test {
public:
    virtual void SetUp() {
    }

    virtual void TearDown() {
    	std::string pin("1234");
    	CryptokiHelperTestUtil::ClearSlot(1L, pin);
    }
};

//-----------------------------------------------------------------------------
/**
 * Creates a DES2 Key
 * */

TEST_F(keyTests, create_key) {
	EXPECT_NO_THROW({
		Cryptoki::CryptokiHelper* p = Cryptoki::CryptokiHelper::instance();
		std::string pin("1234");
		unsigned long slot = 1L;
		p->open(slot, pin);
		Cryptoki::KeyAttribute attr;
		Cryptoki::MechanismInfo mInfo;
		attr._token = TRUE;
		attr._class = CKO_SECRET_KEY;
		mInfo._type = MT_DES2_KEY_GEN;
		p->createKey("TestKey", attr, mInfo);
		p->close();
	});
}

//-----------------------------------------------------------------------------

TEST_F(keyTests, create_and_find_token_key) {
	EXPECT_NO_THROW({
		Cryptoki::CryptokiHelper* p = Cryptoki::CryptokiHelper::instance();
		std::string pin("1234");
		unsigned long slot = 1L;
		p->open(slot, pin);
		Cryptoki::KeyAttribute attr;
		Cryptoki::MechanismInfo mInfo;
		attr._token = TRUE;
		attr._class = OC_SECRET_KEY;
		mInfo._type = MT_DES2_KEY_GEN;
		p->createKey("TokenBasedTestKey", attr, mInfo);
		p->close();

		// find
		p->open(slot, pin);
		Cryptoki::Key k = p->getKeyByName(OC_SECRET_KEY, "TokenBasedTestKey");
		k.getKcv(MT_DES3_ECB); // to avoid from not used variable warning
		p->close();
	});
}

//-----------------------------------------------------------------------------

TEST_F(keyTests, create_and_find_session_key) {
	EXPECT_NO_THROW({
		Cryptoki::CryptokiHelper* p = Cryptoki::CryptokiHelper::instance();
		std::string pin("1234");
		unsigned long slot = 1L;
		p->open(slot, pin);
		Cryptoki::KeyAttribute attr;
		Cryptoki::MechanismInfo mInfo;
		attr._token = FALSE;
		mInfo._type = MT_DES2_KEY_GEN;
		p->createKey("SessionBasedTestKey", attr, mInfo);
		// find
		Cryptoki::Key k = p->getKeyByName(OC_SECRET_KEY, "SessionBasedTestKey");
		k.getKcv(MT_DES3_ECB); // to avoid from not used variable warning
		p->close();
	});
}

//-----------------------------------------------------------------------------

TEST_F(keyTests, negative_find_key) {
	EXPECT_THROW(
		{
			Cryptoki::CryptokiHelper* p = Cryptoki::CryptokiHelper::instance();
			std::string pin("1234");
			unsigned long slot = 1L;
			p->open(slot, pin);
			Cryptoki::Key k = p->getKeyByName(OC_SECRET_KEY, "TestKey"); // Throw here!
			k.getKcv(); // to avoid from not used variable warning
			p->close();
		},
		ExceptionCryptoki);
}

//-----------------------------------------------------------------------------

TEST_F(keyTests, negative_create_and_not_found_Session_key) {
	EXPECT_THROW(
		{
			Cryptoki::CryptokiHelper* p = Cryptoki::CryptokiHelper::instance();
			std::string pin("1234");
			unsigned long slot = 1L;
			p->open(slot, pin);
			Cryptoki::KeyAttribute attr;
			Cryptoki::MechanismInfo mInfo;
			attr._token = FALSE;
			mInfo._type = MT_DES2_KEY_GEN;
			p->createKey("SessionBasedTestKey", attr, mInfo);
			p->close();

			// find
			p->open(slot, pin);
			Cryptoki::Key k = p->getKeyByName(OC_SECRET_KEY, "SessionBasedTestKey"); // Throws here!
			k.getKcv(); // to avoid from not used variable warning
			p->close();
		},
		ExceptionCryptoki);
}

//-----------------------------------------------------------------------------

TEST_F(keyTests, enc_dec) {
	char clearData[] = {
						0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
						0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
						};
	EXPECT_NO_THROW({
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
		VectorUChar encData = k.encrypt(mInfo, clearData, sizeof(clearData));
		VectorUChar decData = k.decrypt(mInfo, encData);

		p->close();
		EXPECT_TRUE(encData.size() != 0);
		EXPECT_TRUE(decData.size() != 0);
		EXPECT_EQ(sizeof(clearData), decData.size());
		EXPECT_EQ(0, memcmp(clearData, decData.data(), decData.size()));
	});
}

//-----------------------------------------------------------------------------

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

//-----------------------------------------------------------------------------

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
			VectorUChar decData = k.decrypt(mInfo, encData); // Throws here!

			p->close();
			EXPECT_TRUE(encData.size() != 0);
			EXPECT_TRUE(decData.size() != 0);
			EXPECT_EQ(sizeof(clearData), decData.size());
			EXPECT_EQ(0, memcmp(clearData, decData.data(), decData.size()));
		},
		ExceptionCryptoki);
}

//-----------------------------------------------------------------------------

TEST_F(keyTests, wrap_unwrap) {
	char clearData[] = {
						0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
						0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
						};
	EXPECT_NO_THROW({
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
		VectorUChar encData = k.encrypt(mInfo, clearData, sizeof(clearData));
		VectorUChar decData = kTarget.decrypt(mInfo, encData);

		p->close();
		EXPECT_TRUE(encData.size() != 0);
		EXPECT_TRUE(decData.size() != 0);
		EXPECT_EQ(sizeof(clearData), decData.size());
		EXPECT_EQ(0, memcmp(clearData, decData.data(), decData.size()));
	});
}
//-----------------------------------------------------------------------------

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
				VectorUChar wrappedKey = kWrapper.wrap(mInfo, k); // Throws here
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

//-----------------------------------------------------------------------------

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
				Cryptoki::Key kTarget = kWrapper.unwrap(mInfo, wrappedKey, attr); // Throws here!

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

//-----------------------------------------------------------------------------

TEST_F(keyTests, create_key_by_value) {
	char keyVal[32];
	EXPECT_NO_THROW({
		std::string keyName("Test_AES_by_val");
		Cryptoki::CryptokiHelper* p = Cryptoki::CryptokiHelper::instance();
		std::string pin("1234");
		unsigned long slot = 1L;
		p->open(slot, pin);

		Cryptoki::MechanismInfo mInfo;
		mInfo._param 	= keyVal;
		mInfo._paramLen = sizeof(keyVal);

		Cryptoki::KeyAttribute kAttr;
		kAttr._label 	= keyName;
		kAttr._keyType 	= KT_AES;
		Cryptoki::Key k = p->createSecretKey(keyName, kAttr, mInfo);
		VectorUChar kcv = k.getKcv();

		Cryptoki::Key kk = p->getKeyByName(OC_SECRET_KEY, keyName);
		VectorUChar kkcv = kk.getKcv();
		p->close();

		EXPECT_EQ(kcv, kkcv);
	});
}

//-----------------------------------------------------------------------------

TEST_F(keyTests, sign_verify) {

	char clearData[] = {
	  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
	};

	EXPECT_NO_THROW({
		Cryptoki::CryptokiHelper* pC = Cryptoki::CryptokiHelper::instance();
		std::string pin("1234");
		unsigned long slot = 1L;
		pC->open(slot, pin);

		Cryptoki::Key pubKey = pC->getKeyByName(OC_PUBLIC_KEY,  GIB_PUBLIC_KEY_NAME);
		Cryptoki::Key priKey = pC->getKeyByName(OC_PRIVATE_KEY, GIB_PRIVATE_KEY_NAME);

		Cryptoki::MechanismInfo mInfo;
		mInfo._type = MT_RSA_PKCS;

		VectorUChar sData = priKey.sign(mInfo, clearData, sizeof(clearData));
		bool verified = pubKey.verify(mInfo, clearData, sizeof(clearData), (char *)sData.data(), sData.size());

		pC->close();

		EXPECT_TRUE(verified);
	});
}

#endif// _KEY_TESTS_H_
