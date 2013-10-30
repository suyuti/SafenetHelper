#ifndef _CRYPTOKIHELPER_TEST_UTIL_H_
#define _CRYPTOKIHELPER_TEST_UTIL_H_

#include <stdio.h>
#include "cryptoki.h"
#include "../../src/cryptokiHelper/CryptokiHelper.h"
#include <string.h>


class CryptokiHelperTestUtil
{
public:
	inline static void ClearSlot(unsigned long slotId, std::string pin, bool clearAll = false) {
		Cryptoki::CryptokiHelper* pC = Cryptoki::CryptokiHelper::instance();
		pC->close();
		pC->open(slotId, pin);

		int rv;
	    CK_ULONG numObjectsToFind = 500;
	    CK_ULONG numObjectsFound = 0;

	    rv = C_FindObjectsInit(pC->getSessionHandle(), NULL, 0);
	    if (rv != CKR_OK)
	    	return;

	    CK_OBJECT_HANDLE h[500];
	    rv = C_FindObjects(pC->getSessionHandle(), h, numObjectsToFind,  &numObjectsFound);
	    if (rv != CKR_OK) {
	    	return;
	    }

	    rv = C_FindObjectsFinal(pC->getSessionHandle());
	    if (rv != CKR_OK)
	    	return;

	    if (numObjectsFound == 0) {
			pC->close();
	    	return;
	    }

		for (CK_ULONG i = 0; i < numObjectsFound; ++i) {
			if (clearAll) {
				C_DestroyObject(pC->getSessionHandle(), h[i]);
			}
			else {
				CK_ATTRIBUTE cmkTemplate[] = {{CKA_LABEL, NULL, 0}};
				char label[256];
				rv = C_GetAttributeValue(pC->getSessionHandle(), h[i], cmkTemplate, 1); // Sadece attribute size öğrenmek için
				if (rv != CKR_OK) {
					throw ExceptionCryptoki(rv, __FILE__, __LINE__);
				}
				cmkTemplate[0].pValue = (CK_BYTE_PTR) malloc(cmkTemplate[0].valueLen + 1);
				memset(cmkTemplate[0].pValue, 0x00, (cmkTemplate[0].valueLen + 1));

				rv = C_GetAttributeValue(pC->getSessionHandle(), h[i], cmkTemplate, 1);
				if (rv != CKR_OK) {
					delete(cmkTemplate[0].pValue);
					throw ExceptionCryptoki(rv, __FILE__, __LINE__);
				}

				if ((strncmp((char*)cmkTemplate[0].pValue, "ActiveLmkIndex", strlen("ActiveLmkIndex")) 	== 0) ||
					(strncmp((char*)cmkTemplate[0].pValue, "LMK_", 			strlen("LMK_")) 			== 0) ||
					(strncmp((char*)cmkTemplate[0].pValue, "PbK_GIB", 		strlen("PbK_GIB")) 			== 0) ||
					(strncmp((char*)cmkTemplate[0].pValue, "PrK_GIB", 		strlen("PrK_GIB")) 			== 0)
					) {
					// Bunlari silme
				}
				else {
					C_DestroyObject(pC->getSessionHandle(), h[i]);
				}
				delete(cmkTemplate[0].pValue);
			}
		}
		pC->close();
	};
};

#endif //_CRYPTOKIHELPER_TEST_UTIL_H_
