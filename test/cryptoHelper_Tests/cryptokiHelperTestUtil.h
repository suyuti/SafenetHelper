#ifndef _CRYPTOKIHELPER_TEST_UTIL_H_
#define _CRYPTOKIHELPER_TEST_UTIL_H_

#include <stdio.h>
#include "cryptoki.h"
#include "../../src/cryptokiHelper/CryptokiHelper.h"


class CryptokiHelperTestUtil
{
public:
	inline static void ClearSlot(unsigned long slotId, std::string& pin) {
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
			C_DestroyObject(pC->getSessionHandle(), h[i]);
		}
		pC->close();
	};
};

#endif //_CRYPTOKIHELPER_TEST_UTIL_H_
