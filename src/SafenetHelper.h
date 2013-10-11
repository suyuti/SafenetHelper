//---------------------------------------------------------
// Mehmet Suyuti Dindar
// 11.10.2013
// SmartSoft
//---------------------------------------------------------

#ifndef _SAFENET_HELPER_H_
#define _SAFENET_HELPER_H_

#include <string>

#include "../include/SafenetHelperTypes.h"

class SafenetHelperImpl;

class SafenetHelper {
private:
	SafenetHelper();
public:
	static SafenetHelper* instance();
	virtual ~SafenetHelper();
	int login(unsigned long slotId, std::string& pin);
	int GenerateAES256Key(	std::string& keyName,
							int& lmkIndex,
							VectorUChar& key,
							VectorUChar& kcv,
							bool isTokenObject = true);

private:
	SafenetHelperImpl* _pImpl;
	static SafenetHelper* _sInstance;
};

#endif //_SAFENET_HELPER_H_
