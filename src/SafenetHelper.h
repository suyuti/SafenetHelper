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
	int setup();
	int addLmk();
	int GenerateAES256Key(VectorUChar& key,
						  VectorUChar& kcv);





	int getFisCalNo(const VectorUChar inData, VectorUChar& outData);
	int getTraek(const VectorUChar pgTrmk, KeyExchangeResponse& outData);
	int processFirst(const ProcessFirstRequest& inData, ProcessFirstResponse& outData);
	int processNext(const ProcessNextRequest& inData, ProcessNextResponse& outData);

private:
	SafenetHelperImpl* _pImpl;
	static SafenetHelper* _sInstance;
};

#endif //_SAFENET_HELPER_H_
