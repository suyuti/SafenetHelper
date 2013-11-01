//---------------------------------------------------------
// Mehmet Suyuti Dindar
// 30.10.2013
// SmartSoft
//---------------------------------------------------------

#include "SafenetHelperUtil.h"
#include "cryptokiHelper/DataObject.h"
#include "../include/SafenetHelperTypes.h"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <stdlib.h>

using namespace Cryptoki;
using namespace std;

log4cxx::LoggerPtr g_logger(log4cxx::Logger::getLogger("main"));
log4cxx::LoggerPtr g_loggerCryptoki(log4cxx::Logger::getLogger("Cryptoki"));
log4cxx::LoggerPtr g_loggerKey(log4cxx::Logger::getLogger("Key"));
log4cxx::LoggerPtr g_loggerDataObject(log4cxx::Logger::getLogger("DataObject"));


Cryptoki::Key SafenetHelperUtil::getActiveLmk(Cryptoki::CryptokiHelper& session)
{
	int lmkIndex = SafenetHelperUtil::getActiveLmkIndex(session);
	std::stringstream ss;
	ss << "LMK_" << setfill('0') << setw(3) << lmkIndex;
	LOG4CXX_DEBUG(g_logger, "ActiveLMKIndex: " << lmkIndex);
	return session.getKeyByName(OC_SECRET_KEY, ss.str());
}

int SafenetHelperUtil::getActiveLmkIndex(Cryptoki::CryptokiHelper& session)
{
	DataObject d = session.getDataByName(GIB_APPNAME, GIB_ACTIVE_LMK_INDEX);
	VectorUChar val = d.getValue();
	int activeLmkIndex = atol((char*)val.data());
	return activeLmkIndex;
}