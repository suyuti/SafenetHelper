//---------------------------------------------------------
// Mehmet Suyuti Dindar
// 11.10.2013
// SmartSoft
//---------------------------------------------------------
#include "gtest/gtest.h"

#include "cryptoHelper_Tests/cryptokiHelper_tests.h"
#include "cryptoHelper_Tests/key_tests.h"
#include "cryptoHelper_Tests/dataObject_tests.h"
#include "safenetHelper_tests.h"
#include "safenetEnvironment.h"
#include <log4cxx/logger.h>
#include <log4cxx/xml/domconfigurator.h>

int main(int argc, char **argv) {
	log4cxx::xml::DOMConfigurator::configure("../test/Log4cxxConfig.xml");

	SafenetEnviroment env;
	::testing::InitGoogleTest(&argc, argv);
	::testing::AddGlobalTestEnvironment(new SafenetEnviroment);
	return RUN_ALL_TESTS();
}
