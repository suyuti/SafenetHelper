//---------------------------------------------------------
// Mehmet Suyuti Dindar
// 11.10.2013
// SmartSoft
//---------------------------------------------------------
#include "gtest/gtest.h"

//#include "safenetHelper_tests.h"
#include "cryptoHelper_Tests/cryptokiHelper_tests.h"
#include "cryptoHelper_Tests/key_tests.h"

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
