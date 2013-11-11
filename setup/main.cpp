#ifdef WINDOWS
#include <windows.h>
#else
#include <unistd.h>
#endif

#include <stdio.h>
#include <iostream>
#include <cstdlib>

#include "../src/cryptokiHelper/CryptokiHelper.h"
#include "../src/cryptokiHelper/ExceptionCryptoki.h"
#include "../src/SafenetHelperUtil.h"
#include "../src/SafenetHelper.h"

#include "../src/util/util.h"

using namespace std;

Cryptoki::CryptokiHelper *pC = NULL;
SafenetHelper *sH = NULL;

void clearScreen()
{
#ifdef WINDOWS
	std::system("CLS");
#else
	std::system("clear");
#endif
}

void sleep(int seconds)
{
#ifdef WINDOWS
	Sleep(seconds * 1000);
#else
	usleep(seconds * 1000 * 1000);
#endif
}

bool initialize()
{
	try {
	        log4cxx::xml::DOMConfigurator::configure("../test/Log4cxxConfig.xml");

		std::string pin("1234");
		int slot = 1L;

		sH = SafenetHelper::instance();
		sH->login(slot, pin);

		pC = Cryptoki::CryptokiHelper::instance();

	} catch(ExceptionCryptoki &ex) {
		return false;
	}
	
	return true;
}

// 1. Setup
bool doSetup()
{
	try {
	        char selection = 0;

		pC->getDataByName(GIB_APPNAME, GIB_ACTIVE_LMK_INDEX);

		cout << "Setup already done! Are you sure? (y/N)" << endl;
		cin >> selection;
		cout << endl;

		if (selection == 'y') {
			sH->setup();
			return true;
		}

	} catch(ExceptionCryptoki &ex) {
	        sH->setup();
		return true;
	}

	return false;
}

// 2.  Add LMK
bool doAddLMK()
{
	try {
		return sH->addLmk() == 0;
	} catch(ExceptionCryptoki &ex) {
		cout << "An error occured: Did you run 1.Setup first?" << endl;
		return false;
	}
}

// 3.  Get Active LMK Index
int doGetActiveLMKIndex()
{
	try {
		return SafenetHelperUtil::getActiveLmkIndex(*pC);
	} catch(ExceptionCryptoki &ex) {
		cout << "An error occured: Did you run 1.Setup first?" << endl;
		return -1;
	}
}

// 4.  Get KCV of Active LMK
bool doGetKCV()
{
	try {
		Cryptoki::Key lmk = SafenetHelperUtil::getActiveLmk(*pC);
		VectorUChar lmkKcv = lmk.getKcv(MT_DES3_ECB);
		printf("Active LMK KCV: \n");
		for (unsigned int i=0; i < lmkKcv.size(); i++)
			printf("%02x", lmkKcv.data()[i]);
		cout << endl;
		return true;
        } catch(ExceptionCryptoki &ex) {
		cout << "An error occured: Did you run 1.Setup first?" << endl;
	}
	return false;
}

// 5.  Export Public Key
bool doExportPublicKey()
{
	try
	{
		std::string keyName(GIB_PUBLIC_KEY_NAME);
		uchar mod[512];
		uchar exp[512];
		int modLen;
		int expLen;
		pC->getPublicKey(keyName, mod, &modLen, exp, &expLen);
		std::string strExp = util::toHexStr(exp, expLen, ' ');
		std::string strMod = util::toHexStr(mod, modLen, ' ');
		cout << "Key: " << keyName << endl;
		cout << "Exp: " << strExp << endl;
		cout << "Mod: " << strMod << endl;
		cout << endl;
		sleep(5);
		return true;
	}
	catch(ExceptionCryptoki &ex)
	{
		return false;
	}

	return false;
}

// 6.  Backup
bool doBackup()
{
	return false;
}

// 7.  Restore
bool doRestore()
{
	return false;
}

int main(int argc, char **argv)
{
    char selection = 0;
    int activeLMKIndex = 0;

    if (!initialize()) {
	    std::cout << "Cryptoki initialize failed." << std::endl;
	    return 1;
    }
    
    do {
	    clearScreen();
	
	    cout << "  GIB HSM Setup Menu\n";
	    cout << "  ===========================\n";
	    cout << "  1.  Setup\n";
	    cout << "  2.  Add LMK\n";
	    cout << "  3.  Get Active LMK Index\n";
	    cout << "  4.  Get KCV of Active LMK\n";
	    cout << "  5.  Export Public Key\n";
	    cout << "  6.  Backup\n";
	    cout << "  7.  Restore\n";
	    cout << "  8.  Exit\n";
	    cout << "  ===========================\n";
	    cout << "  Enter your selection: ";
	    cin >> selection;
	    cout << endl;

	    switch (selection) {
		case '1':
		    if (doSetup())
			    cout << "Setup success..\n";
		    else
			    cout << "Setup failed..\n";
		    cout << "\n";
		    break;

		case '2':
		    if (doAddLMK())
			    cout << "Add LMK success..\n";
		    else
			    cout << "Add LMK failed..\n";
		    cout << "\n";
		    break;
		case '3':
		    activeLMKIndex = doGetActiveLMKIndex();
		    if (activeLMKIndex >= 0)
			    cout << "Current Active LMK Index: " << activeLMKIndex;
		    cout << "\n";
		    sleep(1);
		    break;

		case '4':
		    doGetKCV();
		    sleep(1);
		    cout << "\n";
		    break;

		case '5':
		    if (doExportPublicKey())
			    cout << "Public Key Export success..\n";
		    else
			    cout << "Public Key Export failed..\n";
		    cout << "\n";
		    break;

		case '6':
		    if (doBackup())
			    cout << "Backup success..\n";
		    else
			    cout << "Backup failed..\n";
		    cout << "\n";
		    break;

		case '7':
		    if (doRestore())
			    cout << "Restore success..\n";
		    else
			    cout << "Restore failed..\n";
		    cout << "\n";
		    break;

	        case '8':
		    cout << "Exit\n";
		    exit(0);
		    break;

		default: 
			cout << selection << " is not a valid.\n";
			cout << endl;
		}

	        sleep(1);

	} while (true);

    return 0;
}
