#ifdef WINDOWS
#inlcude <windows.h>
#else
#include <unistd.h>
#endif

#include <iostream>
#include <cstdlib>

using namespace std;

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

// 1. Setup
bool doSetup()
{
	return false;
}

// 2.  Add LMK
bool doAddLMK()
{
	return false;
}

// 3.  Get Active LMK Index
bool doGetActiveLMKIndex()
{
	return false;
}

// 4.  Get KCV of Active LMK
bool doGetKCV()
{
	return false;
}

// 5.  Export Public Key
bool doExportPublicKey()
{
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
		    doGetActiveLMKIndex();
		    cout << "\n";
		    break;

		case '4':
		    doGetKCV();
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
