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
  usleep(seconds * 1000 * 1000);   // usleep takes sleep time in us
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

// 3.  Get Active LMK
bool doGetActiveLMK()
{
	return false;
}

// 4.  Get KCV
bool doGetKCV()
{
	return false;
}

// 5.  Export Ps
bool doExportPs()
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
	
	    cout << "  GIB GSM Setup Menu\n";
	    cout << "  ===========================\n";
	    cout << "  1.  Setup\n";
	    cout << "  2.  Add LMK\n";
	    cout << "  3.  Get Active LMK\n";
	    cout << "  4.  Get KCV\n";
	    cout << "  5.  Export Ps\n";
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
		    if (doExportPs())
			    cout << "Export Ps success..\n";
		    else
			    cout << "Export Ps failed..\n";
		    cout << "\n";
		    break;

		case '4':
		    if (doBackup())
			    cout << "Backup success..\n";
		    else
			    cout << "Backup failed..\n";
		    cout << "\n";
		    break;

		case '5':
		    if (doRestore())
			    cout << "Restore success..\n";
		    else
			    cout << "Restore failed..\n";
		    cout << "\n";
		    break;

		case '6':
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
