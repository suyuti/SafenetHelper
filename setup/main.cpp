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

int main(int argc, char **argv)
{
    char selection = 0;

    do {
	    clearScreen();
	
	    cout << "  GIB GSM Setup Menu\n";
	    cout << "  ===========================\n";
	    cout << "  1.  Setup\n";
	    cout << "  2.  Add LMK\n";
	    cout << "  3.  Export Ps\n";
	    cout << "  4.  Backup\n";
	    cout << "  5.  Restore\n";
	    cout << "  6.  Exit\n";
	    cout << "  ===========================\n";
	    cout << "  Enter your selection: ";
	    cin >> selection;
	    cout << endl;

	    switch (selection) {
		case '1':
		    cout << "Setup\n";
		    cout << "\n";
		    break;

		case '2':
		    cout << "Add LMK\n";
		    cout << "\n";
		    break;
		case '3':
		    cout << "Export Ps\n" ;
		    cout << "\n";
		    break;

		case '4':
		    cout << "Backup\n";
		    cout << "\n";
		    break;

		case '5':
		    cout << "Restore\n";
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
