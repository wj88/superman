#ifndef __KERNEL__

// Requires libnl
// sudo apt-get install libnl-3-dev libnl-genl-3-dev openssl

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

#include "superman.h"
#include "netlink.h"
#include "security.h"

struct option longopts[] = {
	{ "ca_cert",	required_argument,	NULL,	'c' },
	{ "node_cert",	required_argument,	NULL,	'n' },
	{ "dh_privkey",	required_argument,	NULL,	'p' },
	{ "test_cert",	required_argument,	NULL,	't' },
	{ "debug",	no_argument,		NULL,	'D' },
	{ "daemon",	no_argument,		NULL,	'd' },
	{ "version",	no_argument,		NULL,	'V' },
	{ "help",	no_argument,		NULL,	'h' },
	{ 0,		0,			0,	0   }
};

bool debug = false;
bool is_daemon = false;
bool keep_going = true;
time_t last_discovery_request;

char* ca_cert_filename = "/etc/superman/ca_certificate.pem";
char* node_cert_filename = "/etc/superman/node_certificate.pem";
char* node_dh_privatekey_filename = "/etc/superman/node_dh_privatekey.pem";
char* test_cert_filename = "";

void usage(int status, char* progname)
{
    if (status != 0) {
	fprintf(stderr, "Try `%s --help' for more information.\n", progname);
	exit(status);
    }

    printf
	("\nUsage: %s [-DdV?]\n\n"
	 "-c, --ca_cert file	Location of the CA public certificate\n"
	 "-n, --node_cert file	Location of this nodes public certificate\n"
	 "-p, --dh_privkey file	Location of the DH private key file\n"
	 "-t, --test_cert	Location of a certificate to check against\n"
	 "-D, --Debug		Debug mode\n"
	 "-d, --daemon		Daemon mode, i.e. detach from the console\n"
	 "-V, --version		Show version\n"
	 "-?, --help		Show help\n\n"
	 "Dr Jodie Wetherall, <wj88@gre.ac.uk>\n\n", progname);

    exit(status);
}

// This signal handler ensures clean exits
void signal_handler(int type)
{

    switch (type) {
	case SIGSEGV:
		//alog(LOG_ERR, 0, __FUNCTION__, "SEGMENTATION FAULT!!!! Exiting!!! To get a core dump, compile with DEBUG option.");
	case SIGINT:
	case SIGHUP:
	case SIGTERM:
	default:
		printf("\n");
		keep_going = false;
		break;
    }
}

void SetupSigHandlers()
{
	// This server should shut down on these signals.
	signal(SIGTERM, signal_handler);
	signal(SIGHUP, signal_handler);
	signal(SIGINT, signal_handler);
#ifndef DEBUG
	signal(SIGSEGV, signal_handler);
#endif
}

bool ProcessArgs(int argc, char **argv)
{
	// Remember the name of the executable...
    	char* progname = strrchr(argv[0], '/');

	// Parse command line
	while (1) {

		int opt;
		//opt = getopt_long(argc, argv, "i:fjln:dghoq:r:s:uwxDLRV", longopts, 0);
		opt = getopt_long(argc, argv, "DdVc:n:p:t:", longopts, 0);

		if (opt == EOF)
			break;

		switch (opt) {
			case 0:
				break;
			case 'D':
				debug = true;
			case 'd':
				is_daemon = true;
				break;
			case 'n':
				node_cert_filename = optarg;
				break;
			case 'c':
				ca_cert_filename = optarg;
				break;
			case 'p':
				node_dh_privatekey_filename = optarg;
				break;
			case 't':
				test_cert_filename = optarg;
				break;
			case 'V':
				printf("\nSUPERMAN: v%d.%d © Faculty of Engineering and Science, University of Greenwich.\nAuthor: Dr Jodie Wetherall, <wj88@gre.ac.uk>\n\n", SUPERMAN_VERSION_MAJOR, SUPERMAN_VERSION_MINOR);
				exit(0);
				break;
			case '?':
			case ':':
				//exit(0);
			default:
				usage(0, progname);
		}
	}
}




void Daemonise()
{
        // Our process ID and Session ID
        pid_t pid, sid;
        
        // Fork off the parent process
        pid = fork();
        if (pid < 0) {
		exit(EXIT_FAILURE);
        }

        // If we got a good PID, then we can exit the parent process.
        if (pid > 0) {
		exit(EXIT_SUCCESS);
        }

        // Change the file mode mask
        umask(0);
                
        // Open any logs here
                
        // Create a new SID for the child process
        sid = setsid();
        if (sid < 0) {
		// Log the failure
		exit(EXIT_FAILURE);
        }
        
        // Change the current working directory
        if ((chdir("/")) < 0) {
		// Log the failure
		exit(EXIT_FAILURE);
        }
        
        // Close out the standard file descriptors
        close(STDIN_FILENO);
        //close(STDOUT_FILENO);
        close(STDERR_FILENO);
        
        // Daemon-specific initialization goes here
}

void InvokeSendDiscoveryRequest()
{

	uint32_t sk_len;
	unsigned char* sk;
	if(MallocAndCopyPublickey(&sk_len, &sk))
	{
		printf("Main: Calling SendSupermanDiscoveryRequest...\n");
		SendSupermanDiscoveryRequest(sk_len, sk);

		free(sk);
	}
}

void Run()
{
	// unsigned char* ifname = "eth0";
	// unsigned int ifname_len = 5; // inc. null terminator

	unsigned char* ifname = "lo";
	unsigned int ifname_len = 3; // inc. null terminator

	UpdateSupermanInterfaceTableEntry(ifname_len, ifname, true);

	bool discoverySent = false;

	// Capture the time now.
	time(&last_discovery_request);

        // The Big Loop
        while (keep_going) {
        	bool requires_sleep = true;

		time_t timeNow;
		time(&timeNow);
		if(difftime(timeNow, last_discovery_request) >= 5.0)
		{
			time(&last_discovery_request);

			if(!discoverySent)
			{
				discoverySent = true;
				InvokeSendDiscoveryRequest();
			}
		}

		// Do some task here...
		//printf("Main: Checking for netlink messages...\n");
		requires_sleep = !CheckForMessages();
           
		if(requires_sleep)
		{
			//printf("Main: ... going back to sleep.\n");
			usleep(250000); // wait in microseconds (250000 usecs = 0.25 secs, 1000000 usecs = 1 sec)
		}
        }

	UpdateSupermanInterfaceTableEntry(ifname_len, ifname, false);
}

int main(int argc, char **argv)
{
	ProcessArgs(argc, argv);

	printf("Main: Initialising security...\n");
	if(!InitSecurity(ca_cert_filename, node_cert_filename, node_dh_privatekey_filename))
	{
		exit(EXIT_FAILURE);
	}

	if(!InitNetlink())
	{
		DeInitSecurity();
		exit(EXIT_FAILURE);
	}

	if(strlen(test_cert_filename) > 0)
		TestCertificate(test_cert_filename);
	
	SetupSigHandlers();
	if(is_daemon)
		Daemonise();
	
	Run();

	// Return success
	DeInitNetlink();
	DeInitSecurity();
	exit(EXIT_SUCCESS);
}

#endif
