#ifndef __KERNEL__

// Requires libnl
// sudo apt-get install libnl-3-dev libnl-genl-3-dev openssl

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
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
	{ "log_file",	required_argument,	NULL,	'l' },
	{ "debug",	no_argument,		NULL,	'D' },
	{ "mode",	required_argument,	NULL,	'm' },
	{ "if", 	required_argument, 	NULL,	'i' },
	{ "if_state",	required_argument,	NULL,	's' },
	{ "disc_freq",	required_argument,	NULL, 	'f' },
	{ "version",	no_argument,		NULL,	'V' },
	{ "help",	no_argument,		NULL,	'h' },
	{ 0,		0,			0,	0   }
};

enum mode_states {
	mode_none,
	mode_daemon,
	mode_if,
	mode_test_cert
};
unsigned int mode = mode_none;

bool debug = false;
bool keep_going = true;
long update_freq = 3000;
time_t last_discovery_request;

char* ca_cert_filename = "/etc/superman/ca_certificate.pem";
char* node_cert_filename = "/etc/superman/node_certificate.pem";
char* node_dh_privatekey_filename = "/etc/superman/node_dh_privatekey.pem";
char* test_cert_filename = "";

char* log_filename = "/var/log/supermand.log";
bool use_logfile = false;
FILE* log_file = NULL;

enum if_states {
	if_state_unknown,
	if_state_up,
	if_state_down
};
char* if_name = "";
unsigned int if_state = if_state_unknown;

void lprintf(const char* fmt, ...)
{
	if(use_logfile && log_file != NULL) {
		va_list ap;
		va_start(ap, fmt);
		vfprintf(log_file, fmt, ap);
		va_end(ap);
	}
	else {
		va_list ap;
		va_start(ap, fmt);
		vprintf(fmt, ap);
		va_end(ap);
	}
}

void lopen()
{
	if(use_logfile) {
		if(((log_file = fopen(log_filename, "aw")) == NULL)) {
			fprintf(stderr, "Unable to open the log file.\n");
			exit(EXIT_FAILURE);
		}
		else
			setvbuf(log_file, NULL, _IONBF, 0);
	}
}

void lclose()
{
	if(log_file != NULL) {
		fclose(log_file);
		log_file = NULL;
	}
}

void usage(int status, char* progname)
{
    if (status != 0) {
	fprintf(stderr, "Try `%s --help' for more information.\n", progname);
	exit(status);
    }

    printf
	("\nUsage: %s [-DdV?]\n\n"
	 "-m, --mode [mode]          Set the mode to either:\n"
	 "           [daemon]        daemon mode, i.e. detach from the console\n"
	 "           [if]            if mode, to enable or disable an interface\n"
	 "           [test_cert]     test_cert mode, to test a certificate\n"
	 "-c, --ca_cert [file]       Location of the CA public certificate\n"
	 "-n, --node_cert [file]     Location of this nodes public certificate\n"
	 "-p, --dh_privkey [file]    Location of the DH private key file\n"
	 "-l, --logfile	[file]       Location of the log file\n"
	 "-f, --disc_freq [freq ms]  The frequency with which to send discovery packets\n"
	 "-t, --test_cert            Location of a certificate to check against\n"
	 "-D, --Debug                Debug mode\n"
	 "-i, --if iface             The interface to set the status of\n"
	 "-s, --if_state [up|down]   The state of the interface\n"
	 "-V, --version              Show version\n"
	 "-?, --help                 Show help\n\n"
	 "Dr Jodie Wetherall, <wj88@gre.ac.uk>\n\n", progname);

    exit(status);
}

void ReloadSignalled()
{

}

// This signal handler ensures clean exits
void signal_handler(int type)
{
	switch (type) {
		case SIGUSR1:
			ReloadSignalled();
			break;
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
	signal(SIGUSR1, signal_handler);
}

bool ProcessArgs(int argc, char **argv)
{
	// Remember the name of the executable...
	char* progname = strrchr(argv[0], '/');

	// Parse command line
	while (1) {

		int opt;
		//opt = getopt_long(argc, argv, "i:fjln:dghoq:r:s:uwxDLRV", longopts, 0);
		opt = getopt_long(argc, argv, "Dm:Vc:n:p:t:l:i:s:f:", longopts, 0);

		if (opt == EOF)
			break;

		switch (opt) {
			case 0:
				break;
			case 'D':
				debug = true;
			case 'm':
				if(strcmp(optarg, "daemon") == 0) {
					mode = mode_daemon;
					use_logfile = true;
				}
				else if(strcmp(optarg, "if") == 0) {
					mode = mode_if;
				}
				else if(strcmp(optarg, "test_cert") == 0) {
					mode = mode_test_cert;
				}
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
			case 'l':
				use_logfile = true;
				log_filename = optarg;
				break;
			case 'i':
				if_name = optarg;
				break;
			case 's':
				if(strcmp(optarg, "up") == 0)
				 	if_state = if_state_up;
				else if(strcmp(optarg, "down") == 0)
					if_state = if_state_down;
				else {
					printf("Invalid value for argument -s %s\n", optarg);
					exit(0);
				}
				break;
			case 'f':
				{
					long val;
					char* end;
					val = strtol(optarg, &end, 10);
					if(end == optarg || *end != '\0')
					{
						printf("Invalid value for argument -f %s\n", optarg);
						exit(0);
					}
					update_freq = val;
				}
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

	if(mode == mode_none) {
		printf("You must specify the mode.\n");
		usage(0, progname);
		exit(0);
	}

	if(mode == mode_daemon) {
		// Do some validation
	}

	if(mode == mode_if) {
		if(strcmp(if_name, "") == 0 || if_state == if_state_unknown) {
			printf("You must specify -i and -s with -m if.\n");
			usage(0, progname);
			exit(0);
		}
	}

	if(mode == mode_test_cert) {
		if(strcmp(test_cert_filename, "")) {
			printf("You must specify -t  with -m test_cert.\n");
			usage(0, progname);
			exit(0);
		}
	}
}

void Daemonise()
{
	lclose();

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
	lopen();

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
	lprintf("SUPERMAN now in daemon mode.\n");
}

void InvokeSendDiscoveryRequest()
{

	uint32_t sk_len;
	unsigned char* sk;
	if(MallocAndCopyPublickey(&sk_len, &sk))
	{
		//lprintf("Main: Calling SendSupermanDiscoveryRequest...\n");
		SendSupermanDiscoveryRequest(sk_len, sk);

		free(sk);
	}
}

void Run()
{
	// unsigned char* ifname = "eth0";
	// unsigned int ifname_len = 5; // inc. null terminator
	bool discoverySent = false;

/*
#ifdef ENCRYPT_LOCAL
        UpdateSupermanInterfaceTableEntry(3, "lo", false);
#endif
	UpdateSupermanInterfaceTableEntry(5, "eth0", true);
*/

	// Capture the time now.
	time(&last_discovery_request);

	// The Big Loop
	while (keep_going) {
		bool requires_sleep = true;

		time_t timeNow;
		time(&timeNow);
		if(difftime(timeNow, last_discovery_request) >= (update_freq * 1000))
		{
			time(&last_discovery_request);

			if(!discoverySent)
			{
				discoverySent = true;
				InvokeSendDiscoveryRequest();
			}
		}

		// Do some task here...
		//lprintf("Main: Checking for netlink messages...\n");
		requires_sleep = !CheckForMessages();

		if(requires_sleep)
		{
			//lprintf("Main: ... going back to sleep.\n");
			usleep(250000); // wait in microseconds (250000 usecs = 0.25 secs, 1000000 usecs = 1 sec)
		}
	}

	UnloadAll();
}

int main(int argc, char **argv)
{
	ProcessArgs(argc, argv);
	lopen();

	if(mode == mode_daemon)
	{
		lprintf("SUPERMAN daemon started.\n");
		Daemonise();
	}

	// Setup the signal handlers for a graceful closure.
	SetupSigHandlers();

	bool requiresNetlink = (mode == mode_daemon || mode == mode_if);
	bool requiresSecurity = (mode == mode_daemon || mode == mode_test_cert);

	//lprintf("Main: Initialising netlink...\n");
	if(requiresNetlink)
	{
		if(!InitNetlink())
		{
			exit(EXIT_FAILURE);
		}
	}

	//lprintf("Main: Initialising security...\n");
	if(requiresSecurity)
	{
		if(!InitSecurity(ca_cert_filename, node_cert_filename, node_dh_privatekey_filename))
		{
			if(requiresNetlink)
				DeInitNetlink();
			exit(EXIT_FAILURE);
		}
	}

	switch(mode)
	{
		case mode_if:
			UpdateSupermanInterfaceTableEntry(strlen(if_name), if_name, (if_state == if_state_up));
			break;
		case mode_test_cert:
			TestCertificate(test_cert_filename);
			break;
		case mode_daemon:
			Run();
			break;
	}

	// Return success
	if(requiresNetlink)
		DeInitNetlink();
	if(requiresSecurity)
		DeInitSecurity();

	if(mode == mode_daemon)
	{
		lprintf("SUPERMAN daemon finished.\n");
	}
	lclose();

	exit(EXIT_SUCCESS);
}

#endif
