/*
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "def.h"
#include <signal.h>

pcap_t* descr;
pthread_t tid[2];
int sock, connected, bytes_recv = 0;
struct sockaddr_in local_addr, remote_addr;
struct sockaddr_in6 local_addr6, remote_addr6;
socklen_t sin_size;
struct sigaction sigact;
volatile int terminate  = 0;
volatile int pcap_running = 0;

unsigned short server_mode = 0;
char hostname[256] = {0};
char udpremote[256] = {0};
int port = 0;
unsigned short int tunorif = 0; /* [tun==1, if==2] */
char *tap_ip, *tap_mac, *tap_mask = NULL;
char *bpf = NULL;
short int udpmode = 0;
short int onedir = 0; // 1: TUN (receiver), -1: IFACE (sender)
short int ipv6 = 0;
short int tap6 = 0;
short int cksum = 1;
short int compmode = 0;
#ifdef _LINUX
short int iff_flags = IFF_TAP | IFF_NO_PI;
#endif

void usage()
{
	fprintf(stderr, "Option -%c error.\n", optopt);
	fprintf(stderr, "*** tundeep v%s by Adam Palmer <adam@adampalmer.me> ***\n", VER);
	#ifdef _LINUX
	fprintf(stderr, "Usage: tundeep <-i iface|[-t|-T] tapiface> <-h ip> <-p port> [-6] [-C] <-c|-s> ");
	fprintf(stderr, "[-x tapip] [-y tapmask] [-u tapmac] [-b bpf] [-d udp mode] [-e udp remote] [-m] [-K]\n\n");
	#else
	fprintf(stderr, "Usage: tundeep [-a] <-i iface> <-h ip> <-p port> [-6] [-C] <-c|-s> ");
	fprintf(stderr, "[-b bpf] [-d udp mode] [-e udp remote] [-K]\n\n");
	#endif
	fprintf(stderr, "-1 one direction (from iface to socket and from socket to tap)\n");
	fprintf(stderr, "-6 IPv6 mode\n");
	fprintf(stderr, "-C compress mode\n");
	fprintf(stderr, "-K disable checksum\n");
	fprintf(stderr, "-a print all pcap devs\n");
	fprintf(stderr, "-b \"bpf\"\n");
	fprintf(stderr, "-i interface to bind to\n");
	fprintf(stderr, "-h IP to bind to/connect to\n");
	fprintf(stderr, "-p port to bind to/connect to\n");
	fprintf(stderr, "-c client mode\n");
	fprintf(stderr, "-s server mode\n");
	fprintf(stderr, "-d udp mode\n");
	fprintf(stderr, "-e udp peer\n");
	#ifdef _LINUX
	fprintf(stderr, "-t tap interface \n");
	fprintf(stderr, "-T ipv6 tap interface \n");
	fprintf(stderr, "-m tap multi_queue \n");
	fprintf(stderr, "-u tap mac \n");
	fprintf(stderr, "-x if -t mode, set iface ip, if -T mode, set iface ipv6 ip\n");
	fprintf(stderr, "-y if -t mode, set iface mask, if -T mode, set iface ipv6 prefixlen\n");
	#endif
	fprintf(stderr, "--------------------\n\n");
}

void sig_term_handler(int signum)
{
	(void)signum;
	terminate = 1;
}

int main(int argc,char **argv)
{
	int c = 0;
	char iface[128] = {0};
	int actr = 0; char a[34];
	int i = 0, inum = 0;
	pcap_if_t *alldevsp, *device;
	char errbuf[PCAP_ERRBUF_SIZE];
	#ifdef _LINUX
	while ( ((c = getopt(argc, argv, "16CKe:dai:T:t:mu:h:p:csb:x:y:")) != -1) && (actr < 32) )
	#else
	while ( ((c = getopt(argc, argv, "16CKe:dab:i:h:p:cs")) != -1) && (actr < 32) )
	#endif
	{
		a[actr] = c; actr++;
		switch(c)
		{
			case '1':
				onedir = 1;
				break;
			case 'C':
				compmode = 1;
				break;
			case 'K':
				cksum = 0;
				break;
			case '6':
				ipv6 = 1;
				break;
			case 'b':
				bpf = strdup(optarg);
				break;
			case 'a':
				//interface
				fprintf(stderr, "Printing device list:\n");
				fprintf(stderr, "---------------------\n");
				if (pcap_findalldevs(&alldevsp, errbuf))
				{
					debug(1, 1, "Error finding devices (%s)", errbuf);
				}
				for (device = alldevsp; device != NULL; device = device->next)
				{
					fprintf(stderr, "%d. %s", ++i, device->name);
					if (device->description)
					{
						fprintf(stderr, " (%s)\n", device->description);
					} else {
						fprintf(stderr, " (No description available)\n");
					}
				}
				fprintf(stderr, "---------------------\n");
				debug(1, 0, "Device list finished printing");
				printf("Enter the interface number (1-%d): ", i);
				if (scanf("%d", &inum)) { /* ssshh compiler */ }
				if (inum < 1 || inum > i)
				{
					fprintf(stderr, "\nInterface out of range\n");
					pcap_freealldevs(alldevsp);
					exit(0);
				}
				for (device=alldevsp, i=0; i < inum-1; device = device->next, i++);
				strncpy(iface, device->name, 127);
				tunorif = IFACE;
				break;
			case 'i':
				strncpy(iface, optarg, 127);
				tunorif = IFACE;
				break;
			case 'e':
				//host to listen on/connect to
				strncpy(udpremote, optarg, 255);
				break;
			case 'h':
				//host to listen on/connect to
				strncpy(hostname, optarg, 255);
				break;
			case 'p':
				//port
				port = atoi(optarg);
				if (port < 0 || port > 65535)
				{
					debug(1, 1, "Invalid port number");
				}
				break;
			case 'c':
				//client mode
				server_mode = 0;
				break;
			case 's':
				//server mode
				server_mode = 1;
				break;
			case 'd':
				udpmode = 1;
				cksum = 0;
				break;
			#ifdef _LINUX
			case 't':
				//tap
				strncpy(iface, optarg, 127);
				tunorif = TUN;
				break;
			case 'T':
				//tap6
				strncpy(iface, optarg, 127);
				tap6 = 1;
				tunorif = TUN;
				break;
			case 'm':
				//tap multi_queue
				iff_flags |=  IFF_MULTI_QUEUE;
				break;
			case 'u':
				//tap mac
				tap_mac = malloc(18);
				strncpy(tap_mac,optarg,17);
				break;
			case 'x':
				//tap ip
				tap_ip = malloc(128);
				strncpy(tap_ip, optarg, 127);
				break;
			case 'y':
				//tap mask
				tap_mask = malloc(128);
				strncpy(tap_mask, optarg, 127);
				break;
			#endif
			case '?':
				usage();
				debug(2, 1, "Usage error");
				break;
		}
	}
	if (onedir && tunorif == IFACE) onedir = -1;
	a[actr]='\0';
	if ( ((strchr(a, 's') == NULL) && (strchr(a, 'c') == NULL)) && (strchr(a, 'd') == NULL) )
	{
		usage();
		debug(2, 1, "Usage: Either -s or -c must be specified");
	}
	if ( (strchr(a, 's') != NULL) && (strchr(a, 'c') != NULL) )
	{
		usage();
		debug(2, 1, "Usage: Option -s and -c can not be specified together");
	}
	if ( (!udpmode && (strchr(a, 'h') == NULL)) || (strchr(a, 'p') == NULL) )
	{
		usage();
		debug(2, 1, "Usage: Options -h and -p are mandatory");
	}
	if ( (strchr(a, 'd') != NULL) && (strchr(a, 'e') == NULL) && onedir <= 0)
	{
		usage();
		debug(2, 1, "Usage: -e endpoint must be specified in UDP mode");
	}
	if ( (strchr(a, 'd') != NULL) && ( (strchr(a, 'c') != NULL) || (strchr(a, 's') != NULL) ) )
	{
		usage();
		debug(2, 1, "Usage: -c/-s not required in UDP mode");
	}
	if ( (strchr(a, 'a') == NULL) && (strchr(a, 'i') == NULL) && (strchr(a, 't') == NULL) && (strchr(a, 'T') == NULL) )
	{
		usage();
		debug(2, 1, "Usage: Option -a, -i, -t or -T must be specified");
	}
	if ( (strchr(a, 'a') != NULL) && (strchr(a, 'i') != NULL) && (strchr(a, 't') != NULL) && (strchr(a, 'T') != NULL) )
	{
		usage();
		debug(2, 1, "Usage: Option -a, -i and -t can not be specified together");
	}
	if ( (strchr(a, 't') != NULL) && (strchr(a, 'T') != NULL) )
	{
		usage();
		debug(2, 1, "Options -t and -T can not be specified together");
	}
	if ( ( (strchr(a, 'a') != NULL) || (strchr(a, 'i') != NULL) ) && ( (strchr(a, 'u') != NULL) || (strchr(a, 'x') != NULL) || (strchr(a, 'y') != NULL) ))
	{
		usage();
		debug(2, 1, "Usage: Options -u, -x and -y only work with -t or -T, not -i or -a");
	}

	#ifdef _LINUX
	if (tunorif == TUN)
	{
		//set up the tap device
		if ((tap_fd = tun_alloc(iface, iff_flags)) < 0)
		{
			perror("tun/tap failed");
		}
		if (tap6)
		{
			confif6(iface, tap_ip, tap_mask);
		} else {
			confif(iface, tap_ip, tap_mask);
		}
		if (tap_ip != NULL) { free(tap_ip); }
		if (tap_mask != NULL) { free(tap_mask); }
	}
	#endif

	/* First we set up PCAP */
	struct bpf_program fp;/* hold compiled program */
	bpf_u_int32 netp = 0; /* ip */

	/* open device for reading in promiscuous mode */
	if (onedir <= 0) {
		descr = pcap_open_live(iface, MAX_PCAP_SIZ, 1,PCAP_TIMEOUT, errbuf);
		if(descr == NULL) {
			printf("pcap_open_live(): %s\n", errbuf);
			debug(2, 1, "pcap_open_live");
		}
	}

	if (bpf && descr)
	{
		/* Now we'll compile the filter expression*/
		if(pcap_compile(descr, &fp,bpf, 0, netp) == -1) { //no search
			fprintf(stderr, "Error calling pcap_compile\n");
			debug(2, 1, "pcap_compile");
		} else if(pcap_setfilter(descr, &fp) == -1) { /* set the filter */
			fprintf(stderr, "Error setting filter\n");
			debug(2, 1, "pcap filter");
		}
		free(bpf);
	}

	/* Now we set up the socket */
	if (!tun_connect(hostname, port))
	{
		debug (1, 1, "tun_connect failed");
	}

	/* Now launch the threads */

	//read from br0 and write to socket
	if (onedir <= 0 && pthread_create(&(tid[0]), NULL, &thread_func, "") != 0)
	{
		debug (1, 1, "Thread creation failed");
	}

	// read from socket and write to br0:
	if (onedir >= 0 && pthread_create(&(tid[1]), NULL, &thread_func, "") != 0) 
	{
		debug (1, 1, "Thread creation failed");
	}

	memset(&sigact, 0, sizeof(sigact));
	sigact.sa_handler = SIG_IGN;
	sigaction(SIGHUP, &sigact, NULL);
	sigact.sa_handler = sig_term_handler;
	sigaction(SIGTERM, &sigact, NULL);
	sigaction(SIGINT, &sigact, NULL);

	while (!terminate) sleep(10); // terminate on signal

	// Wait for pcap_loop to finish
	for (int i = 2000; i && pcap_running; --i) {
		pcap_breakloop(descr);
		pthread_kill(tid[0], SIGTERM);
		usleep(1000);
	}
	
	if (descr) pcap_close(descr);

	return 0;
}
