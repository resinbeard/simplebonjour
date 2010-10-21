/**
 * Copyright (c) 2010 Murray Foster <mrafoster@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <m_pd.h> // pd interface libraries

#if defined(__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__) && __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ <= 1040
#define TEST_NEW_CLIENTSTUB 1
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>

#ifdef _WIN32
	#include <winsock2.h>
	#include <ws2tcpip.h>
	#include <Iphlpapi.h>
	#include <process.h>
	typedef int        pid_t;
	#define getpid     _getpid
	#define strcasecmp _stricmp
	#define snprintf   _snprintf
	static const char kFilePathSep = '\\';
	#ifndef HeapEnableTerminationOnCorruption
	#     define HeapEnableTerminationOnCorruption (HEAP_INFORMATION_CLASS)1
	#endif
	#if !defined(IFNAMSIZ)
	 #define IFNAMSIZ 16
    #endif
	#define if_nametoindex if_nametoindex_win
	#define if_indextoname if_indextoname_win

	typedef PCHAR (WINAPI * if_indextoname_funcptr_t)(ULONG index, PCHAR name);
	typedef ULONG (WINAPI * if_nametoindex_funcptr_t)(PCSTR name);

	unsigned if_nametoindex_win(const char *ifname)
		{
		HMODULE library;
		unsigned index = 0;

		// Try and load the IP helper library dll
		if ((library = LoadLibrary(TEXT("Iphlpapi")) ) != NULL )
			{
			if_nametoindex_funcptr_t if_nametoindex_funcptr;

			// On Vista and above there is a Posix like implementation of if_nametoindex
			if ((if_nametoindex_funcptr = (if_nametoindex_funcptr_t) GetProcAddress(library, "if_nametoindex")) != NULL )
				{
				index = if_nametoindex_funcptr(ifname);
				}

			FreeLibrary(library);
			}

		return index;
		}

	char * if_indextoname_win( unsigned ifindex, char *ifname)
		{
		HMODULE library;
		char * name = NULL;

		// Try and load the IP helper library dll
		if ((library = LoadLibrary(TEXT("Iphlpapi")) ) != NULL )
			{
			if_indextoname_funcptr_t if_indextoname_funcptr;

			// On Vista and above there is a Posix like implementation of if_indextoname
			if ((if_indextoname_funcptr = (if_indextoname_funcptr_t) GetProcAddress(library, "if_indextoname")) != NULL )
				{
				name = if_indextoname_funcptr(ifindex, ifname);
				}

			FreeLibrary(library);
			}

		return name;
		}

#else
	#include <unistd.h>			// For getopt() and optind
	#include <netdb.h>			// For getaddrinfo()
	#include <sys/time.h>		// For struct timeval
	#include <sys/socket.h>		// For AF_INET
	#include <netinet/in.h>		// For struct sockaddr_in()
	#include <arpa/inet.h>		// For inet_addr()
	#include <net/if.h>			// For if_nametoindex()
	static const char kFilePathSep = '/';
#endif

#if (TEST_NEW_CLIENTSTUB && !defined(__APPLE_API_PRIVATE))
#define __APPLE_API_PRIVATE 1
#endif

#include "dns_sd.h"

// The "+0" is to cope with the case where _DNS_SD_H is defined but empty (e.g. on Mac OS X 10.4 and earlier)
#if _DNS_SD_H+0 >= 116
#define HAS_NAT_PMP_API 1
#define HAS_ADDRINFO_API 1
#else
#define kDNSServiceFlagsReturnIntermediates 0
#endif

//*************************************************************************************************************
// Globals

typedef union { unsigned char b[2]; unsigned short NotAnInteger; } Opaque16;

static int operation;
static uint32_t opinterface = kDNSServiceInterfaceIndexAny;
static DNSServiceRef client    = NULL;
static DNSServiceRef client_pa = NULL;	// DNSServiceRef for RegisterProxyAddressRecord
static DNSServiceRef sc1, sc2, sc3;		// DNSServiceRefs for kDNSServiceFlagsShareConnection testing

static int num_printed;
static char addtest = 0;
static DNSRecordRef record = NULL;
static char myhinfoW[14] = "\002PC\012Windows XP";
static char myhinfoX[ 9] = "\003Mac\004OS X";
static char updatetest[3] = "\002AA";
static char bigNULL[8192];	// 8K is maximum rdata we support

// Note: the select() implementation on Windows (Winsock2) fails with any timeout much larger than this
#define LONG_TIME 2
static unsigned int MAXLENGTHSTRING = 80;

static volatile int timeOut = LONG_TIME;

//i really despise these, seriously.
//please recommend a better solution?
int errorfilter = 0;
float portglobal = 0;
char *namepointer;

static t_class *simplebonjour_class;

typedef struct _simplebonjour
{
  t_object  x_obj;
  DNSServiceErrorType err;
  char servicetype[80];
  t_outlet *a_out, *b_out;
}
t_simplebonjour;

void *simplebonjour_new(void)
{

  t_simplebonjour *x = (t_simplebonjour *)pd_new(simplebonjour_class);
    x->a_out = outlet_new(&x->x_obj, &s_float);
  x->b_out = outlet_new(&x->x_obj, &s_symbol);

  return (void *)x;
}

static void printtimestamp(void)
	{
	struct tm tm;
	int ms;
#ifdef _WIN32
	SYSTEMTIME sysTime;
	time_t uct = time(NULL);
	tm = *localtime(&uct);
	GetLocalTime(&sysTime);
	ms = sysTime.wMilliseconds;
#else
	struct timeval tv;
	gettimeofday(&tv, NULL);
	localtime_r((time_t*)&tv.tv_sec, &tm);
	ms = tv.tv_usec/1000;
#endif
	printf("%2d:%02d:%02d.%03d  ", tm.tm_hour, tm.tm_min, tm.tm_sec, ms);
	}

#define DomainMsg(X) (((X) & kDNSServiceFlagsDefault) ? "(Default)" : \
                      ((X) & kDNSServiceFlagsAdd)     ? "Added"     : "Removed")

//browse function callback
static void DNSSD_API browse_reply(DNSServiceRef sdref, const DNSServiceFlags flags, uint32_t ifIndex, DNSServiceErrorType errorCode,
	const char *replyName, const char *replyType, const char *replyDomain, void *context)
	{
	char *op = (flags & kDNSServiceFlagsAdd) ? "Add" : "Rmv";
	(void)sdref;        // Unused
	(void)context;      // Unused
	if (num_printed++ == 0) printf("Timestamp     A/R Flags if %-25s %-25s %s\n", "Domain", "Service Type", "Instance Name");
	printtimestamp();
	if (errorCode) printf("Error code %d\n", errorCode);
	else printf("%s%6X%3d %-25s %-25s %s\n", op, flags, ifIndex, replyDomain, replyType, replyName);
	if (!(flags & kDNSServiceFlagsMoreComing)) fflush(stdout);
	errorfilter = 1;
	namepointer = replyName;

	}
//resolve function callback
static void DNSSD_API resolve_reply(DNSServiceRef sdref, const DNSServiceFlags flags, uint32_t ifIndex, DNSServiceErrorType errorCode,
	const char *fullname, const char *hosttarget, uint16_t opaqueport, uint16_t txtLen, const unsigned char *txtRecord, void *context)
	{
	union { uint16_t s; u_char b[2]; } port = { opaqueport };
	uint16_t PortAsNumber = ((uint16_t)port.b[0]) << 8 | port.b[1];
	(void)sdref;        // Unused
	(void)ifIndex;      // Unused
	(void)context;      // Unused

	printtimestamp();
	if (errorCode) printf("Error code %d\n", errorCode);
	else
		{
		printf("%s can be reached at %s:%u (interface %d)", fullname, hosttarget, PortAsNumber, ifIndex);
		if (flags) printf(" Flags: %X", flags);
		printf("\n");
		}
    errorfilter = 1;
    portglobal = (float)PortAsNumber;
	if (!(flags & kDNSServiceFlagsMoreComing)) fflush(stdout);
	}

//event handler for browsing events
static void HandleBrowseEvents(t_simplebonjour *x)
	{
	int dns_sd_fd  = client    ? DNSServiceRefSockFD(client   ) : -1;
	int dns_sd_fd2 = client_pa ? DNSServiceRefSockFD(client_pa) : -1;
	int nfds = dns_sd_fd + 1;
	fd_set readfds;
	struct timeval tv;
	int result;
	int stopimm = 0;

	if (dns_sd_fd2 > dns_sd_fd) nfds = dns_sd_fd2 + 1;
    while(stopimm == 0)
    {
		// 1. Set up the fd_set as usual here.
		// This example client has no file descriptors of its own,
		// but a real application would call FD_SET to add them to the set here
		FD_ZERO(&readfds);

		// 2. Add the fd for our client(s) to the fd_set
		if (client   ) FD_SET(dns_sd_fd , &readfds);
		// 3. Set up the timeout.
		tv.tv_sec  = timeOut;
		tv.tv_usec = 0;

		result = select(nfds, &readfds, (fd_set*)NULL, (fd_set*)NULL, &tv);

		if (result > 0)
			{
			DNSServiceErrorType err = kDNSServiceErr_NoError;
			if      (client    && FD_ISSET(dns_sd_fd , &readfds)) err = DNSServiceProcessResult(client   );
			else if (client_pa && FD_ISSET(dns_sd_fd2, &readfds)) err = DNSServiceProcessResult(client_pa);
			if (err) { fprintf(stderr, "DNSServiceProcessResult returned %d\n", err); stopimm = 1; }
			}
		else
			{
                if(errorfilter == 0)
                    post("simplebonjour: no bonjour services of type '%s' found", x->servicetype);
                else
                {
                    errorfilter = 0;
                    outlet_symbol(x->b_out, gensym(namepointer));
                }
                stopimm = 1;
			}
        }
	}

//event handler for resolving events
static void HandleResolveEvents(t_simplebonjour *x)
	{
	int dns_sd_fd  = client    ? DNSServiceRefSockFD(client   ) : -1;
	int dns_sd_fd2 = client_pa ? DNSServiceRefSockFD(client_pa) : -1;
	int nfds = dns_sd_fd + 1;
	fd_set readfds;
	struct timeval tv;
	int result;
	int stopimm = 0;

	if (dns_sd_fd2 > dns_sd_fd) nfds = dns_sd_fd2 + 1;

    while(stopimm == 0)
    {
		// 1. Set up the fd_set as usual here.
		// This example client has no file descriptors of its own,
		// but a real application would call FD_SET to add them to the set here
		FD_ZERO(&readfds);

		// 2. Add the fd for our client(s) to the fd_set
		if (client   ) FD_SET(dns_sd_fd , &readfds);
		// 3. Set up the timeout.
		tv.tv_sec  = timeOut;
		tv.tv_usec = 0;

		result = select(nfds, &readfds, (fd_set*)NULL, (fd_set*)NULL, &tv);

		if (result > 0)
			{
			DNSServiceErrorType err = kDNSServiceErr_NoError;
			if      (client    && FD_ISSET(dns_sd_fd , &readfds)) err = DNSServiceProcessResult(client   );
			else if (client_pa && FD_ISSET(dns_sd_fd2, &readfds)) err = DNSServiceProcessResult(client_pa);
			if (err) { fprintf(stderr, "DNSServiceProcessResult returned %d\n", err); stopimm = 1; }
			}
		else
			{
			    if(errorfilter == 1)
                {
                    errorfilter = 0;
                    post("simplebonjour: service resolved on port %d", (int)portglobal);
                    outlet_float(x->a_out, portglobal);
                }
                else
                    post("simplebonjour: unable to resolve service");
                stopimm = 1;
			}
        }
	}

// on bang, provides some information about simplebonjour
void simplebonjour_bang(t_simplebonjour *x)
{
  post("simplebonjour\npure-data external to interface with bonjour zeroconf-enabled servers\nwritten by murray foster, 2010\nsee README for more information");
}


//browse method
//pd usage: send message |browse _bonjourservice._udp ( to simplebonjour inlet
//**purpose**
//simplebonjour will browse zeroconf network for specified service type via message thru
//left inlet.  all available interfaces/domains will be perused (i think). names of
//available servers will be output through right outlet, individually as symbols
//as they are discovered by simplebonjour.
//NOTE: i recommend using the bbogart popup object to store these names and allow the user easy access
//      to them.  i've used it very successfully.  just a thought! -murray

static void simplebonjour_browse(t_simplebonjour *x, t_symbol *s, int argc, t_atom *argv)
{
    x->servicetype[0] = '\0';
    atom_string(&argv[0], x->servicetype, MAXLENGTHSTRING);

    x->err = DNSServiceBrowse(&client, 0, opinterface, x->servicetype, 0, browse_reply, NULL);

    if (!client || x->err != kDNSServiceErr_NoError) { fprintf(stderr, "DNSService call failed %ld\n", (long int)x->err); post("DNSService call failed."); return (-1); }
    HandleBrowseEvents(x);

    if (client   ) DNSServiceRefDeallocate(client   );
	if (client_pa) DNSServiceRefDeallocate(client_pa);
}

//resolve method
//pd usage: send message |resolve your-servicename ( to simplebonjour inlet
//**purpose**
//simplebonjour will resolve the port number of known service name via message thru
//left inlet. if service is found, portnumber will output as a float thru left outlet.

static void simplebonjour_resolve(t_simplebonjour *x, t_symbol *s, int argc, t_atom *argv)
{
    char resolvetarget[MAXLENGTHSTRING];
    char resolvedomain[MAXLENGTHSTRING];

    char localstorage[MAXLENGTHSTRING];
    localstorage[0] = '\0';

    resolvetarget[0] = '\0';
    atom_string(&argv[0], resolvetarget, MAXLENGTHSTRING);
    resolvedomain[0] = '\0';
    if(argv[1].a_type==A_SYMBOL)
        atom_string(&argv[1], resolvedomain, MAXLENGTHSTRING);
    else
        strcpy(resolvedomain, "local");

    x->err = DNSServiceResolve(&client, 0, opinterface, resolvetarget, x->servicetype, resolvedomain, resolve_reply, NULL);
    if (!client || x->err != kDNSServiceErr_NoError) { fprintf(stderr, "DNSService call failed %ld\n", (long int)x->err); post("DNSService call failed."); return (-1); }

    HandleResolveEvents(x);

    if (client   ) DNSServiceRefDeallocate(client   );
	if (client_pa) DNSServiceRefDeallocate(client_pa);
}


void simplebonjour_setup(void)
{
  simplebonjour_class = class_new(gensym("simplebonjour"),
        (t_newmethod)simplebonjour_new,
        0, sizeof(t_simplebonjour),
        CLASS_DEFAULT, 0);
  class_addbang(simplebonjour_class, simplebonjour_bang);
  class_addmethod(simplebonjour_class, (t_method)simplebonjour_browse, gensym("browse"), A_GIMME, 0);
  class_addmethod(simplebonjour_class, (t_method)simplebonjour_resolve, gensym("resolve"), A_GIMME, 0);
  setenv("AVAHI_COMPAT_NOWARN", "shut up", 1);
}
