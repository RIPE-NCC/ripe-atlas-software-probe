/* 
RIPE NCC 2011  Atlas. Antony Antony <antony@ripe.net>
Parts came from: 
DNS Query Program on Linux
Author : Prasshhant Pugalia (prasshhant.p@gmail.com)
Dated : 29/4/2009
Also DNSMN GPL version
*/
#include <errno.h>
#include <getopt.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include<stdio.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/nameser.h>
#include <netdb.h>


#include "libbb.h"

#ifndef ns_t_dnskey
#define ns_t_dnskey   48
#endif 

#ifndef T_DNSKEY
#define T_DNSKEY ns_t_dnskey  
#endif 



u_int32_t get32b(char *p);  

void ldns_write_uint16(void *dst, uint16_t data);
uint16_t ldns_read_uint16(const void *src);
static int connect_to_name(char *host, char *port);

//DNS header structure
struct DNS_HEADER
{
	u_int16_t id;        // identification number
	u_int16_t rd :1,     // recursion desired
		  tc :1,     // truncated message
		  aa :1,     // authoritive answer
		  opcode :4, // purpose of message
		  qr :1,     // query/response flag
		  rcode :4,  // response code
		  cd :1,     // checking disabled
		  ad :1,     // authenticated data
		  z :1,      // its z! reserved
		  ra :1;     // recursion available

	u_int16_t q_count; // number of question entries
	u_int16_t ans_count; // number of answer entries 
	u_int16_t auth_count; // number of authority entries
	u_int16_t add_count; // number of resource entries
};       


// EDNS0

struct EDNS0_HEADER 
{
	/** EDNS0 available buffer size, see RFC2671 */
	u_int16_t qtype; 
        uint16_t _edns_udp_size;
	u_int8_t _edns_x; // combined rcode and edns version both zeros.
	u_int8_t _edns_y; // combined rcode and edns version both zeros.
	//u_int16_t _edns_z;
	u_int16_t DO ;
	u_int16_t len ;
	u_int8_t _edns_d;
};

//Constant sized fields of query structure
struct QUESTION
{
	u_int16_t qtype;
	u_int16_t qclass;
};  

//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{   
	u_int16_t type;
	u_int16_t _class;
	u_int32_t ttl;
	u_int16_t data_len;
};
#pragma pack(pop)

//Pointers to resource record contents
struct RES_RECORD
{
	unsigned char *name;
	struct R_DATA *resource;
	unsigned char *rdata;
};

static struct option longopts[]=
{
        { "hostname-bind", no_argument, NULL, 'h' },
        { "id-server", no_argument, NULL, 'i' },
        { "version-bind", no_argument, NULL, 'b' },
        { "version.server", no_argument, NULL, 'r' },
        { "soa", required_argument, NULL, 's' },
	{ "edns0", required_argument, NULL, 'e' },
	{ "dnssec", no_argument, NULL, 'd' },
	{ "dnskey", required_argument, NULL, 'D' },
        { NULL, }
};

struct addrinfo hints, *res, *ressave;
int dns_id;
static int opt_dnssec = 0;	
static int opt_edns0 = 0;
static void got_alarm(int sig);
static void fatal(const char *fmt, ...);
static void fatal_err(const char *fmt, ...);
static void report(const char *fmt, ...);
static void report_err(const char *fmt, ...);
unsigned char* ReadName(unsigned char* reader,unsigned char* buffer,int* count);
void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host) ; 
unsigned int makequery( struct DNS_HEADER *dns, struct EDNS0_HEADER *edns0, unsigned char *buf, unsigned char *lookupname, u_int16_t qtype, u_int16_t qclass);

void printAnswer(unsigned char *result, int wire_size,  unsigned long long tTrip_us);

int tdig_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int tdig_main(int argc, char **argv)
{
	unsigned char buf[2048];
	unsigned char lookupname[32];
	char * server_ip_str;
	int c;
	struct QUESTION *qinfo = NULL;
	optind= 0;
	u_int16_t qtype; 
//	struct addrinfo hints, *res, *ressave;
	int s ,  err_num;;
	u_int16_t qclass;
	struct DNS_HEADER *dns = NULL;
	struct EDNS0_HEADER *edns0 = NULL;
	
	unsigned int qlen; 
	qtype = T_TXT; /* TEXT */
	qclass = C_CHAOS;
	bzero(buf, 2048);	
	int opt_v4_only , opt_v6_only;
	char  *atlas_str = NULL;
	struct sigaction sa;
	unsigned long long  tSend_us, tRecv_us, tTrip_us;
	int opt_tcp = 0;
	int tcp_fd = 0;
	int result = 0;
	FILE *tcp_file;
	uint8_t wire[1300]; 
	char *check;
	ssize_t wire_size = 0;

	srand (time (0));

	tSend_us = monotonic_us();
	opt_v4_only =  opt_v6_only = 0;
	while (c= getopt_long(argc, argv, "46dD:e:tbhirs:A:?", longopts, NULL), c != -1)
	{
		switch(c)
		{
			case '4':
				opt_v4_only = 1;
				break; 
			case '6':
				opt_v6_only = 1;
				break;
			case 'A':
				atlas_str = optarg;
			        break;
			case 'b':
				strcpy(lookupname , "version.bind.");
				break;
			case 'D':
				qtype = T_DNSKEY;
				qclass = C_IN;
				if(opt_edns0 == 0)
					opt_edns0 = 512; 
				opt_dnssec = 1;
				strcpy(lookupname, optarg);
				break;

			case 'd':
				opt_dnssec = 1;
				if(opt_edns0 == 0)
					opt_edns0 = 512;
				break;
			case 'e':
				opt_edns0= strtoul(optarg, &check, 10);
				break;
			case 'h':
				strcpy(lookupname , "hostname.bind.");
				break;
			case 'i':
				strcpy(lookupname , "id.server.");
				break;
			case 'r':
				strcpy(lookupname , "version.server.");
				break;

			case 's':
				qtype = T_SOA;
				qclass = C_IN;
				strcpy(lookupname, optarg);
				break;
			case 't':
				opt_tcp = 1;
			break;

			default:
				fprintf(stderr, "ERROR unknown option %d \n");
				return (1);
		}
	} 
	if (optind != argc-1)
		report_err("exactly one server IP address expected");
	server_ip_str = argv[optind];

	if(atlas_str) {
		time_t mytime;
        	mytime = time(NULL);
		printf ("%s %lu ", atlas_str, mytime);
	}

	bzero(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;    
	if( opt_v4_only == 1 )
	{
		hints.ai_family = AF_INET;    
	}
	else if ( opt_v6_only == 1 )
	{
		hints.ai_family = AF_INET6;    
	}
	else if ( (opt_v4_only == 1 ) && (opt_v6_only == 1 ))
	{
		hints.ai_family = AF_UNSPEC;    
	}
	hints.ai_flags = 0;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = 0;
	char port[] = "domain";

	
	dns = (struct DNS_HEADER *)&buf;
	qlen =  makequery(dns, edns0, buf, lookupname,  qtype, qclass);
	// query info 
	//qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + qlen] ; //fill it 
	ressave = res;
	int sendto_len  ;
	sendto_len = sizeof(struct DNS_HEADER) + qlen + sizeof(struct QUESTION) + sizeof(struct EDNS0_HEADER) ;
	// sendto_len--;
	if(opt_tcp)
	{
		sa.sa_flags= 0;
		sa.sa_handler= got_alarm;
		sigemptyset(&sa.sa_mask);
		sigaction(SIGALRM, &sa, NULL);
		//fprintf(stderr, "setting alarm\n");
		alarm(10);
		signal(SIGPIPE, SIG_IGN);

		tcp_fd= connect_to_name(server_ip_str, port);
		if (tcp_fd == -1)
		{
			report_err("unable to connect to '%s'", server_ip_str);
			goto err;
		}
		
		// Stdio makes life easy 
		tcp_file= fdopen(tcp_fd, "r+");
		if (tcp_file == NULL)
		{
			report("fdopen failed");
			goto err;
		}
		tcp_fd= -1; 

		uint16_t payload_len ;
		payload_len = (uint16_t) sendto_len;
		ldns_write_uint16(wire, sendto_len );
		memcpy(wire + 2, buf, sendto_len);
		int wire_red =0;
		wire_red = fwrite(wire, (sendto_len+2), 1, tcp_file);
		if (  wire_red   > 0)
		{
			bzero(wire, 1300);	
			while ( fread(wire, 2, 1, tcp_file) == NULL)
			{
				if (feof(tcp_file))
				{
					report("got unexpected EOF from server");
					return 0;
				}
				if (errno == EINTR)
				{
					report("timeout");
					//kick_watchdog();
					sleep(10);
				}
				else
				{
					printf (" TCP-READ-ERROR-SIZE\n");
					report_err("error reading from server");
					return 0;
				}
			} 
			wire_size = ldns_read_uint16(wire);
			
			bzero(buf, 2048);	
			while ( fread(buf, wire_size, 1, tcp_file) == NULL)
			{
				if (feof(tcp_file))
				{
					report("got unexpected EOF from server");
					return 0;
				}
				if (errno == EINTR)
				{
					report("timeout");
					//kick_watchdog();
					sleep(10);
				}
				else
				{
					printf (" TCP-READ-ERROR-%d byte\n", wire_size);
					report_err("error reading from server");
					return 0;
				}
			} 
			
		}
	}
	else 
	{
		err_num = getaddrinfo(server_ip_str, port , &hints, &res);
		if(err_num)
		{ 
			printf("%s ERROR port %s %s\n", server_ip_str, port, gai_strerror(err_num));	
			return (0);
		}


		do 
		{
			sa.sa_flags= 0;
			sa.sa_handler= got_alarm;
			sigemptyset(&sa.sa_mask);
			sigaction(SIGALRM, &sa, NULL);
			alarm(1);
			tSend_us = monotonic_us();

			s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
			if(s < 0)
				continue;

			void *ptr;
			char addrstr[100];
			switch (res->ai_family)
			{
				case AF_INET:
					ptr = &((struct sockaddr_in *) res->ai_addr)->sin_addr;		
					break;
				case AF_INET6:
					ptr = &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
					break;
			}
			inet_ntop (res->ai_family, ptr, addrstr, 100);
			printf ("DNS%d T %s %s ", res->ai_family == PF_INET6 ? 6 : 4, server_ip_str,  addrstr );

			tSend_us = monotonic_us();
			if(sendto(s, (char *)buf, sendto_len, 0, res->ai_addr, res->ai_addrlen) == -1) {
				perror("send");
				close(s);
				continue;
			}  
			else 
			{
				if( ( wire_size = read(s, buf, 2048)) == -1) {
					perror("read");
					close(s);
					continue;
				}
				else {
					close(s);
					break;
				}
				close(s);
				break;
			}
		} while ((res = res->ai_next) != NULL);
		freeaddrinfo(ressave);
	}
	tRecv_us = monotonic_us();
	tTrip_us = tRecv_us - tSend_us;

	printAnswer(buf, wire_size, tTrip_us );
	alarm(0);

leave:
	return (result);

err:
        fprintf(stderr, "tdig: leaving with error\n");
        result= 1;
        goto leave;
}

static void got_alarm(int sig)
{
	fprintf(stderr, "got alarm, setting alarm again\n");
	alarm(1);
}

void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host) 
{
	char *s;
	s = dns;
	int lock = 0 , i;
	for(i = 0 ; i < (int)strlen((char*)host) ; i++) 
	{
		//printf ("%c", host[i] );
		if(host[i]=='.') 
		{
			*dns++=i-lock;
			for(;lock<i;lock++) {
				*dns++=host[lock];
			}
			lock++; //or lock=i+1;
		}
	}
	*dns++=0;
}

void printAnswer(unsigned char *result, int wire_size, unsigned long long tTrip_us) 
{
	int i, stop=0;
	unsigned char *qname, *reader;
	struct DNS_HEADER *dnsR = NULL;
	struct RES_RECORD answers[20]; //the replies from the DNS server

	dnsR = (struct DNS_HEADER*) result;

	//point to the query portion
	qname =(unsigned char*)&result[sizeof(struct DNS_HEADER)];

	//move ahead of the dns header and the query field
	reader = &result[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];

	/*
	printf(" : questions  %d  ",ntohs(dnsR->q_count));
	printf(" : answers %d ",ntohs(dnsR->ans_count));
	printf(" : authoritative servers %d ",ntohs(dnsR->auth_count));
	printf(" : additional records %d",ntohs(dnsR->add_count));
	*/

	stop=0;

	printf ("%u.%03u 1 100 ", tTrip_us / 1000 , tTrip_us % 1000);
	if(dnsR->ans_count == 0) 
	{
		printf ("0 %d UNKNOWN UNKNOWN", dnsR->tc);
	}
	else 
	{
		printf (" %d ", ntohs(dnsR->ans_count));	
		printf (" %d ",  dnsR->tc);
	}

	printf (" %u ",  wire_size);
	for(i=0;i<ntohs(dnsR->ans_count);i++)
	{
		answers[i].name=ReadName(reader,result,&stop);
		reader = reader + stop;

		answers[i].resource = (struct R_DATA*)(reader);
		reader = reader + sizeof(struct R_DATA);
	}

	//print answers
	for(i=0;i<ntohs(dnsR->ans_count);i++)
	{
		answers[i].rdata  = NULL;

		if(ntohs(answers[i].resource->type)==T_TXT) //txt
		{
			printf(" TXT ", ntohs(answers[i].resource->data_len));
			printf(" %s ",answers[i].name);
			answers[i].rdata = ReadName(reader,result,&stop);
			reader = reader + stop;

			answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';
			printf(" %s", answers[i].rdata);
		}
		else if (ntohs(answers[i].resource->type)== T_SOA)
		{
			printf("SOA ");
			printf(" %s ",answers[i].name);
			answers[i].rdata = ReadName(reader,result,&stop);
			//printf(" %s", answers[i].rdata);
			reader =  reader + stop;
			answers[i].rdata = ReadName(reader,result,&stop);
			//printf(" %s", answers[i].rdata);
		        reader =  reader + stop;
			u_int32_t serial;
			serial = get32b(reader);
			printf(" %u ", serial);
		        reader =  reader + 4;
		}
		else if (ntohs(answers[i].resource->type)== T_DNSKEY)
		{
			
			printf("DNSKEY ");
		}
		else  
		{

			printf("DISCARDED-%u ", ntohs(answers[i].resource->type));
		}
		fflush(stdout);
		
		// free mem 
		if(answers[i].name != NULL) 
			free (answers[i].name);  

		if(answers[i].rdata != NULL) 
			free (answers[i].rdata); 
	}
	printf("\n");
}
unsigned char* ReadName(unsigned char* reader,unsigned char* buffer,int* count)
{
	unsigned char *name;
	unsigned int p=0,jumped=0,offset;
	int i , j;

	*count = 1;
	name = (unsigned char*)malloc(256);

	name[0]=NULL;

	//read the names in 3www6google3com format
	while(*reader!=0)
	{
		if(*reader>=192)
		{
			offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 <img src="http://www.binarytides.com/blog/wp-includes/images/smilies/icon_wink.gif" alt=";)" class="wp-smiley">
			reader = buffer + offset - 1;
			jumped = 1; //we have jumped to another location so counting wont go up!
		}
		else
			name[p++]=*reader;

		reader=reader+1;

		if(jumped==0)
			*count = *count + 1; //if we havent jumped to another location then we can count up
	}

	name[p]=NULL; //string complete
	if(jumped==1)
		*count = *count + 1; //number of steps we actually moved forward in the packet

	//now convert 3www6google3com0 to www.google.com
	for(i=0;i<(int)strlen((const char*)name);i++) {
		p=name[i];
		for(j=0;j<(int)p;j++) {
			name[i]=name[i+1];
			i=i+1;
		}
		name[i]='.';
	}
	name[i-1]=NULL; //remove the last dot
	return name;
}


unsigned int makequery( struct DNS_HEADER *dns, struct EDNS0_HEADER *edns0, unsigned char *buf, unsigned char *lookupname, u_int16_t qtype, u_int16_t qclass)
{
	unsigned char *qname;
	struct QUESTION *qinfo = NULL; 
	struct EDNS0_HEADER *e;
	unsigned int ret;
	int r;
	r =  rand();
	r %= 65535;
	dns->id = (unsigned short) r;
	dns->qr = 0; //This is a query
	dns->opcode = 0; //This is a standard query
	dns->aa = 0; //Not Authoritative
	dns->tc = 0; //This message is not truncated
	dns->rd = 0; //Recursion  not Desired
	dns->ra = 0; //Recursion not available! hey we dont have it (lol)
	dns->z = 0;
	dns->ad = 0;
	dns->cd = 0;
	dns->rcode = 0;
	dns->q_count = htons(1); //we have only 1 question
	dns->ans_count = 0;
	dns->auth_count = 0;
	dns->add_count = htons(1);

	//point to the query portion
	qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];
	
	ChangetoDnsNameFormat(qname , lookupname);
	qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; //fill it 
	ret = (strlen((const char*)qname) + 1);

	qinfo->qtype = htons(qtype); 
	qinfo->qclass = htons(qclass);

	e=(struct EDNS0_HEADER*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + sizeof(struct QUESTION) + 2 ) ]; //fill it 

	e->qtype = htons(ns_t_opt);
	e->_edns_udp_size = htons(opt_edns0);
	//e->_edns_z = htons(128);
	if(opt_dnssec  == 1) 
	{
		e->DO = 0x80;
	}
	e->len = htons(0);
//	printf (" qtype int %u , qclass %u : %s \n", qtype, qclass, qname);
	return  (ret);
}

static void fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "tdig: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");

	va_end(ap);
	exit(1);
}

static int connect_to_name(char *host, char *port)
{
	int r, s, s_errno;
	//struct addrinfo *res, *aip;
	struct addrinfo  *aip;
	struct addrinfo hints;
	char addrstr[100];
	void *ptr;

	memset(&hints, '\0', sizeof(hints));
	hints.ai_socktype= SOCK_STREAM;
	r= getaddrinfo(host, port, &hints, &res);
	if (r != 0) 
		{
			report_err("unable to resolve '%s': %s", host, gai_strerror(r));		       return (-1);
		}
	ressave = res;
	s_errno= 0;
	s= -1;
	for (aip= res; aip != NULL; aip= aip->ai_next)
	{
		s= socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (s == -1)
		{	
			s_errno= errno;
			continue;
		}

		if (connect(s, res->ai_addr, res->ai_addrlen) == 0)
		{
			switch (res->ai_family)
                        {
                                case AF_INET:
                                        ptr = &((struct sockaddr_in *) res->ai_addr)->sin_addr;
                                        break;
                                case AF_INET6:
                                        ptr = &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
                                        break;
                        }
			inet_ntop (res->ai_family, ptr, addrstr, 100);
			printf ("DNS%d T %s %s ", res->ai_family == PF_INET6 ? 6 : 4, host,  addrstr );

			break;
		}

		s_errno= errno;
		close(s);
		s= -1;
	}

	freeaddrinfo(res);
	if (s == -1)
		errno= s_errno;
	return s;
}


static void fatal_err(const char *fmt, ...)
{
	int s_errno;
	va_list ap;

	s_errno= errno;

	va_start(ap, fmt);

	fprintf(stderr, "tdig: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, ": %s\n", strerror(s_errno));

	va_end(ap);

	exit(1);
}

static void report(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	fprintf(stderr, "tdig: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");

	va_end(ap);
}

static void report_err(const char *fmt, ...)
{
	int s_errno;
	va_list ap;
	va_start(ap, fmt);
        fprintf(stderr, "tdig: ");
        vfprintf(stderr, fmt, ap);
        fprintf(stderr, ": %s\n", strerror(s_errno));

        va_end(ap);
}


/* get 4 bytes from memory
 * eg.  used to extract serial number from soa packet
 */
u_int32_t
get32b (char *p)
{
    u_int32_t var;

    var = (0x000000ff & *(p)) << 24;
    var |= (0x000000ff & *(p+1)) << 16;
    var |= (0x000000ff & *(p+2)) << 8;
    var |= (0x000000ff & *(p+3));

    return (var);
}

/*
 * Copy data allowing for unaligned accesses in network byte order
 * (big endian).
 */
void ldns_write_uint16(void *dst, uint16_t data)
{
#ifdef ALLOW_UNALIGNED_ACCESSES
        * (uint16_t *) dst = htons(data);
#else
        uint8_t *p = (uint8_t *) dst;
        p[0] = (uint8_t) ((data >> 8) & 0xff);
        p[1] = (uint8_t) (data & 0xff);
#endif
}


uint16_t
ldns_read_uint16(const void *src)
{
#ifdef ALLOW_UNALIGNED_ACCESSES
        return ntohs(*(uint16_t *) src);
#else
        uint8_t *p = (uint8_t *) src;
        return ((uint16_t) p[0] << 8) | (uint16_t) p[1];
#endif
}
