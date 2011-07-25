/* 
RIPE NCC 2011  Atlas. Antony Antony <antony@ripe.net>
Parts came from: 
DNS Query Program on Linux
Author : Prasshhant Pugalia (prasshhant.p@gmail.com)
Dated : 29/4/2009
Also DNSMN GPL version
*/

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
        { NULL, }
};

int dns_id;

static void fatal(const char *fmt, ...);
unsigned char* ReadName(unsigned char* reader,unsigned char* buffer,int* count);
void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host) ; 
unsigned int makequery( struct DNS_HEADER *dns, unsigned char *buf, unsigned char *lookupname, u_int16_t qtype, u_int16_t qclass);

void printAnswer(unsigned char *result, unsigned long long tTrip_us);


int tdig_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int tdig_main(int argc, char **argv)
//int main(int argc, char **argv)
{
	unsigned char buf[2048];
	unsigned char lookupname[32];
	char * server_ip_str;
	char * soa_str;
	int c;
	struct QUESTION *qinfo = NULL;
	optind= 0;
	u_int16_t qtype; 
	struct addrinfo hints, *res, *ressave;
	int s ,  err_num;;
	u_int16_t qclass;
	struct DNS_HEADER *dns = NULL;
	unsigned int qlen; 
	qtype = T_TXT; /* TEXT */
	qclass = C_CHAOS;
	bzero(buf, 2048);	
	int opt_v4_only , opt_v6_only;
	char  *atlas_str = NULL;
	char hostname[100];
	bzero(hostname, 100);
	gethostname(hostname, 100);

	unsigned long long  tSend_us, tRecv_us, tTrip_us;

	opt_v4_only =  opt_v6_only = 0;
	while (c= getopt_long(argc, argv, "46bhirs:A:?", longopts, NULL), c != -1)
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
				soa_str = optarg;
				fprintf(stderr, "EROOR SOA query not implemented\n");
				return(1);

			default:
				fprintf(stderr, "ERROR unknown option %d \n");
				return (1);
		}
	} 
	if (optind != argc-1)
		fatal("exactly one server IP address expected");
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

	err_num = getaddrinfo(server_ip_str, port , &hints, &res);
	if(err_num)
		{ 
			printf("%s ERROR port %s %s\n", server_ip_str, port, gai_strerror(err_num));	
			return (1);
		}

	dns = (struct DNS_HEADER *)&buf;
	qlen =  makequery(dns, buf, lookupname,  qtype, qclass);
	// query info 
	qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + qlen] ; //fill it 
	ressave = res;
	int sendto_len  ;
	sendto_len = sizeof(struct DNS_HEADER) + qlen + sizeof(struct QUESTION);

	do 
	{
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
		printf ("DNS%d %s %s %s ", res->ai_family == PF_INET6 ? 6 : 4, hostname, server_ip_str,  addrstr );

		tSend_us = monotonic_us();
		if(sendto(s, (char *)buf, sendto_len, 0, res->ai_addr, res->ai_addrlen) == -1) {
			perror("send");
			close(s);
			continue;
		}  
		else 
		{
			if(read(s, buf, 2048) == -1) {
				perror("read");
				close(s);
				continue;
			}
			else {
				close(s);
				break;
			}	
			tRecv_us = monotonic_us();
			tTrip_us = tRecv_us - tSend_us;
			close(s);
			break;
		}
	} while ((res = res->ai_next) != NULL);
	if(!res) {
		freeaddrinfo(ressave);
		printf("DNS0 %s bad-hostname\n", server_ip_str);
		return (1);
	}
	freeaddrinfo(ressave);
	printAnswer(buf, tTrip_us );
	return (0);
}

void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host) 
{
	int lock = 0 , i;
	for(i = 0 ; i < (int)strlen((char*)host) ; i++) 
	{
		if(host[i]=='.') 
		{
			*dns++=i-lock;
			for(;lock<i;lock++) {
				*dns++=host[lock];
			}
			lock++; //or lock=i+1;
		}
	}
	*dns++=NULL;
}

void printAnswer(unsigned char *result, unsigned long long tTrip_us) 
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
		printf ("0 UNKNOWN UNKNOWN");
	}
	else 
		printf (" %d ", ntohs(dnsR->ans_count));	

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
		printf(" %s ",answers[i].name);

		if(ntohs(answers[i].resource->type)==16) //txt
		{
			answers[i].rdata = ReadName(reader,result,&stop);
			reader = reader + stop;

			// printf(": type TXT : len %d ", ntohs(answers[i].resource->data_len));
			answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';
			printf(" %s", answers[i].rdata);
		}
		else 
		{
			printf("DISCARDED NOT TXT=16 type");
		}
		

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


unsigned int makequery( struct DNS_HEADER *dns, unsigned char *buf, unsigned char *lookupname, u_int16_t qtype, u_int16_t qclass)
{
	unsigned char *qname;
	struct QUESTION *qinfo = NULL;
	unsigned int ret;

	dns->id = (unsigned short) htons(getpid());
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
	dns->add_count = 0;

	//point to the query portion
	qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];
	
	ChangetoDnsNameFormat(qname , lookupname);
	qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; //fill it 
	ret = (strlen((const char*)qname) + 1);

	qinfo->qtype = htons(qtype); 
	qinfo->qclass = htons(qclass);

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
