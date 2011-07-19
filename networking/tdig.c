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

static void fatal(const char *fmt, ...);
unsigned char* ReadName(unsigned char* reader,unsigned char* buffer,int* count);
void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host) ; 
unsigned int makequery( struct DNS_HEADER *dns, char *buf, char *lookupname, u_int16_t qtype, u_int16_t qclass);

int printAnswer(char *result);

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

int tdig_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int tdig_main(int argc, char **argv)
{
 	unsigned char buf[2048], *reader;
	char lookupname[32];
	char * server_ip_str;
	char * soa_str;
	int c;
	int raw_fd;
	struct sockaddr_in dest;
	struct QUESTION *qinfo = NULL;
	optind= 0;
	u_int16_t qtype; 
	u_int16_t qclass;
	
	struct DNS_HEADER *dns = NULL;
	unsigned int qlen; 
	qtype = T_TXT; /* TEXT */
	qclass = C_CHAOS;
	bzero(buf, 2048);	

	while (c= getopt_long(argc, argv, "46bhirs:?", longopts, NULL), c != -1)
	{
		switch(c)
		{
			case '4':
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
				fatal("soa not implemented yet");
				break;

			default:
				fatal("unknown option");
				break;

		}
	} 
	if (optind != argc-1)
                fatal("exactly one server IP address expected");

	server_ip_str = argv[optind];
	dest.sin_family = AF_INET;
	dest.sin_port = htons(53);
	dest.sin_addr.s_addr = inet_addr(server_ip_str );
	raw_fd = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); //UDP packet for DNS queries
	dns = (struct DNS_HEADER *)&buf;
	qlen =  makequery(dns, buf, lookupname,  qtype, qclass);
	// query info 
	qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + qlen] ; //fill it 

	if(sendto(raw_fd,(char*)buf,sizeof(struct DNS_HEADER) + qlen + sizeof(struct QUESTION),0,(struct sockaddr*)&dest,sizeof(dest)) == 0)
	{
		printf("Error sending socket");
	}
	int i;
	i = sizeof dest ;
	if(recvfrom (raw_fd,(char*)buf,2048,0,(struct sockaddr*)&dest,&i) == 0)
	{
		printf("Failed. Error Code ");
	}
	printf("RESPONSE ");
	printAnswer(buf);
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

int printAnswer(char *result) 
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

	printf(" : questions  %d  ",ntohs(dnsR->q_count));
	printf(" : answers %d ",ntohs(dnsR->ans_count));
	printf(" : authoritative servers %d ",ntohs(dnsR->auth_count));
	printf(" : additional records %d",ntohs(dnsR->add_count));

	stop=0;

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
		printf(": name  %s ",answers[i].name);

		if(ntohs(answers[i].resource->type)==16) //txt
		{
			answers[i].rdata = ReadName(reader,result,&stop);
			reader = reader + stop;

			printf(": type TXT : len %d ", ntohs(answers[i].resource->data_len));
			answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';
			printf(": record %s", answers[i].rdata);
		}
		else {
			printf (": unknown type  %d \n", ntohs(answers[i].resource->type));
		}

		// free mem 
		if(answers[i].name != NULL) 
			free (answers[i].name); 

		if(answers[i].rdata != NULL) 
			free (answers[i].rdata); 
		printf("\n");
	}
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


unsigned int makequery( struct DNS_HEADER *dns, char *buf, char *lookupname, u_int16_t qtype, u_int16_t qclass)
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

	fprintf(stderr, "httppost: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");

	va_end(ap);
	exit(1);
}
