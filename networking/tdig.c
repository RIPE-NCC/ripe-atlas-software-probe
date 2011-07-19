/* 
RIPE NCC 2011  Atlas. Antony Antony <antony@ripe.net>
Parts came from: 
DNS Query Program on Linux
Author : Prasshhant Pugalia (prasshhant.p@gmail.com)
Dated : 29/4/2009
Also DNSMN GPL version
*/

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
	unsigned short id; // identification number

	unsigned char rd :1; // recursion desired
	unsigned char tc :1; // truncated message
	unsigned char aa :1; // authoritive answer
	unsigned char opcode :4; // purpose of message
	unsigned char qr :1; // query/response flag

	unsigned char rcode :4; // response code
	unsigned char cd :1; // checking disabled
	unsigned char ad :1; // authenticated data
	unsigned char z :1; // its z! reserved
	unsigned char ra :1; // recursion available

	unsigned short q_count; // number of question entries
	unsigned short ans_count; // number of answer entries 
	unsigned short auth_count; // number of authority entries
	unsigned short add_count; // number of resource entries
};       

//Constant sized fields of query structure
struct QUESTION
{
	unsigned short qtype;
	unsigned short qclass;
};  

//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{   
	unsigned short type;
	unsigned short _class;
	unsigned int ttl;
	unsigned short data_len;
};
#pragma pack(pop)

//Pointers to resource record contents
struct RES_RECORD
{
	unsigned char *name;
	struct R_DATA *resource;
	unsigned char *rdata;
};

char dns_servers[256]; 

unsigned char* ReadName(unsigned char* reader,unsigned char* buffer,int* count);
void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host) ;
int printAnswer(char *result);

int dns_id;
static unsigned char buf[2048], *qname,*reader;

int tdig_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int tdig_main(int argc, char **argv)
{

	char * packet [512];
	//char * packet = (char *) malloc(512);
	int raw_fd;
	int udp_fd;
	struct sockaddr_in dest;
	//char dns_server[] = "k.root-servers.net.";
	char dns_server[] = "193.0.14.129";
	dest.sin_family = AF_INET;
	dest.sin_port = htons(53);
	dest.sin_addr.s_addr = inet_addr(dns_server);

	struct DNS_HEADER *dns = NULL;
	struct QUESTION *qinfo = NULL;

	raw_fd = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); //UDP packet for DNS queries

	//Set the DNS structure to standard queries
	dns = (struct DNS_HEADER *)&buf;

	dns->id = (unsigned short) htons(getpid());
	dns->qr = 0; //This is a query
	dns->opcode = 0; //This is a standard query
	dns->aa = 0; //Not Authoritative
	dns->tc = 0; //This message is not truncated
	dns->rd = 0; //Recursion Desired
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

	ChangetoDnsNameFormat(qname , "id.server.");
	qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; //fill it

	qinfo->qtype = htons(16); //txt 
	qinfo->qclass = htons(3); //chaos
	if(sendto(raw_fd,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION),0,(struct sockaddr*)&dest,sizeof(dest)) == 0)
	{
		printf("Error sending socket");
	}
	printf("Sent");
	int i;
	i = sizeof dest ;
	if(recvfrom (raw_fd,(char*)buf,2048,0,(struct sockaddr*)&dest,&i) == 0)
	{
		printf("Failed. Error Code ");
	}
	printf("Received.");
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
	struct DNS_HEADER *dnsR = NULL;
	struct RES_RECORD answers[20],auth[20],addit[20]; //the replies from the DNS server

	dnsR = (struct DNS_HEADER*) buf;

	//point to the query portion
	qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];

	//move ahead of the dns header and the query field
	reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];

	printf("nThe response contains : ");
	printf("n %d Questions.",ntohs(dnsR->q_count));
	printf("n %d Answers.",ntohs(dnsR->ans_count));
	printf("n %d Authoritative Servers.",ntohs(dnsR->auth_count));
	printf("n %d Additional records.\n",ntohs(dnsR->add_count));

	stop=0;

	for(i=0;i<ntohs(dnsR->ans_count);i++)
	{
		answers[i].name=ReadName(reader,buf,&stop);
		reader = reader + stop;

		answers[i].resource = (struct R_DATA*)(reader);
		reader = reader + sizeof(struct R_DATA);


	}

	//print answers
	for(i=0;i<ntohs(dnsR->ans_count);i++)
	{
		//printf("nAnswer : %d",i+1);
		printf("Name : %s ",answers[i].name);

		if(ntohs(answers[i].resource->type)==16) //txt
		{
			answers[i].rdata = ReadName(reader,buf,&stop);
			reader = reader + stop;

			printf("type : TXT : %d ", ntohs(answers[i].resource->data_len));
			printf(" %s ", answers[i].name);
			answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';
			printf(" %s ", answers[i].name);
			printf(" %s", answers[i].rdata);
		}
		else {
			printf ("Unknown type : %d\n", ntohs(answers[i].resource->type));
		}

		// free memory
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
