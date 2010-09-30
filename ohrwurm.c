/*
 * ohrwurm-0.1 - an RTP fuzzer
 * (c) 2006 by Matthias Wenzel
 */
#define _GNU_SOURCE /* to get O_NOFOLLOW */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <pcap.h>

#define VERSION	"0.1"

#define byte	unsigned char
#define u16	unsigned short
#define u32	unsigned int

#define DEBUG

#ifdef DEBUG
# define printd(fmt,args...) printf(fmt, ## args)
#else
# define printd(fmt,args...)
#endif


//#define SNAPLEN 65535
#define SNAPLEN 4096
#define PROMISC 1
#define KERNEL_ROUTER "/proc/sys/net/ipv4/ip_forward"
#define DEFAULT_BER 1.23
#define DEFAULT_INTERFACE "eth0"


typedef struct rtp_fuzz_t{
	/* global mac addresses */
	byte *	mac_local;
	byte *	mac_a;
	byte *	mac_b;

	u32	ip_a;
	u32	ip_a_n; /* network order for faster comparison */
	u32	ip_b;
	u32	ip_b_n; /* network order for faster comparison */

	/* global tx socket */
	int	rawsock;
	struct sockaddr_ll rawsock_sa;
	struct ifreq rawsock_ifr;

	u16	sip_port;
	u16	sip_port_n; /* network order for faster comparison */

	/* once we have identified our RTP stream, the port numbers */
	/* will be set */
	u16	rtp_port_a;
	u16	rtp_port_b;
	u16	rtp_port_a_n; /* network order for faster comparison */
	u16	rtp_port_b_n; /* network order for faster comparison */

	int	suppress_rtcp;
	u16	rtcp_port_a_n; /* network order for faster comparison */
	u16	rtcp_port_b_n; /* network order for faster comparison */

	byte	pbuf[SNAPLEN];
	u32	plen;

	byte	kernel_routing; /* '0' disabled, '1' enabled */

	u32	random_seed;
	double	BER; /* bit error ratio in % */
}rtp_fuzz;

rtp_fuzz ow;


void usage(char * p){
	printf("\nusage: %s -a <IP target a> -b <IP target b> [-s <randomseed>] [-e <bit error ratio in %%>] [-i <interface>] [-A <RTP port a> -B <RTP port b>]\n", p);
	printf("\n");
	printf("\t-a <IPv4 address A in dot-decimal notation> SIP phone A\n");
	printf("\t-b <IPv4 address B in dot-decimal notation> SIP phone B\n");
	printf("\t-s <integer> randomseed (default: read from /dev/urandom)\n");
	printf("\t-e <double> bit error ratio in %% (default: %lf)\n", DEFAULT_BER);
	printf("\t-i <interfacename> network interface (default: eth0)\n");
	printf("\t-t suppress RTCP packets (default: dont suppress)\n");
	printf("\t-A <port number> of RTP port on IP a (requires -B)\n");
	printf("\t-B <port number> of RTP port on IP b (requires -A)\n");
	printf("\t   note: using -A and -B skips SIP sniffing, any RTP can be fuzzed\n");
	printf("\n");
	exit(0);
}

static inline void send_packet(const u_char * p){

	// FIXME: GW operation

	/* determine the target IP address,
	 * assign the corresponding MAC address */
	if(!memcmp(&ow.ip_a,&ow.pbuf[30],4)){
		if(ow.mac_a)
			memcpy(ow.pbuf,ow.mac_a,6);
	}
	if(!memcmp(&ow.ip_b,&ow.pbuf[30],4)){
		if(ow.mac_b)
			memcpy(ow.pbuf,ow.mac_b,6);
	}
	if(ow.mac_local){
		memcpy(&ow.pbuf[6],ow.mac_local,6);
		if(!memcmp(ow.pbuf,ow.mac_local,6))
			return; /* never send to our own mac */
	}

	if ((!ow.mac_a)||(!ow.mac_b)) return;

	int ret;
	ret=sendto(ow.rawsock,ow.pbuf,ow.plen,0,(struct sockaddr *)&ow.rawsock_sa,sizeof(ow.rawsock_sa));
//	printd("<<<< sent %d bytes\n",ret);
}

static inline int parse_sip_packet(const u_char * p){
	if(ow.plen<=42)return 0;
	byte sip[SNAPLEN];

	memcpy(sip,&p[42],ow.plen-42);
	sip[ow.plen-42]=0;
	int port=0;
	int ret;
	byte * pport;
	byte sdp_media_audio[]="\r\nm=audio "; // FIXME mv to ow, cmdline parameter
	pport=strstr(sip,sdp_media_audio);
	if(!pport) return 0;
	pport+=strlen(sdp_media_audio);
	ret=sscanf(pport,"%d%*[ ]RTP%*s",&port);
	if(!ret) return 0;

	printd("RTP port=%d\n",port);

	return port;
}

void set_ip_checksum(byte * p){
	u16 * pchk=(u16 *)(p+24);
	u16 * pip =(u16 *)(p+14);
	u32 chk=0;
	int i;
	*pchk=0;
	for(i=0;i<10;i++){
		chk=chk+ntohs(pip[i]);
	}
	while (chk>>16){
		chk = (chk&0xffff) + (chk>>16);
	}
	chk=~chk;
	*pchk=htons(chk);
}

void set_udp_checksum(byte * p){
	byte * chk=p+40;
	chk[0]=0;
	chk[1]=0;
	// FIXME do UDP checksumming if it was set before
}


static inline int get_rnd_bit(void){
	long int r;
	r=random();
	if(r%10000<ow.BER*100.0)
		return 1;
	return 0;
}

void fuzz(u_char * p){
//	printd("fuzzing %d byte packet\n", ow.plen);

	byte * rtp = &p[42];
	byte * rtp_payload = &p[54];

	/* the rtp payload gets uniform bit errors */
	int i,j;
	for(i=0;i<ow.plen-54;i++){
		for(j=0;j<8;j++){
			if(get_rnd_bit()){
				/* toggle j-th bit in payload */
				if(rtp_payload[i]&(1<<j))
					rtp_payload[i] &= ~(1<<j);
				else
					rtp_payload[i] |= 1<<j;
			}
		}
	}

	/* special handling of the rtp header */
	long int r;

	/* uniform bit errors on the 1st 16 bits */
	for(i=0;i<2;i++){
		for(j=0;j<8;j++){
			if(get_rnd_bit()){
				/* toggle j-th bit in header */
				if(rtp[i]&(1<<j))
					rtp[i] &= ~(1<<j);
				else
					rtp[i] |= 1<<j;
			}
		}
	}

	/* sequence number */
	short s;
	if(get_rnd_bit()){
		r=random()%200;
		s=ntohs(*((short *)&(rtp[2])));
		if(r>99){
			s += (r-100);
		}else{
			s -= r;
		}
		*((short *)&(rtp[2])) = htons(s);
	}
	/* sequence number two MSBs */
	if(get_rnd_bit()){
		if(rtp[2]&0x80)
			rtp[2] &= 0x7f;
		else
			rtp[2] |= 0x80;
	}
	if(get_rnd_bit()){
		if(rtp[2]&0x40)
			rtp[2] &= 0xbf;
		else
			rtp[2] |= 0x40;
	}

	/* timestamp */
	if(get_rnd_bit()){
		r=random()%200;
		i=ntohl(*((int *)&(rtp[4])));
		if(r>99){
			i += (r-100);
		}else{
			i -= r;
		}
		*((int *)&(rtp[4]))=htonl(i);
	}
	/* timestamp two MSBs */
	if(get_rnd_bit()){
		if(rtp[4]&0x80)
			rtp[4] &= 0x7f;
		else
			rtp[4] |= 0x80;
	}
	if(get_rnd_bit()){
		if(rtp[4]&0x40)
			rtp[4] &= 0xbf;
		else
			rtp[4] |= 0x40;
	}
	/* synchronization source */
	if(get_rnd_bit()){
		*((u32 *)&(rtp[8])) = random();
	}


//FIXME: write length field in ip and udp header 
	/* change the length of the rtp header + payload */
//	if(get_rnd_bit()){
		for(i=ow.plen;i<SNAPLEN;i++){
			p[i]=random();
		}
		ow.plen=42+random()%2000;
		/* IP header length */
		*((u16 *)&p[16])=htons(ow.plen-14);
		/* udp header length */
		*((u16 *)&p[38])=htons(ow.plen-34);
		
//	}

	set_ip_checksum(p);
	set_udp_checksum(p);
}

void enable_routing(void){
	int f=open(KERNEL_ROUTER,O_RDWR|O_NOFOLLOW);
	if(!f){
		printf("ERROR: couldn't access %s\n",KERNEL_ROUTER);
		exit(1);
	}
	if(1!=read(f,&ow.kernel_routing,1)){
		printf("ERROR: couldn't read from %s\n",KERNEL_ROUTER);
		exit(1);
	}
	if(ow.kernel_routing=='1'){
		close(f);
		return;
	}
	byte one='1';
	if(1!=write(f,&one,1)){
		printf("ERROR: couldn't write to %s\n",KERNEL_ROUTER);
		exit(1);
	}
	close(f);
	printd("enabled kernel routing.\n");
}
void disable_routing(void){
	int f=open(KERNEL_ROUTER,O_RDWR|O_NOFOLLOW);
	if(!f){
		printf("ERROR: couldn't access %s\n",KERNEL_ROUTER);
		exit(1);
	}
	byte zero='0';
	if(1!=write(f,&zero,1)){
		printf("ERROR: couldn't write to %s\n",KERNEL_ROUTER);
		exit(1);
	}
	close(f);
	printd("disabled kernel routing.\n");
}

void restore_routing(void){
	if(!ow.kernel_routing)
		return;
	int f=open(KERNEL_ROUTER,O_RDWR|O_NOFOLLOW);
	if(!f){
		printf("ERROR: couldn't access %s\n",KERNEL_ROUTER);
		exit(1);
	}
	if(1!=write(f,&ow.kernel_routing,1)){
		printf("ERROR: couldn't write to %s\n",KERNEL_ROUTER);
		exit(1);
	}
	close(f);
	printd("restored kernel routing.\n");
}

void packet_dispatch(u_char * null,
                     const struct pcap_pkthdr * h,
                     const u_char * p){
	/* to return fast, do all the bail out checks first */
	/* fast means no memcpy, no structures, no endianess */
	/* cosa nostra style */

	/* filter non-IP packets */
	if((p[12]!=8)||(p[13]!=0)) return;

	/* filter packets, that are not sent to our local mac address,
	 * (either packets sent by our box in another context, or
	 * packets that we sent by relaying or even fuzzing) */
	if(ow.mac_local)
		if(memcmp(p,ow.mac_local,6))
			return;

	ow.plen=h->caplen; /* fuzz() may change the packet length */
	/* pcap delivers a const u_char * to the packet,
	 * we need to copy it to write to the packet */
	memcpy(ow.pbuf,p,ow.plen);

	/* it's an IP packet, either we need to
	 * 1) parse (SIP/SDP)
	 * 2) fuzz (RTP)
	 * 3) blindly replay (ICMP,TCP,...)
	 */

	if(ow.pbuf[23]!=0x11){
		/* IP, non-UDP, replay */
		send_packet(ow.pbuf);
		return;
	}

	/* it's a UDP packet */

	if(ow.rtp_port_a && ow.rtp_port_b){
		if( // FIXME: compare IP addresses
		   ( (!memcmp(&ow.pbuf[34],&ow.rtp_port_a_n,2))&&
		     (!memcmp(&ow.pbuf[36],&ow.rtp_port_b_n,2))  ) ||
		   ( (!memcmp(&ow.pbuf[34],&ow.rtp_port_b_n,2))&&
		     (!memcmp(&ow.pbuf[36],&ow.rtp_port_a_n,2))  )
		  ){
			/* it's "our" rtp stream, fuzz it */
			fuzz(ow.pbuf);
		}else{
			/* suppress_rtcp */
			if(ow.suppress_rtcp){
				if( // FIXME: compare IP addresses
				   ( (!memcmp(&ow.pbuf[34],&ow.rtcp_port_a_n,2))&&
				     (!memcmp(&ow.pbuf[36],&ow.rtcp_port_b_n,2))  ) ||
				   ( (!memcmp(&ow.pbuf[34],&ow.rtcp_port_b_n,2))&&
				     (!memcmp(&ow.pbuf[36],&ow.rtcp_port_a_n,2))  )
				  ){
					printd("dropping RTCP packet\n");
					return;
				}
			}
		}
	}else{
		if(
		    (!memcmp(&ow.sip_port_n,&ow.pbuf[34],2)) ||
		    (!memcmp(&ow.sip_port_n,&ow.pbuf[36],2))
		  ){
			/* port 5060, SIP */
			printd("got a SIP packet, looking for SDP/RTP port numbers\n");

			int rtp_port;
			rtp_port=parse_sip_packet(ow.pbuf);
			if(rtp_port){
				/* check for IP addresses a and b */
				if(!memcmp(&ow.ip_a,&ow.pbuf[26],4)){
					ow.rtp_port_a    =rtp_port;
					ow.rtp_port_a_n  =htons(rtp_port);
					ow.rtcp_port_a_n =htons(rtp_port+1);
				}
				if(!memcmp(&ow.ip_b,&ow.pbuf[26],4)){
					ow.rtp_port_b    =rtp_port;
					ow.rtp_port_b_n  =htons(rtp_port);
					ow.rtcp_port_b_n =htons(rtp_port+1);
				}
			}

			// FIXME assign mac_local earlier (in main())
			if (!ow.mac_local){
				ow.mac_local=malloc(6);
				if(!ow.mac_local)exit(7);//FIXME
				memcpy(ow.mac_local,ow.pbuf,6);
				printd("got local mac address %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x\n",ow.mac_local[0],ow.mac_local[1],ow.mac_local[2],ow.mac_local[3],ow.mac_local[4],ow.mac_local[5]);
			}
			if(!ow.mac_a){
				if(!memcmp(&ow.ip_a,&ow.pbuf[26],4)){
					ow.mac_a=malloc(6);
					if(!ow.mac_a){
						printf("ERROR: couldn't mallog 6 bytes\n");
						exit(1);
					}
					memcpy(ow.mac_a,&ow.pbuf[6],6);
					printd("got mac address for a %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x\n",ow.mac_a[0],ow.mac_a[1],ow.mac_a[2],ow.mac_a[3],ow.mac_a[4],ow.mac_a[5]);
					if(ow.mac_b)disable_routing();
				}
			}
			if(!ow.mac_b){
				if(!memcmp(&ow.ip_b,&ow.pbuf[26],4)){
					ow.mac_b=malloc(6);
					if(!ow.mac_b){
						printf("ERROR: couldn't mallog 6 bytes\n");
						exit(1);
					}
					memcpy(ow.mac_b,&ow.pbuf[6],6);
					printd("got mac address for b %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x\n",ow.mac_b[0],ow.mac_b[1],ow.mac_b[2],ow.mac_b[3],ow.mac_b[4],ow.mac_b[5]);
					if(ow.mac_a)disable_routing();
				}
			}
		}
	}
	send_packet(ow.pbuf);


	return;
}

void signal_handler(int s){
	restore_routing();
	printf("the random seed was %u\nbye.\n",ow.random_seed);
	exit(0);
}

int main(int ac, char ** av){

	printf("ohrwurm-" VERSION "\n");
	memset(&ow,0,sizeof(ow));

	enable_routing();

	if (ac < 2) usage(av[0]);
	char *opt_a=NULL, *opt_b=NULL, *opt_s=NULL, *opt_e=NULL, *opt_i=NULL;
	char *opt_A=NULL, *opt_B=NULL;

	int ret;
	while ((ret = getopt(ac, av, "a:b:s:e:i:tA:B:")) > 0){
		switch (ret) {
			case 'a':
				opt_a = optarg;
				break;
			case 'b':
				opt_b = optarg;
				break;
			case 's':
				opt_s = optarg;
				break;
			case 'e':
				opt_e = optarg;
				break;
			case 'i':
				opt_i = optarg;
				break;
			case 't':
				ow.suppress_rtcp=1;
				break;
			case 'A':
				opt_A = optarg;
				break;
			case 'B':
				opt_B = optarg;
				break;
			default:
				usage(av[0]);
		}
	}

	if (!opt_a){
		printf("ERROR: no target a specified\n");
		usage(av[0]);
	}
	if (!opt_b){
		printf("ERROR: no target b specified\n");
		usage(av[0]);
	}

	if (inet_pton(AF_INET, opt_a, &ow.ip_a)<=0){
		printf("ERROR: %s is no valid IP address\n", opt_a);
		usage(av[0]);
	}
	if (inet_pton(AF_INET, opt_b, &ow.ip_b)<=0){
		printf("ERROR: %s is no valid IP address\n", opt_b);
		usage(av[0]);
	}

	ow.ip_a_n=htonl(ow.ip_a);
	ow.ip_b_n=htonl(ow.ip_b);
	ow.sip_port  =5060;
	ow.sip_port_n=htons(ow.sip_port);

	/* if -A and -B are provided we skip SIP sniffing for port detection */
	if(
	    ( opt_A && !opt_B) ||
	    (!opt_A &&  opt_B)
	  ){
		printf("ERROR: you need to supply both, -A and -B\n");
		exit(1);
	}
	if(opt_A){
		char * port_end;
		ow.rtp_port_a=strtoul(opt_A,&port_end,10);
		if(*port_end){
			printf("ERROR: couldn't parse port number (%s)\n", opt_A);
			exit(1);
		}
		ow.rtp_port_a_n=htons(ow.rtp_port_a);
	}
	if(opt_B){
		char * port_end;
		ow.rtp_port_b=strtoul(opt_B,&port_end,10);
		if(*port_end){
			printf("ERROR: couldn't parse port number (%s)\n", opt_B);
			exit(1);
		}
		ow.rtp_port_b_n=htons(ow.rtp_port_b);
	}
	
	/* random seed */
	if(opt_s){
		char * seed_end;
		ow.random_seed=strtoul(opt_s,&seed_end,10);
		if(*seed_end){
			printf("ERROR: couldn't parse random seed (%s)\n", opt_s);
			exit(1);
		}
	}else{
		int r=open("/dev/urandom",O_RDONLY|O_NOFOLLOW);
		if (!r){
			printf("ERROR: couldn't open /dev/urandom\n");
			exit(1);
		}
		if(sizeof(unsigned int)!=read(r,&ow.random_seed,sizeof(unsigned int))){
			printf("ERROR: couldn't read from /dev/urandom\n");
			exit(1);
		}
		close(r);
	}
	srandom(ow.random_seed);
	printf("using random seed %u\n",ow.random_seed);

	/* BER - bit error ratio */
	if(opt_e){
		char * ber_end;
		ow.BER=strtod(opt_e,&ber_end);
		if(*ber_end){
			printf("ERROR: couldn't parse bit error ratio (%s)\n", opt_e);
			exit(1);
		}
	}else{
		ow.BER=DEFAULT_BER;
	}

	/* network interface */
	byte * interface;
	if(opt_i)
		interface=opt_i;
	else
		interface=DEFAULT_INTERFACE;
	memset(&ow.rawsock_ifr,0,sizeof(ow.rawsock_ifr));
	memcpy(ow.rawsock_ifr.ifr_name,interface,strlen(interface)+1);

	ow.rawsock=socket(PF_PACKET,SOCK_RAW,0);
	if (ow.rawsock<3){
		printf("ERROR: couldn't create rawsock\n");
		exit(1);
	}
	memset(&ow.rawsock_sa,0,sizeof(ow.rawsock_sa));
	ow.rawsock_sa.sll_family=AF_PACKET;
	if(ioctl(ow.rawsock,SIOCGIFINDEX,&ow.rawsock_ifr)<0){
		printf("ERROR: couldn't get interface index of %s\n", ow.rawsock_ifr.ifr_name);
		exit(1);
	}
	ow.rawsock_sa.sll_ifindex=ow.rawsock_ifr.ifr_ifindex;
	//ow.rawsock_sa.sll_halen=ETH_ALEN;
	/* FIXME fill sll_addr according to packet(7) (???) */

	pcap_t * pcap;
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap=pcap_open_live(interface,SNAPLEN,PROMISC,0,errbuf);
	if(!pcap){
		printf("ERROR: couldn't open %s in promiscuous mode\n", interface);
		printf("ERROR: pcap says: %s\n", errbuf);
		exit(1);
	}

	bpf_u_int32 dev_net;
	bpf_u_int32 dev_mask;
	if (pcap_lookupnet(interface, &dev_net, &dev_mask, errbuf)){
		printf("ERROR: couldn't lookup %s's IP and netmask\n", interface);
		printf("ERROR: pcap says: %s\n", errbuf);
		exit(1);
	}

	char filterbuf[1024];
	/* paranoia, above checks should suffice */
	if ((strlen(opt_a)>15)||(strlen(opt_b)>15)){
		printf("nope\n");
		exit(1);
	}
	sprintf(filterbuf, "(host %s or host %s) and ip", opt_a, opt_b);

	struct bpf_program pfilter;
	if(pcap_compile(pcap,&pfilter,filterbuf,1,dev_mask)){
		printf("ERROR: couldn't compile this filter:\n"
		       "\"%s\"",filterbuf);
		exit(1);
	}
	if(pcap_setfilter(pcap,&pfilter)){
		printf("ERROR: couldn't set this filter:\n"
		       "\"%s\"",filterbuf);
		exit(1);
	}

	signal(SIGINT, signal_handler);

	int p_count;
	while (802){
		p_count=pcap_dispatch(pcap,1,packet_dispatch,NULL);
		if (p_count<0){
			printf("ERROR: during capture\n");
			exit(1);
		}
	}

	pcap_freecode(&pfilter);
	return 0;
}

