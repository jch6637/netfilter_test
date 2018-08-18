#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <linux/types.h>
#include <linux/netfilter.h>        /* for NF_ACCEPT */
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#define LEN 1
char *warning_list[LEN] = { "nate.com" };
int check_result, list_index;

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i % 16 == 0)
            printf("\n");
        printf("%02x ", buf[i]);
    }
}

int get_ip_header_length(unsigned char *packet)
{
	struct iphdr *ip = (struct iphdr *)packet;
	
	return ip->ihl * 4;
}

int get_tcp_header_length(unsigned char *packet)
{
	struct tcphdr *tcp = (struct tcphdr *)packet;
	
	return tcp->th_off * 4;
}

void return_url(unsigned char *packet, char *result)
{
	int cnt = 0;
	struct iphdr *ip = (struct iphdr *)packet;
	struct tcphdr *tcp = (struct tcphdr *)(packet + ip->ihl * 4);
	unsigned char *start = packet + ip->ihl * 4 + tcp->th_off * 4;

	for(int i = 0; i < 50; i++)
	{
		if( strncmp(start, "Host", 4) == 0)
		{
			start += 6;
			while( *start != 0x0d)
			{
				result[cnt++] = *start;
				start++;
			}
			return;
		}
		start++;
	}
		
}

int check_http(unsigned char *packet)
{
	struct iphdr *ip = (struct iphdr *)packet;

	if(ip->protocol == IPPROTO_TCP)
	{
		struct tcphdr *tcp = (struct tcphdr *)(packet + ip->ihl * 4);
		if(strncmp(packet + ip->ihl * 4 + tcp->th_off * 4, "GET", 3) == 0)
					return 1;
	}
	return 0;
}

int check_list(unsigned char *url)
{
	int flag = 0, i;
	for(i = 0; i < LEN; i++)
	{
		if( strncmp(url, warning_list[i], strlen(warning_list[i])) == 0)
		{
			list_index = i;
			flag++;
			break;
		}
	}
	return flag;
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    int proto;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi; 
    int ret;
    unsigned char *data;
    
    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) 
        id = ntohl(ph->packet_id);


    hwph = nfq_get_packet_hw(tb);
    mark = nfq_get_nfmark(tb);
    ifi = nfq_get_indev(tb);
    ifi = nfq_get_outdev(tb);
    ifi = nfq_get_physindev(tb);
    ifi = nfq_get_physoutdev(tb);
    ret = nfq_get_payload(tb, &data);

	if(check_http(data))
	{
		char result[200];
		return_url(data, result);
		printf("[*]URL : %s\n",result);
		check_result = check_list(result);
	}  	

    return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);
    if(check_result)
    {
    	printf("[*]Warning in %s\n",warning_list[list_index]);
    	return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    printf("fd : %d\n",fd);
    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            nfq_handle_packet(h, buf, rv);
            continue;
        }

        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */

        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}

