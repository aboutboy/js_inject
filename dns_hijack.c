#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/if_vlan.h>
#include <linux/inetdevice.h>

MODULE_LICENSE("GPL");
MODULE_LICENSE("Dual BSD/GPL");

#define LOCAL_DEV_NAME               "br-lan"
#define DEFAULT_NEED_REDIRECT_URL    "www.163.com"
#define URL_MAX_LENGTH               128
#define PACKAGE_MAX_LENGTH           512
#define TTL_TIME                     30

#define PACKED __attribute__(( packed, aligned(1) ) )

#define DP(fmt, args...) do{		/* show debug*/	\
		printk("[%s:%d] "fmt, __func__, __LINE__, ## args);	\
}while(0)

/*
 * dns 报文的结构
 */
typedef struct _dns_struct {
	unsigned short id;     //ID:长度为16位，是一个用户发送查询的时候定义的随机数
	unsigned short flag;   //标志: QR(1),Opcode(4),AA(1),TC(1),RD(1),RA(1),Z(3),RCode(4)
	unsigned short ques;   //QDCount:长度16位，报文请求段中的问题记录数。
	unsigned short answ;   //ANCount:长度16位，报文回答段中的回答记录数。
	unsigned short auth;   //NSCOUNT :长度16位，报文授权段中的授权记录数。
	unsigned short addrrs; //ARCOUNT :长度16位，报文附加段中的附加记录数。
} PACKED dns_header;

typedef struct _dns_query_type {
	unsigned short type;
	unsigned short classtype;
} PACKED dns_query_type;

typedef struct _dns_response_type {
	unsigned short name;      //C0 0C 域名指针
	unsigned short type;      //查询类型
	unsigned short classtype; //分类
	unsigned int ttl;
	unsigned short len;
	char dns_addr[1];
} PACKED dns_response_type;

static int change_url_type(const char * url, char *dst, int dstlen){
	char len = 0;
	int pos = 0;
	char* cp = NULL;
	char* prev = NULL;
	if(!url ||  strlen(url) >= dstlen - 1){
		return -1;
	}

	prev = (char*)url;
	cp = (char*)url;
	memset(dst, 0x00, dstlen);
	while (1) {
		if (*cp == '.') {
			if (len == 0) {
				cp++;
				prev++;
				continue;
			}

			dst[pos] = len;
			pos++;

			if (pos + len >= dstlen -1) {
				return -1;
			}

			memcpy(dst + pos, prev, len);
			pos += len;
			len = 0;
			prev = cp;
			continue;
		} else if (*cp == '\0') {
			if (len == 0) {
				return pos;
			}

			dst[pos] = len;
			pos++;
			
			if (pos + len >= dstlen -1) {
				return -1;
			}

			memcpy(dst + pos, prev, len);
			return pos + len;
		}

		len++;
		cp++;
	}
}

static int build_and_xmit_udp(struct sk_buff* skb, const struct net_device* dev, unsigned char* smac, unsigned char* dmac,
							  unsigned char* pkt, int pkt_len, unsigned long sip, unsigned long dip,
							  unsigned short sport, unsigned short dport) {
	struct sk_buff* pskb    = NULL;
	struct ethhdr* ethdr    = NULL;
	struct iphdr* iph       = NULL;
	struct udphdr* udph     = NULL;
	struct vlan_hdr *vhdr   = NULL;

	int total_len, eth_len, ip_len, header_len;
	int udp_len;
	__wsum udp_hdr_csum;
	
	if (NULL == smac || NULL == dmac) {
		goto out;
	}

	// 设置各个协议数据长度
	udp_len = pkt_len + sizeof(struct udphdr);
	ip_len = udp_len + sizeof(struct iphdr);
	eth_len = ip_len + ETH_HLEN;
	total_len = eth_len + NET_IP_ALIGN;
    total_len += LL_MAX_HEADER;
	header_len = total_len - pkt_len;

	//通过alloc_skb()来为一个新的skb申请内存结构
	pskb = alloc_skb(total_len, GFP_ATOMIC);
	if (NULL == pskb) {
		goto out;
	}

	skb_reserve(pskb, header_len);
	pskb->dev = (struct net_device*)dev;
	skb_copy_to_linear_data(pskb, pkt, pkt_len);
	pskb->len += pkt_len;

	skb_push(pskb, sizeof(*udph));
	skb_reset_transport_header(pskb);
	udph = udp_hdr(pskb);
	//“从上往下”填充skb结构，依次是UDP层--IP层--MAC层
	memset(udph, 0, sizeof(struct udphdr));
	udph->source = sport;
	udph->dest = dport;
	udph->len = htons(sizeof(struct udphdr)+pkt_len);
	udph->check = 0;
	udp_hdr_csum = csum_partial(udph, udp_len, 0);
	udph->check = csum_tcpudp_magic(sip, dip, udp_len, IPPROTO_UDP, udp_hdr_csum);
	pskb->csum = udp_hdr_csum;
	if (udph->check == 0) {
		udph->check = CSUM_MANGLED_0;
	}

	//填充IP层
	skb_push(pskb, sizeof(struct iphdr));
	skb_reset_network_header(pskb);
	iph = ip_hdr(pskb);

	iph->version = 4;
	iph->ihl = sizeof(struct iphdr)>>2;
	iph->tot_len = htons(ip_len);
	iph->tos = 0;
	iph->id  = 0;
	iph->frag_off = htons(IP_DF);
	iph->ttl = 0x40;
	iph->protocol = IPPROTO_UDP;
	iph->check = 0;
	iph->saddr = sip;
	iph->daddr = dip;
	iph->check = ip_fast_csum((unsigned char *)iph,iph->ihl);

	if ( __constant_htons(ETH_P_8021Q) == skb->protocol ) {
		vhdr = (struct vlan_hdr *)skb_push(pskb, VLAN_HLEN );
		vhdr->h_vlan_TCI = vlan_eth_hdr(skb)->h_vlan_TCI;
		vhdr->h_vlan_encapsulated_proto = __constant_htons(ETH_P_IP);
	}

	//填充MAC层
	ethdr = (struct ethhdr *)skb_push(pskb, ETH_HLEN);
	skb_reset_mac_header(pskb);
	memcpy(ethdr->h_dest, dmac, ETH_ALEN);
	memcpy(ethdr->h_source, smac, ETH_ALEN);
	ethdr->h_proto = eth_hdr(skb)->h_proto;
	pskb->protocol = eth_hdr(skb)->h_proto;
	
	//调用dev_queue_xmit()发送报文
	DP("send the package....\n");
	if (0 > dev_queue_xmit(pskb)) {
		goto out;
	}

	return 1;
out:
	if (NULL != pskb) {
		kfree_skb (pskb);
	}

	return 0;
}

unsigned short get_domain_name_ptr(unsigned short offset){
	unsigned short url_offset = 0;
	return (url_offset | 0xC000) | offset;
}

void init_dns_response_header(dns_header * dns_hd, unsigned short id) {
	dns_hd->id      = id;     
	dns_hd->flag    = htons(0x8180);  
	dns_hd->ques    = htons(0x1);   
	dns_hd->answ    = htons(0x1);   
	dns_hd->auth    = htons(0x0);   
	dns_hd->addrrs  = htons(0x0); 
}

void init_dns_response_request(unsigned char* cp, const char* url, int * request_len){
	char request_url[URL_MAX_LENGTH] = {0};
	int request_url_len = 0;
	dns_query_type* dns_qtype = NULL;

	request_url_len = change_url_type(url, request_url, URL_MAX_LENGTH);
	memcpy(cp, request_url, request_url_len + 1);
	*request_len += request_url_len + 1;
	dns_qtype = (dns_query_type*)(cp + request_url_len + 1);
	dns_qtype->type       = htons(0x1);
	dns_qtype->classtype  = htons(0x1);
	*request_len += sizeof(dns_query_type);
}

void init_dns_response_answer(unsigned char* cp, unsigned short offset, const char* url, unsigned int ip, int * answer_len){
	
	dns_response_type* response_answer = NULL;
	int answer_url_len = 0;
	char answer_url[URL_MAX_LENGTH] = {0};
	unsigned short request_offset = 0, domain_offset = 0;
	answer_url_len = change_url_type(url, answer_url, URL_MAX_LENGTH);
	response_answer = (dns_response_type*)cp;
	request_offset = sizeof(dns_header);

    response_answer->name = htons(get_domain_name_ptr(request_offset));
    response_answer->type = htons(0x01);
    response_answer->classtype = htons(0x01);
    response_answer->ttl = htons(TTL_TIME);
    response_answer->len = htons(0x04);
    memcpy(response_answer->dns_addr,&ip,0x04); 
    *answer_len = sizeof(dns_response_type) - 1 + sizeof(unsigned int);
/*
	response_answer->name      = htons(get_domain_name_ptr(request_offset));  //request_url position    
	response_answer->type      = htons(0x05);     
	response_answer->classtype = htons(0x01); 
	response_answer->ttl       = htonl(TTL_TIME);              // 设置为 540
	response_answer->len       = htons(answer_url_len + 1);     // url 长度
	memcpy(response_answer->dns_addr, answer_url, answer_url_len + 1);
	
	*answer_len += sizeof(dns_response_type) + answer_url_len;
	response_answer = (dns_response_type*)(cp + *answer_len);
	domain_offset = offset + sizeof(dns_response_type) -1;
	
	response_answer->name      = htons(get_domain_name_ptr(domain_offset));  //url position    
	response_answer->type      = htons(0x1);     
	response_answer->classtype = htons(0x1); 
	response_answer->ttl       = htonl(TTL_TIME);     // 设置为 540
	response_answer->len       = htons(sizeof(unsigned int));          // address 长度
	memcpy(response_answer->dns_addr, &ip, sizeof(unsigned int));
	
	*answer_len += sizeof(dns_response_type) - 1 + sizeof(unsigned int);
	response_answer = (dns_response_type*)(cp + *answer_len);
	response_answer->name      = htons(get_domain_name_ptr(domain_offset + 5));  //url position    
	response_answer->type      = htons(0x2);     
	response_answer->classtype = htons(0x1); 
	response_answer->ttl       = htonl(TTL_TIME);     // 设置为 540
	response_answer->len       = htons(0x5);          // address 长度
	unsigned short url_offset = htons(get_domain_name_ptr(domain_offset) + 5);
	memcpy(response_answer->dns_addr, "\2ns", 0x3);
	memcpy(response_answer->dns_addr+ 3, &url_offset, 0x2);
	domain_offset = offset + *answer_len + sizeof(dns_response_type) -1;
	*answer_len += sizeof(dns_response_type) - 1 + 5;

	response_answer = (dns_response_type*)(cp + *answer_len);
	response_answer->name      = htons(get_domain_name_ptr(domain_offset));  //url position    
	response_answer->type      = htons(0x1);     
	response_answer->classtype = htons(0x1); 
	response_answer->ttl       = htonl(TTL_TIME);     // 设置为 540
	response_answer->len       = htons(sizeof(unsigned int));          // address 长度
	memcpy(response_answer->dns_addr, &ip, sizeof(unsigned int));
	*answer_len += sizeof(dns_response_type) - 1 + sizeof(unsigned int);	
	*/
}


static void build_dns_response(unsigned char** pkt, int * pkt_len, unsigned int ip, unsigned short id) {
	dns_header* dns_hd = NULL;
	char* cp        = NULL;
	int request_len = 0;
	int answer_len  = 0;
	int offset  = 0;
	*pkt = (void*)kmalloc(PACKAGE_MAX_LENGTH, GFP_ATOMIC);
	cp = *pkt;
	/*dns header*/
	dns_hd = (dns_header*)(cp);
	init_dns_response_header(dns_hd, id);
	cp += sizeof(dns_header);
	*pkt_len += sizeof(dns_header) ;
	offset = sizeof(dns_header);
	/*dns request*/
	init_dns_response_request(cp, DEFAULT_NEED_REDIRECT_URL, &request_len);
	cp += request_len;
	*pkt_len += request_len;
	offset += request_len;
	
	/*dns answer*/
	init_dns_response_answer(cp, offset, DEFAULT_NEED_REDIRECT_URL, ip, &answer_len);
	*pkt_len += answer_len;
	cp += answer_len;
	offset += answer_len;

	/*dns Authoritative nameservers*/
	/*dns Additional records*/
}

int dns_hijacking_response(const struct net_device* dev, struct sk_buff *skb, unsigned int ip) {
	unsigned char* smac, * dmac, * pkt;
	unsigned long sip, dip;
	unsigned short sport, dport, id;
	int pkt_len = 0;
	struct iphdr *iph = ip_hdr(skb);
    struct ethhdr *eth = eth_hdr(skb);
    struct udphdr *udph = NULL;
	int header_len = 0, ret = 0;

	header_len = sizeof(struct iphdr) + sizeof(struct udphdr);
            
    udph = (struct udphdr *)((unsigned char *)iph + sizeof(*iph));

    dport = udph->source;
    sport = udph->dest;
        
	sip = iph->daddr;
    dip = iph->saddr;
	smac = eth->h_dest;
	dmac = eth->h_source;
    DP("\n");
	id = *((unsigned short*)(skb->data + header_len));
	build_dns_response(&pkt, &pkt_len, ip, id);
	// 获取 mac ip port
	// 获取 dns request
	// 合成 dns response
	ret = build_and_xmit_udp(skb, dev, smac, dmac,
						     pkt, pkt_len, sip, 
					         dip, sport, dport);
	if(pkt) {
		kfree(pkt);
	}

	return ret;
}

unsigned int get_local_ip(void) {
	struct ifreq ifr;
	struct in_device *in_dev = NULL;
	struct in_ifaddr **ifap  = NULL;
	struct in_ifaddr *ifa    = NULL;
	struct net_device *dev   = NULL;
	struct net * net = &init_net;

	memset(ifr.ifr_name, 0x00, IFNAMSIZ);
	strncpy(ifr.ifr_name, LOCAL_DEV_NAME, sizeof(LOCAL_DEV_NAME) -1);
	ifr.ifr_name[IFNAMSIZ - 1] = 0;

	dev = __dev_get_by_name(net, ifr.ifr_name);

	if (!dev) {
		return 0;
	}

	in_dev = __in_dev_get_rtnl(dev);
	
	if (!in_dev) {
		return 0;
	}

	for (ifap = &in_dev->ifa_list; (ifa = *ifap) != NULL;
			ifap = &ifa->ifa_next) {
		if (!strcmp(ifr.ifr_name, ifa->ifa_label)) {
			break;
		}
	}

	if (!ifa) {
		return 0;
	}

	return ifa->ifa_address;
}


int is_dns_hijack(const char* url, const char* start, int len) {
	char request_url[URL_MAX_LENGTH] = {0};
	int request_url_len = 0;
	dns_header *dns_header_ptr = NULL;
    char tmpbuf[URL_MAX_LENGTH] = "";
    int i;
	if (len <= sizeof(dns_header)) {
		return 0;		
	}

	dns_header_ptr = (dns_header*)start;

	if (dns_header_ptr->flag != htons(0x0100) &&
		dns_header_ptr->ques    != htons(0x1) &&
		dns_header_ptr->answ    != 0 &&
		dns_header_ptr->auth    != 0 &&
		dns_header_ptr->addrrs  != 0) {
		return 0;
	}

	request_url_len = change_url_type(url, request_url, URL_MAX_LENGTH);
    //DP("request:%s,len=%d.\n",request_url,request_url_len);
    
	if (len < sizeof(dns_header) + request_url_len+ sizeof(dns_query_type)) {
		return 0;
	}
    memcpy(tmpbuf,start + sizeof(dns_header),request_url_len);
    //DP("src request_url:%s,len:%d.\n",tmpbuf,strlen(tmpbuf));
    
	if (0 == memcmp(start + sizeof(dns_header), request_url, request_url_len)){
		dns_query_type* dns_qtype = NULL;
		dns_qtype = (dns_query_type*)(start + request_url_len + sizeof(dns_header) + 1);
		if(dns_qtype->type == htons(0x01)){
			return 1;
		} else {
			return 0;
		}
	}
	return 0;
}


static unsigned int 
dns_hijack_func (unsigned int hooknum, struct sk_buff *skb, 
            const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)) 
{
    struct iphdr *iph = ip_hdr(skb);
    struct ethhdr *eth = eth_hdr(skb);
    struct udphdr *udph = NULL;
    unsigned int sip, dip;
    unsigned int local_ip_address = 0;
    unsigned short source, dest;
    unsigned char *payload = NULL;
    unsigned int  udp_data_len = 0, udp_head_len = 0;
    if (!skb) {
        return NF_ACCEPT;
    }
    if (!eth) {
        return NF_ACCEPT;
    }
    if (!iph) {
        return NF_ACCEPT;
    }
    if (skb->pkt_type == PACKET_BROADCAST) {
        return NF_ACCEPT;
    }
    if ((skb->protocol==htons(ETH_P_8021Q)||skb->protocol==htons(ETH_P_IP))&&skb->len>=sizeof(struct ethhdr)) {
        if (skb->protocol==htons(ETH_P_8021Q)) {
            iph=(struct iphdr *)((u8*)iph+ 4);
        }
        if (iph->version != 4) {
            return NF_ACCEPT;
        }
        if (skb->len < 20) {
            return NF_ACCEPT;
        }
        if ((iph->ihl * sizeof(unsigned int)) > skb->len || skb->len < ntohs(iph->tot_len) || (iph->frag_off & htons(0x1FFF)) != 0) {
            return NF_ACCEPT;
        }
        sip = iph->saddr;
        dip = iph->daddr;
        if (iph->protocol ==  IPPROTO_UDP) {
            udph = (struct udphdr *)((unsigned char *)iph+iph->ihl*sizeof(unsigned int));
            source = ntohs(udph->source);
            dest = ntohs(udph->dest);
            udp_head_len = iph->ihl *sizeof(unsigned int) + sizeof(struct udphdr);
            udp_data_len = ntohs(iph->tot_len) - udp_head_len;
            payload = skb->data + udp_head_len;
            //dns
            if (dest == 53) {
                if (!is_dns_hijack(DEFAULT_NEED_REDIRECT_URL, payload, udp_data_len)){
                    DP("return accept....\n");
                    return NF_ACCEPT;
                }
                local_ip_address = get_local_ip();
                if (!local_ip_address ||!dns_hijacking_response(in, skb, local_ip_address)){
                    DP("return accept....\n");
                    return NF_ACCEPT;
                }
                return NF_DROP;
            }
        }
    }
    return NF_ACCEPT;
}


static struct nf_hook_ops dns_hooks[] = {
    {
        .pf         = NFPROTO_IPV4,
        .priority   = NF_IP_PRI_MANGLE,
        .hooknum    = NF_INET_PRE_ROUTING,
        .hook       = dns_hijack_func,
        .owner      = THIS_MODULE,
    }
};


int dns_hijack_init(void)
{

    return nf_register_hooks(dns_hooks,ARRAY_SIZE(dns_hooks));
}

void dns_hijack_fini(void)
{
    
    nf_unregister_hooks(dns_hooks,ARRAY_SIZE(dns_hooks));
}

module_init(dns_hijack_init);
module_exit(dns_hijack_fini);


