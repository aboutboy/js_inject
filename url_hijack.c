/*
内核版本3.18.21，简单的url 劫持，主要学会如何构造tcp数据包。

*/
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

#define HIJACK_URL  "www.qq.com"
#define REDIRECT_URL    "www.163.com"

#define DP(fmt, args...) do{		/* show debug*/	\
		printk("[%s:%d] "fmt, __func__, __LINE__, ## args);	\
}while(0)

typedef enum {
	eRET_MIN = 0,
	eRET_SUCCESS = eRET_MIN,
	eRET_FAILURE,
	eRET_INVALID_ARG,
	eRET_INVALID_STATE,
	eRET_NO_RESOURCE,
	eRET_ALREADY_EXIST,
	eRET_NOT_EXIST,
	eRET_TIMEOUT,
	eRET_MAX,
	/* To use same size of unsigned int */
	eRET_PADDING = ((unsigned int)~0),
} e_ret;

/*find 'substr' from a fixed-length buffer   
 *('full_data' will be treated as binary data buffer)  
 *return NULL if not found  
 */
static char* memstr(char* full_data, int full_data_len, char* substr)  
{  
    if (full_data == NULL || full_data_len <= 0 || substr == NULL) {  
        return NULL;  
    }  
  
    if (*substr == '\0') {  
        return NULL;  
    }  
  
    int sublen = strlen(substr);  
  
    int i;  
    char* cur = full_data;  
    int last_possible = full_data_len - sublen + 1;  
    for (i = 0; i < last_possible; i++) {  
        if (*cur == *substr) {  
            //assert(full_data_len - i >= sublen);  
            if (memcmp(cur, substr, sublen) == 0) {  
                //found  
                return cur;  
            }  
        }  
        cur++;  
    }  
  
    return NULL;  
}  

static int get_tcp_data_len(struct sk_buff *skb)
{
	struct iphdr *iph;
    struct tcphdr *tcph ;
	int ip_header_len = 0;
	int tcp_header_len = 0;
	int tcp_data_len = 0;
	if (!skb)
	{
		return 0;
	}
	iph = ip_hdr(skb);
	ip_header_len = iph->ihl<<2;
    tcph = (struct tcphdr*)(skb->data + ip_header_len);
	tcp_header_len = tcph->doff<<2;
	tcp_data_len = ntohs(iph->tot_len) - ip_header_len - tcp_header_len;
	//tcp_data_len = ntohs(iph->tot_len) - iph->ihl<<2 - tcph->doff<<2;//这个结果为0,why
	//printk("ntohs(iph->tot_len) = %d	ip_header_len=%d	tcp_header_len= %d	tcp_data_len=%d\n",ntohs(iph->tot_len),ip_header_len,tcp_header_len,tcp_data_len);
	return tcp_data_len;
}


/*description : 从字符串中获取关键字段的值
 *input : 
	source: 	源字符串
	source_len:	原数据串长度
	key_name: 	关键值字段名称，用于定位字段在字符串中位置
	key_value:	存放获取到的关键值	OUT
	key_end:	用于标识关键值结束的标记
	value_len:	用于标识key_value缓冲大小
*优化:传入source长度以避免出现未知内存访问
*/
static e_ret get_str_key_value(char *source, int source_len, char *key_name, char *key_value, char *key_end, int value_len)
{
	char *ptr_start = NULL, *ptr_end = NULL;
	int key_name_len = 0, key_end_len = 0, real_value_len = 0, i = 0;
	e_ret ret = eRET_FAILURE;
	if (NULL == source || NULL == key_value || NULL == key_end)
	{
		ret = eRET_INVALID_ARG;
	}
	else
	{
		if (key_name_len <= source)
		{
			key_name_len = strlen(key_name);

			//用memstr替换strstr来处理非字符串,避免出现未知内存访问
			ptr_start = memstr(source, source_len, key_name);
			//printk("source_len = %d, ptr_start_len = %d\n", source_len ,ptr_start_len);

			if (NULL != ptr_start)
			{
				ptr_start += strlen(key_name);

				ptr_end = memstr(ptr_start, source_len-(ptr_start-source), key_end );
				if (NULL != ptr_end)
				{
					real_value_len = ptr_end - ptr_start;
					memcpy(key_value, ptr_start, 
						real_value_len > (value_len-1)?(value_len-1):real_value_len);
					ret = eRET_SUCCESS;
				}
				else
				{
					ret = eRET_FAILURE;
				}
			}
			else
			{
				ret = eRET_FAILURE;
			}
		}
		else
		{
			ret = eRET_FAILURE;
		}
	}
	return ret;
}

int is_hijack_url(struct sk_buff *skb)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    char host[256];
    char *data;
    int tcp_data_len = 0;
    iph = ip_hdr(skb);
    if(iph->protocol != IPPROTO_TCP){
        return -1;
    }
    tcph = tcp_hdr(skb);
    data = (char *)tcph + (tcph->doff<<2);
    memset(host,0x0,sizeof(host));
    tcp_data_len = get_tcp_data_len(skb);
    if(tcp_data_len > 0){
        get_str_key_value(data,tcp_data_len,"\r\nHost: ",host,"\r\n",sizeof(host));
        DP("Host :%s.\n",host);
        if(memcmp(host,HIJACK_URL,strlen(HIJACK_URL)) == 0){
            return 0;
        }
    }
    
    return -1;
}

void build_html_body(char *data)
{
    char htmlbody[1024];
    sprintf(htmlbody, "<html><head>\n"
					 "<title>302 Moved Temporarily</title>\n"
					 "</head><body>\n"
					 "<h1>Moved Temporarily</h1>\n"
					 "<p>The document has moved <a href=\"http://%s/?data=%s\">here</a>.</p>\n"
					 "<h1></body></html></h1>\n\n", REDIRECT_URL,HIJACK_URL);
     sprintf(data, "HTTP/1.1 302 Moved Temporarily\r\n"
			   "Location: http://%s/?data=%s\r\n"
			   "Content-Type: text/html; charset=iso-8859-1\r\n"
			   "Content-length: %d\r\n\r\n"
			   "%s",  REDIRECT_URL,HIJACK_URL,strlen(htmlbody), htmlbody);
}


int return_hijack_page(struct sk_buff *skb,struct net_device *in)
{
    struct sk_buff *nskb = NULL;
    struct ethhdr *ethdr = NULL, *oeth = NULL;
    struct iphdr *iph = NULL,*oiph = NULL;
    struct tcphdr *tcph = NULL,*otcph = NULL;
    struct vlan_hdr *vhdr = NULL;
    int total_len,eth_len,ip_len,header_len,tcp_len;
    char *tcp_data;
    int tcp_data_len;
    char data[1024];

    build_html_body(data);
    tcp_data_len = strlen(data);
    
    tcp_len = tcp_data_len + sizeof(struct tcphdr);
    ip_len = tcp_len + sizeof(struct iphdr);
    eth_len = ip_len + ETH_HLEN;
    total_len = eth_len + NET_IP_ALIGN;
    header_len = total_len - tcp_data_len;

    nskb = alloc_skb(total_len,GFP_ATOMIC);
    if(NULL == nskb){
        goto out;
    }
    oeth = eth_hdr(skb);
    oiph = ip_hdr(skb);
    otcph = tcp_hdr(skb); 

    nskb->dev = (struct net_device*)in;
    // http-->tcp-->ip-->mac
    //http
    skb_reserve(nskb,header_len);
    skb_copy_to_linear_data(nskb,data,tcp_data_len);
    nskb->len += tcp_data_len; 
    
    //tcp
    skb_push(nskb,sizeof(struct tcphdr));
    skb_reset_transport_header(nskb);
    tcph = tcp_hdr(nskb);
    
    memset(tcph,0x0,sizeof(struct tcphdr));
    tcph->source = otcph->dest;
    tcph->dest = otcph->source;
    tcph->doff = sizeof(struct tcphdr)/4;
    tcph->seq = otcph->ack_seq;
    tcph->ack_seq = htonl(ntohl(otcph->seq)+skb->len - oiph->ihl*4 - otcph->doff*4);
    tcph->fin = 1;
    tcph->ack = 1;
    tcph->psh = 1;
    //tcph->window = 65535;
    tcph->check = 0;
    tcph->check = tcp_v4_check(tcp_data_len + sizeof(struct tcphdr),
                    oiph->daddr,oiph->saddr,
                    csum_partial((char *)tcph,tcp_data_len + sizeof(struct tcphdr),0));

    //ip
    skb_push(nskb,sizeof(struct iphdr));
    skb_reset_network_header(nskb);
    iph = ip_hdr(nskb);
    iph->version = 4;
    iph->ihl = sizeof(struct iphdr)>>2;
    iph->tot_len = htons(ip_len);
    iph->tos = 0;
    iph->id = 0;
    iph->frag_off = htons(IP_DF);
    iph->ttl = 0x40;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = oiph->daddr;
    iph->daddr = oiph->saddr;
    iph->check = 0;
    iph->check = ip_fast_csum((unsigned char *)iph,iph->ihl);
    /*
    if ( __constant_htons(ETH_P_8021Q) == skb->protocol ) {
        DP("ETH_P_8021Q....\n");
		vhdr = (struct vlan_hdr *)skb_push(nskb, VLAN_HLEN );
		vhdr->h_vlan_TCI = vlan_eth_hdr(skb)->h_vlan_TCI;
		vhdr->h_vlan_encapsulated_proto = __constant_htons(ETH_P_IP);
	}
	*/
    //mac
    ethdr = (struct ethhdr *)skb_push(nskb,ETH_HLEN);
    skb_reset_mac_header(nskb);
    memcpy(ethdr->h_dest,oeth->h_source,ETH_ALEN);
    memcpy(ethdr->h_source,oeth->h_dest,ETH_ALEN);
    ethdr->h_proto = oeth->h_proto;
    nskb->protocol = oeth->h_proto;
    if(dev_queue_xmit(nskb) < 0){
        goto out;
    }
    DP("send the package success....\n");
    return 0;
out:
    if(nskb){
        kfree_skb(nskb);
    }    
    return -1;
    
}


static unsigned int 
url_hijack_func (unsigned int hooknum, struct sk_buff *skb, 
            const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)) 
{
    if(memcmp(in->name,"br-lan",strlen("br-lan")) == 0){//up
        if(is_hijack_url(skb) == 0){
            return_hijack_page(skb,in);
            return NF_DROP;
        }
    }
    return NF_ACCEPT;
}


static struct nf_hook_ops url_hooks[] = {
    {
        .pf         = NFPROTO_IPV4,
        .priority   = NF_IP_PRI_MANGLE,
        .hooknum    = NF_INET_PRE_ROUTING,
        .hook       = url_hijack_func,
        .owner      = THIS_MODULE,
    }
};


int url_hijack_init(void)
{

    return nf_register_hooks(url_hooks,ARRAY_SIZE(url_hooks));
}

void url_hijack_fini(void)
{
    
    nf_unregister_hooks(url_hooks,ARRAY_SIZE(url_hooks));
}

module_init(url_hijack_init);
module_exit(url_hijack_fini);


