#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>

#include <linux/inet.h>
char buffer[20];

char* proc_all = "/proc/proc_all";
char* proc_in = "/proc/proc_in";
char* proc_out = "/proc/proc_out";
char* proc_mo = "/proc/proc_mo";


//net filter hook options
//we will call the hook_func when the condition is met
static struct nf_hook_ops nfhoIn;
static struct nf_hook_ops nfhoOut;
struct sk_buff *sock_buff;
struct udphdr *udp_header;          //udp header struct (not used)
struct iphdr *ip_header;            //ip header struct

//compare two char array
bool compare(char* s1, char* s2){
    size_t i;
    for(i = 0; s1[i] && s2[i]; i++){
        if(s1[i] != s2[i]){
            return false;
        }
    }
    return true;
}

//read from a specific file path indicated by parameter
//the read result is stored into a char array buffer.
int read(char* path){
    size_t bytes_read;
    FILE *fp;
    fp = fopen(path, "r");
    bytes_read = fread(buffer,1,sizeof(buffer),fp);
    fclose(fp);
    if (bytes_read == 0 || bytes_read == sizeof(buffer)){
        return -1;
    }
    buffer[bytes_read] == '\0';
    return 0;
}

//function to be called by hook
//This will enable the user to
// 1.block in/outcoming traffic by checking info from proc_all
// 2.filter the specific address' incoming traffic from proc_in
// 3.filter the specific address' outcoming traffic from proc_out
// 4. monitor the num packages by proc_mo.
unsigned int hook_func(unsigned int hooknum,
                       struct sk_buff **skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *))
{
    int r;
    //test whether the user wants to monitor the num of packages received.
    r = read(proc_mo);
    if(r == 0){

    }
    //test whether the user has decided to block all
    r = read(proc_all);
    if(r == 0){
        printk(KERN_INFO "All packages are blocked.\n");
        return NF_DROP;
    }
    //test whether the user has decided to filter incoming
    //traffics
    r = read(proc_in);
    if(r == 0){
        sock_buff = skb;
        ip_header = (struct iphdr *)skb_network_header(sock_buff);
        char source[16];
        snprintf(source, 16, "%pI4", &ip_header->saddr);
        if(string_Com(buff,source)){
            printf(KERN_INFO "package dropped\n");
            return NF_DROP;
        }
    }
    //test whether the user has decided to filter outgoing
    //traffics
    r = read(proc_out);
    if(r == 0){
        sock_buff = skb;
        ip_header = (struct iphdr *)skb_network_header(sock_buff);
        char source[16];
        snprintf(source, 16, "%pI4", &ip_header->saddr);
        if(string_Com(buff,source)){
            printf(KERN_INFO "package dropped\n");
            return NF_DROP;
        }
    }
    return NF_ACCEPT;
}



//This is called when the module is loded with insmod command
//will register the hook needed to complete the tasks
int init_module()
{
    nfhoIn.hook = hook_func;
    nfhoIn.hooknum = NF_IP_LOCAL_IN;            //called right after packet recieved, first hook in Netfilter
    nfhoIn.pf = PF_INET;                           //IPV4 packets
    nfhoIn.priority = NF_IP_PRI_FIRST;             //set to highest priority over all other hook functions

    nfhoOut.hook = hook_func;
    nfhoOut.hooknum = NF_IP_LOCAL_OUT;
    nfhoOut.pf = PF_INET;
    nfhoOut.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfhoIn);                     //register hook
    nf_register_hook(&nfhoOut);

    return 0; //return 0 for success;
}


//Called when module unloaded using 'rmmod'
void cleanup_module()
{
    nf_unregister_hook(&nfhoIn);
    nf_unregister_hook(&nfhoOut);//cleanup – unregister hook
}

