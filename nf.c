#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ctype.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <stdbool.h>

#include <linux/inet.h>

char buffer[20];

char *proc_all = "/proc/all_traffic";
char *proc_in = "/proc/in_traffic";
char *proc_out = "/proc/out_traffic";
char *proc_mo = "/proc/monitor_traffic";


//net filter hook options
//we will call the hook_func when the condition is met
static struct nf_hook_ops nfhoIn;
static struct nf_hook_ops nfhoOut;
struct sk_buff *sock_buff;
struct udphdr *udp_header;          //udp header struct (not used)
struct iphdr *ip_header;            //ip header struct

bool blockIncome = false;
bool blockOutgoing = false;
bool blockAll = false;

int MAXMUM = 20;
char *in_traffic[20];
size_t in_index;
char *out_traffic[20];
size_t out_index;
char *monitor_list[20];
size_t monitor_index;
int count_received[20];
int count_blocked[20];

//return the length of a char array
unsigned int string_length(char *arr) {
    int i;
    for (i = 0; arr[i]; i++) {
    }
    return i;
}

//read to content in file path to temp
//return 0 if not read anything
//refernce link:k
unsigned int read(char *path, char *buffer, int size) {
    int i, err;
    struct file *f;
    mm_segment_t oldfs;
    unsigned long long offset;
    // Init the buffer with 0
    for (i = 0; i < size; i++) {
        buffer[i] = 0;
    }
    err = 0;
    oldfs = get_fs();
    set_fs(get_ds());
    f = filp_open(path, O_RDONLY, 0);
    set_fs(oldfs);
    if (IS_ERR(f)) {
        err = PTR_ERR(f);
        filp_close(f, NULL);
        return 0;
    }
    if (f == NULL) {
        filp_close(f, NULL);
        return 0;
    }
    offset = 0;
    vfs_read(f, buffer, 20, &offset);
    set_fs(oldfs);
    //printk(KERN_INFO "read %s buf:%s %d\n",path,buff,string_Length(buff));
    filp_close(f, NULL);
    return string_length(buffer);
}

//Quit
//i specifies whether that's incoming, outgoing and monitoring
// 1: monitoring
// 2: incoming
// 3: outgoing
void quit_list(size_t index, int i) {
    if (i == 1) {
        kfree(in_traffic[index]);
        in_traffic[index] = in_traffic[in_index - 1];
        in_index--;
    } else if (i == 2) {
        kfree(out_traffic[index]);
        out_traffic[index] = out_traffic[out_index - 1];
        out_index--;
    } else if (i == 3) {
        kfree(monitor_list[index]);
        monitor_list[index] = monitor_list[monitor_index - 1];
        monitor_index--;
    }
}

//update the three lists based on the input from the use
//Note: we can quit monitoring by typing the same address. If we have
//received the same addresss, we delete that from the array.
unsigned int update_list(void) {
    char *buffer;
    int r;
    size_t index;
    bool hasSameIn;
    bool hasSameOut;
    bool hasSameMo;
    buffer = kmalloc(30 * sizeof(char), GFP_KERNEL);
    r = read(proc_all, buffer,sizeof(buffer));
    if (r != 0) {
        blockAll = true;
    }
    r = read(proc_in, buffer, sizeof(buffer));
    if (r != 0) {
        blockIncome = true;
        hasSameIn = false;
        //check if we have the same ip before, if so, call quit.
        for (index = 0; index < in_index; index++) {
            if (strcmp(in_traffic[index], buffer) == 0) {
                hasSameIn = true;
                quit_list(index, 1);
            }
        }
        if (hasSameIn) {
            if (in_index == MAXMUM) {
                printk(KERN_INFO
                "Too many ips on the list\n");
                return -1;
            }
            in_traffic[in_index] = kmalloc(r * sizeof(char), GFP_KERNEL);
            strcpy(in_traffic[in_index], buffer);
            in_index++;
        }
    }

    r = read(proc_out, buffer,sizeof(buffer));
    if (r != 0) {
        blockOutgoing = true;
        hasSameOut = false;
//check if we have the same ip before, if so, call quit.
        for (index = 0; index < out_index; index++) {
            if (strcmp(out_traffic[index], buffer) == 0) {
                hasSameOut = true;
                quit_list(index, 2);
            }
        }
        if (!hasSameOut) {
            if (out_index == MAXMUM) {
                printk(KERN_INFO
                "Too many ips on the list\n");
                return -1;
            }
            out_traffic[out_index] = kmalloc(r * sizeof(char), GFP_KERNEL);
            strcpy(out_traffic[out_index], buffer);
            out_index++;
        }
    }
    r = read(proc_mo, buffer, sizeof(buffer));
    if (r != 0) {
//check if we have the same ip before, if so, call quit.
        for (index = 0; index < monitor_index; index++) {
            if (strcmp(monitor_list[index], buffer) == 0) {
                quit_list(index, 3);
                count_received[index] = count_received[index - 1];
                count_blocked[index] = count_blocked[index - 1];
                hasSameMo = true;
            }
        }
        if (!hasSameMo) {
            if (out_index == MAXMUM) {
                printk(KERN_INFO
                "Too many ips on the list\n");
                return -1;
            }
            out_traffic[out_index] = kmalloc(r * sizeof(char), GFP_KERNEL);
            strcpy(out_traffic[out_index], buffer);
            out_index++;
        }
    }
    kfree(buffer);
    return 0;
}

//print pakage info
unsigned int printInfo(void) {
    int i;
    for (i = 0; i < monitor_index; i++) {
        printk(KERN_INFO
        "This is the statistics from:\t%s", monitor_list[i]);
        printk(KERN_INFO
        "The number of packets arrived:\t %d", count_received[i]);
        printk(KERN_INFO
        "number of packets accetped:\t%d", count_received[i] - count_blocked[i]);
        printk(KERN_INFO
        "number of packets blocked:\t %d", count_blocked[i]);
    }
    return 0;
}

//function to be called by hook
//This will enable the user to
// 1.block in/outcoming traffic by checking info from proc_all
// 2.filter the specific address' incoming traffic from proc_in
// 3.filter the specific address' outcoming traffic from proc_out
// 4. monitor the num packages by proc_mo.
unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    //update the source and dest
    size_t index;
    size_t i;
    char source[20], dest[20];
    sock_buff = skb;
    ip_header = (struct iphdr *) skb_network_header(sock_buff);
    snprintf(source, 20, "%pI4", &ip_header->saddr);
    snprintf(dest, 20, "%pI4", &ip_header->daddr);

    //update the list
    update_list();

    //update the receive information
    for (index = 0; index < monitor_index; index++) {
        if (strcmp(source, monitor_list[index]) == 0) {
            count_received[index]++;
        }
    }

    if (blockAll) {
        for (index = 0; index < monitor_index; index++) {
            if (strcmp(source, monitor_list[index]) == 0) {
                count_blocked[index]++;
                break;
            }
        }
        printk(KERN_INFO
        "All packets are blocked.\n");
        printInfo();
        return NF_DROP;
    }

    if (blockIncome) {
        for (i = 0; i < in_index; i++) {
            if (strcmp(source, in_traffic[i]) == 0) {
                for (index = 0; index < monitor_index; index++) {
                    if (strcmp(source, monitor_list[index]) == 0) {
                        count_blocked[index]++;
                    }

                    printk(KERN_INFO
                    "Incoming Packet is blocked\n");
                    printInfo();
                    return NF_DROP;
                }
            }
        }
    }

    if (blockOutgoing) {
        for (i = 0; i < out_index; i++) {
            if (strcmp(dest, out_traffic[i]) == 0) {
                printk(KERN_INFO
                "Outgoing Packet is blocked \n");
                printInfo();
                return NF_DROP;
            }
        }
    }

    printk(KERN_INFO
    "Incoming Packet is accepted\n");
    printInfo();
    return NF_ACCEPT;
}


//This is called when the module is loded with insmod command
//will register the hook needed to complete the tasks
int init_module() {
    nfhoIn.hook = hook_func;
    nfhoIn.hooknum = 1;            //NF_IP_LOCAL_IN called right after packet recieved, first hook in Netfilter
    nfhoIn.pf = PF_INET;                           //IPV4 packets
    nfhoIn.priority = NF_IP_PRI_FIRST;             //set to highest priority over all other hook functions

    nfhoOut.hook = hook_func;
    nfhoOut.hooknum = 3;         //NF_IP_LOCAL_OUT
    nfhoOut.pf = PF_INET;
    nfhoOut.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfhoIn);                     //register hook
    nf_register_hook(&nfhoOut);

    return 0; //return 0 for success;
}


//Called when module unloaded using 'rmmod'
void cleanup_module() {
    size_t index = 0;
    kfree(proc_all);
    kfree(proc_in);
    kfree(proc_out);
    kfree(proc_mo);
    for (index = 0; index < in_index; index++) {
        kfree(in_traffic[index]);
    }
    for (index = 0; index < out_index; index++) {
        kfree(out_traffic[index]);
    }
    for (index = 0; index < monitor_index; index++) {
        kfree(monitor_list[index]);
    }

    nf_unregister_hook(&nfhoIn);
    nf_unregister_hook(&nfhoOut);//cleanup – unregister hook
}

