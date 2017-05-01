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

//for block all the outgoing traffic
char *msg0;
//for block all the traffic
char *msg1;
//for block in coming traffic
char *msg2;
//for block out going traffic
char *msg3;
//for monitoring
char *msg4;


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
bool blockAllO = false;

int MAXMUM = 20;
char *in_traffic[20];
size_t in_index;
char *out_traffic[20];
size_t out_index;
char *monitor_list[20];
size_t monitor_index;
int count_received[20];
int count_blocked[20];

//Quit
//i specifies whether that's incoming, outgoing and monitoring
// 1: monitoring
// 2: incoming
// 3: outgoing
void quit_list(size_t index, int i) {
    char * temp;
    if (i == 1) {
        temp = in_traffic[index];
        in_traffic[index] = in_traffic[in_index - 1];
        kfree(temp);
        in_index--;
    } else if (i == 2) {
        temp = out_traffic[index];
        out_traffic[index] = out_traffic[out_index - 1];
        kfree(temp);
        out_index--;
    } else if (i == 3) {
        temp = monitor_list[monitor_index - 1];
        monitor_list[index] = monitor_list[monitor_index - 1];
        kfree(temp);
        monitor_index--;
    }
}

//allow writing from the user space to kernel space.
static ssize_t
write_proc0 (struct file *filp, const char __user * buf, size_t count,
        loff_t * offp)
{

// you have to move data from user space to kernel buffer
copy_from_user (msg0, buf, count);
strim(msg0);
msg0[count] = '\0';

blockAllO =true;
return count;
}


//allow writing from the user space to kernel space.
static ssize_t
write_proc1 (struct file *filp, const char __user * buf, size_t count,
        loff_t * offp)
{

// you have to move data from user space to kernel buffer
copy_from_user (msg1, buf, count);
strim(msg1);
msg1[count] = '\0';

blockAll =true;
return count;
}

//allow writing from the user space to kernel space.
static ssize_t
write_proc2 (struct file *filp, const char __user * buf, size_t count,
        loff_t * offp)
{
size_t index;
bool hasSameIn;

// you have to move data from user space to kernel buffer
copy_from_user (msg2, buf, count);
strim(msg2);
msg2[count] = '\0';

blockIncome = true;
hasSameIn = false;

//check if we have the same ip before, if so, call quit.
for (index = 0; index < in_index; index++) {
    if (strncmp(in_traffic[index], msg2, 30) == 0) {
        hasSameIn = true;
        quit_list(index, 1);
    }
}
if (!hasSameIn) {
   if (in_index == MAXMUM) {
       printk(KERN_INFO "Too many ips on the list\n");
   return -1;
   }
   in_traffic[in_index] = kmalloc(count * sizeof(char), GFP_KERNEL);
   strcpy(in_traffic[in_index], msg2);
   in_index++;
}

return count;
}

//allow writing from the user space to kernel space.
static ssize_t
write_proc3 (struct file *filp, const char __user * buf, size_t count,
        loff_t * offp)
{
size_t index;
bool hasSameOut;
// you have to move data from user space to kernel buffer
copy_from_user (msg3, buf, count);
strim(msg3);
msg3[count] = '\0';
blockOutgoing = true;
hasSameOut = false;
//check if we have the same ip before, if so, call quit.
   for (index = 0; index < out_index; index++) {
      if (strncmp(out_traffic[index], msg3, 30) == 0) {
      hasSameOut = true;
      quit_list(index, 2);
   }
}
if (!hasSameOut) {
    if (out_index == MAXMUM) {
        printk(KERN_INFO "Too many ips on the list\n");
        return -1;
     }
out_traffic[out_index] = kmalloc(count * sizeof(char), GFP_KERNEL);
strcpy(out_traffic[out_index], msg3);
out_index++;
    }
return count;
}

//allow writing from the user space to kernel space.
static ssize_t
write_proc4 (struct file *filp, const char __user * buf, size_t count,
        loff_t * offp)
{

bool hasSameMo;
size_t index;
// you have to move data from user space to kernel buffer
copy_from_user (msg4, buf, count);
strim(msg4);
msg4[count] = '\0';
hasSameMo = false;
//check if we have the same ip before, if so, call quit.
for (index = 0; index < monitor_index; index++) {
     if (strncmp(monitor_list[index], msg4, 30) == 0) {
         quit_list(index, 3);
         count_received[index] = count_received[index - 1];
         count_blocked[index] = count_blocked[index - 1];
         hasSameMo = true;
     }
}
if (!hasSameMo) {
     if (out_index == MAXMUM) {
         printk(KERN_INFO "Too many ips on the list\n");
         return -1;
     }
     out_traffic[out_index] = kmalloc(count * sizeof(char), GFP_KERNEL);
     strcpy(out_traffic[out_index], msg4);
     out_index++;
    }
return count;
}

static const struct file_operations proc_fops0 = {
        .owner = THIS_MODULE,
        .write = write_proc0,
};

static const struct file_operations proc_fops1 = {
        .owner = THIS_MODULE,
        .write = write_proc1,
};

static const struct file_operations proc_fops2 = {
        .owner = THIS_MODULE,
        .write = write_proc2,
};

static const struct file_operations proc_fops3 = {
        .owner = THIS_MODULE,
        .write = write_proc3,
};

static const struct file_operations proc_fops4 = {
        .owner = THIS_MODULE,
        .write = write_proc4,
};


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
unsigned int hook_funcIn(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    //update the source and dest
    size_t index;
    size_t i;
    char source[20], dest[20];
    sock_buff = skb;
    ip_header = (struct iphdr *) skb_network_header(sock_buff);
    snprintf(source, 20, "%pI4", &ip_header->saddr);
    snprintf(dest, 20, "%pI4", &ip_header->daddr);

    //update the receive information
    for (index = 0; index < monitor_index; index++) {
        if (strncmp(source, monitor_list[index],30) == 0) {
            count_received[index]++;
        }
    }

    if (blockAll) {
        for (index = 0; index < monitor_index; index++) {
            if (strncmp(source, monitor_list[index],30) == 0) {
                count_blocked[index]++;
                break;
            }
        }
        printk(KERN_INFO "All packets are blocked.\n");
        printInfo();
        return NF_DROP;
    }

    if (blockIncome) {
        for (i = 0; i < in_index; i++) {
            if (strcmp(source, in_traffic[i]) == 0) {
                for (index = 0; index < monitor_index; index++) {
                    if (strncmp(source, monitor_list[index],30) == 0) {
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

    printk(KERN_INFO
    "Incoming Packet is accepted\n");
    printInfo();
    return NF_ACCEPT;
}

unsigned int hook_funcOut(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    //update the source and dest
    size_t index;
    size_t i;
    char source[20], dest[20];
    sock_buff = skb;
    ip_header = (struct iphdr *) skb_network_header(sock_buff);
    snprintf(source, 20, "%pI4", &ip_header->saddr);
    snprintf(dest, 20, "%pI4", &ip_header->daddr);

    //update the receive information
    for (index = 0; index < monitor_index; index++) {
        if (strncmp(source, monitor_list[index],30) == 0) {
            count_received[index]++;
        }
    }

    if (blockAllO) {
        for (index = 0; index < monitor_index; index++) {
            if (strncmp(source, monitor_list[index],30) == 0) {
                count_blocked[index]++;
                break;
            }
        }
        printk(KERN_INFO "All packets are blocked.\n");
        printInfo();
        return NF_DROP;
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

//create a new proc file entry.
void
create_new_proc_entry (void)
{
    proc_create ("blockO", 0666, NULL, &proc_fops0);
    msg0 = kmalloc (100 * sizeof (char), GFP_KERNEL);
    if (msg0 == 0)
    {
        printk (KERN_INFO "why is msg 0 \n");
    }

    proc_create ("block", 0666, NULL, &proc_fops1);
    msg1 = kmalloc (100 * sizeof (char), GFP_KERNEL);
    if (msg1 == 0)
    {
        printk (KERN_INFO "why is msg 0 \n");
    }

    proc_create ("inc", 0666, NULL, &proc_fops2);
    msg2 = kmalloc (100 * sizeof (char), GFP_KERNEL);
    if (msg2 == 0)
    {
        printk (KERN_INFO "why is msg 0 \n");
    }

    proc_create ("outg", 0666, NULL, &proc_fops3);
    msg3 = kmalloc (100 * sizeof (char), GFP_KERNEL);
    if (msg3 == 0)
    {
        printk (KERN_INFO "why is msg 0 \n");
    }


    proc_create ("monitor", 0666, NULL, &proc_fops4);
    msg4 = kmalloc (100 * sizeof (char), GFP_KERNEL);
    if (msg4 == 0)
    {
        printk (KERN_INFO "why is msg 0 \n");
    }
}


//This is called when the module is loded with insmod command
//will register the hook needed to complete the tasks
int init_module() {
    nfhoIn.hook = hook_funcIn; //function to call when conditions below met
    nfhoIn.hooknum = NF_INET_LOCAL_IN;
    nfhoIn.pf = PF_INET; //IPV4 packets
    nfhoIn.priority = NF_IP_PRI_FIRST; //set to highest priority over all other hook functions
    nf_register_hook(&nfhoIn); //register hook


    nfhoOut.hook = hook_funcOut; //function to call when conditions below met
    nfhoOut.hooknum = NF_INET_LOCAL_OUT;
    nfhoOut.pf = PF_INET; //IPV4 packets
    nfhoOut.priority = NF_IP_PRI_FIRST; //set to highest priority over all other hook functions
    nf_register_hook(&nfhoOut); //register hook

    create_new_proc_entry();    //load proc files
    return 0;
}


//Called when module unloaded using 'rmmod'
void cleanup_module() {
    size_t index = 0;
    kfree(msg0);
    kfree(msg1);
    kfree(msg2);
    kfree(msg3);
    kfree(msg4);

    remove_proc_entry("blockO", NULL);

    remove_proc_entry("block",NULL);

    remove_proc_entry("inc",NULL);

    remove_proc_entry("outg",NULL);

    remove_proc_entry("monitor",NULL);

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

