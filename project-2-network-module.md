# Network Firewall Module

In this project, you will build a kernel module that monitors network traffic. Your module will allow users to specify things like “block all network traffic” and “print network traffic info." You will use netfilter (www.netfilter.org), a software packet filtering framework. Netfilter will let your kernel module register callback functions with the network stack. Netfilter is the library used by software like iptables to implement firewalls.

This link, though a little older, will help you get started writing a module: http://www.tldp.org/LDP/lkmpg/2.6/html/lkmpg.html. These slides also provide an introduction to modules: http://www.cs.uni.edu/~diesburg/courses/cop4610_fall10/week06/week6.pdf

The following link is the netfilter homepage, where you can find documentation about using netfilter with a kernel module: http://www.netfilter.org/. Start with this link, which is an introduction to networking concepts, and then read the more detailed documentation: https://www.netfilter.org/documentation/HOWTO/networking-concepts-HOWTO-1.html

## Project structure

You'll need to implement two pieces of functionality:

1. A linux kernel module that does the actual network monitoring/logging/filtering.
2. A way for the user to interact with and configure the module's functionality at runtime.

The easiest way to implement the interaction between the user and the module is to use the proc filesystem (see tips below). 

### For the kernel module portion (implemented with netfilter hooks):

- Implement the ability to filter all incoming/outgoing traffic. This link (and Section 4.6) contain most of the information you need: https://www.netfilter.org/documentation/HOWTO//netfilter-hacking-HOWTO-4.html#ss4.5
- Implement the ability to filter incoming/outgoing traffic from/to specific addresses. Read the specific addresses using whichever way you decided to communicate to/from the kernel module (the instructions in the list above, for instance, described using the /proc filesystem to do this). For example, when the user modifies the appropriate file in /proc, your module should re-read the file and make sure it's filtering what is currently specified.
- Implment the ability to monitor how many packets are received (and possibly blocked) from a specified address.

The filtering should be implemented by having your module register netfilter hooks. Some existing modules, such as iptables, already allow you to do this (and you can use the corresponding iptables program to modify the settings), so in a sense, you're implementing similar but simplified functionality. The following tutorials explain this (these links are a little dated, so you may not be able to use their code verbatim):

http://www.paulkiddie.com/2009/10/creating-a-simple-hello-world-netfilter-module/
http://www.paulkiddie.com/2009/11/creating-a-netfilter-kernel-module-which-filters-udp-packets/

### For the user interaction portion:

- Allow the user to specify that all incoming or all outgoing traffic should be blocked or unblocked.
- Allow the user to specify specific addresses whose packets should be blocked or unblocked.
- Allow the user to specify that they want to monitor (or quit monitoring) how many packets are received (and possibly blocked) from a specified address.
- Allow the user to view the statistics about the addresses that are being monitored. You should print how many packets have been received (and possibly blocked) from the addresses that are being monitored.

## Tips

- Start by creating a simple "hello, world!" kernel module and make sure you can insert (insmod), list (lsmod) and remove (rmmod) it.
- Review the kernel module slides we covered in the class (https://github.com/CS3281-vu/lectures/tree/master/SpecialLecture).
- Read about the "dmesg" command you can use to view your module's output - your printk messages from modules will show up there.
- Read about the "proc" filesystem and how you can use it to interact with kernel space from user space. See the example here: https://github.com/CS3281-vu/examples/tree/master/kernel_modules -- also, this link explains the proc filesystem: http://www.ibm.com/developerworks/library/l-proc/
- Understand the rules on memory allocation in the kernel. Instead of malloc and free, you will use kmalloc and kfree: http://www.linuxgrill.com/anonymous/fire/netfilter/kernel-hacking-HOWTO-4.html

# Project Report

In your project report, describe the following:

1. The design of your module.
2. The design of the user interaction, including the format of the commands a user can specify and what they do.
3. How the netfilter hooks work and what kinds of hooks there are.
4. Describe how you tested your project.
5. How you would implement more advanced functionality, such as a stateful firewall (https://en.wikipedia.org/wiki/Stateful_firewall).
6. Describe, with netfilter specific terms, how you would enforce a "quota" on how much traffic a user can generate to/from a specific address.
7. Explain why the Linux kernel does not have a binary kernel interface (this is one of the reasons that the sample netfilter code in some of the links above doesn't work on newer versions of the Linux kernel). This article will help: http://www.kroah.com/log/linux/stable_api_nonsense.html

Also include a short, 5 slide presentation describing:

1. The high level idea of the project.
2. The overall structure.
3. The challenges.
4. What you learned.
5. The work distribution between you and your partner.
