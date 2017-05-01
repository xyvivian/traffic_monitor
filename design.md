# Project 2: Network Firewall Module

## Tao Chen (section 02) Xueying Ding (section 02)

We are using C language as our main programming language for this project. We decide to implement one source file which combines the  kernel module class with the proc filesystem. The /proc filesystem is for the ability to filter incoming/outgoing traffic from/to specific addresses. When the user modifies the appropriate file in /proc, our module should re-read the file and make sure it's filtering what is currently specified. To build a basic kernel module in module class, we will mimic the Netfilter’s functions. Specifically, we will start by implementing the init_module(), and cleanup_module() 

How System can be integrated and tested:

The kernel module system needs to be integrated by using a special makefile(similar to the Hello,world example in the http://www.tldp.org/LDP/lkmpg/2.6/html/lkmpg.html.) This will make the module with special .ko extension, so we can distinguish it from the regular .o files. 

To test our program, we needs the insmod, lsmod, rmmod commands which loads,checks or removes the existing kernel modules from terminal. We can check the corresponding functionalities after the successful compilation and loading process.
