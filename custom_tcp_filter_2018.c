//***************************************************************
//  https://github.com/MisterChangRay
//
//  Custom Tcp Header Options And When  Data Arrive  Netfilter Check It
// 
//  This Code Test Pass Of Ubantu
// 
//***************************************************************

#include <linux/netfilter.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <uapi/linux/tcp.h>
#include <linux/netdevice.h>
#include <linux/kernel.h>


// length of custion option bytes
#define LENGTH_OF_OPTION 4

// the tcp option that will be appended on tcp header
static unsigned char option_tm[LENGTH_OF_OPTION] = {0xAE, LENGTH_OF_OPTION, 0xF1, 0xF2};
static char my_buf[64];

//user defined function for adding tcp option
unsigned int hook_out(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	struct 	iphdr           *iph    ;
	struct 	tcphdr          *tcph   ;
	struct  net_device		*dev    ;
    int                     hdr_len ;

	iph     = ip_hdr(skb);
	tcph    = (struct tcphdr *) skb_transport_header(skb);
	dev     = skb->dev;

	/* log the original src IP */
	printk(KERN_INFO"debug post-routing dest IP=%x\n", iph->daddr);
	printk(KERN_INFO"debug post-routing skb-> iphdr=\n" );

	skb_network_header(skb);

	//the condition for modify packet 
	if( skb_headroom(skb)>= 22 ) {
	 	//ipv4 and tcp packet
		if( skb->data[0]==0x45 && iph->protocol==0x06 ) {  
			//original header length, ip header + tcp header
            hdr_len = (iph->ihl + tcph->doff) * 4; 
            //copy original header to tmp buf; copy 64B to tmp buf; 64B is bigger than hdr_len;
	        memcpy(my_buf, skb->data, 64);
	        //append new tcp option on original header to generate a new header;
	        memcpy(my_buf + hdr_len, option_tm, LENGTH_OF_OPTION);
		
			// remove original header
            skb_pull( skb, hdr_len );
            //add new header
            skb_push( skb, hdr_len + LENGTH_OF_OPTION ); 
            //copy new header into skb;
	        memcpy(skb->data, my_buf, hdr_len + LENGTH_OF_OPTION );	

	        //update header offset in skb
	        skb->transport_header = skb->transport_header - LENGTH_OF_OPTION ;
	        skb->network_header   = skb->network_header   - LENGTH_OF_OPTION ;

            //update ip header and checksum
	        iph = ip_hdr(skb);  //update iph point to new ip header
	        iph->tot_len = htons(skb->len);
	        iph->check = 0;     //re-calculate ip checksum
	        iph->check = ip_fast_csum( iph, iph->ihl);
            //update tcp header and checksum
            tcph =  (struct tcphdr *) skb_transport_header(skb); 
            //update tcph point to new tcp header
            tcph->doff = tcph->doff + (LENGTH_OF_OPTION / 4);

	        tcph->check = 0;
	        int datalen;
	        //tcp segment length
	        datalen = (skb->len - iph->ihl*4); 

            ////re-calculate tcp checksum
            //tcp checksum = tcp segment checksum and tcp pseudo-header checksum
	        tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
	                                      datalen, iph->protocol,
	                                      csum_partial((char *)tcph, datalen, 0));
	        //the reason is not clear, but without it, it seems the hardware will re-calcuate the checksum
	        skb->ip_summed = CHECKSUM_UNNECESSARY;  
          
        }

	   
    }
    else { printk(KERN_INFO"head room is not enough\n" ); }
	/* modify the packet's src IP */
	return NF_ACCEPT;
}



//user defined function for adding tcp option
unsigned int hook_in(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	struct 	iphdr           *iph    ;
	struct 	tcphdr          *tcph   ;
    unsigned char           *d      ;
    unsigned char           *d2     ;
    int                     i       ;

	iph     = ip_hdr(skb);
	tcph    = (struct tcphdr *) skb_transport_header(skb);

	/* log the original src IP */
	printk(KERN_INFO"net hook source IP=%x to IP=%x \n", iph->saddr, iph->daddr);

	/* log the original src IP */
	d = skb_network_header(skb);

	//the condition for modify packet 
	if(   (skb)>= 22 ) {
	 	//ipv4 and tcp packet
		if( skb->data[0]==0x45 && iph->protocol==0x06 ) {
			// set d of tcp header 
			d = tcph;
			// offset address to header tail
			d = d + (tcph->doff * 4);

			// iterator tcp header from  tail to head with 4 byte		
            for(i=LENGTH_OF_OPTION - 1 ; i >= 0; i--) {
            	d --;
            	d2 = option_tm[i];

            	if(*d !=  option_tm[i]) {
            		// drop pack if header option data check faild
            		return NF_DROP;
            	}
            }
        }
    }
	return NF_ACCEPT;
}


/* A netfilter instance to use */
static struct nf_hook_ops nfho_in[] __read_mostly = {
	{
		.hook = hook_in,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		//process packet after routing process
		.priority = NF_IP_PRI_FIRST,
		.owner = THIS_MODULE
	}
	,
	{
		.hook = hook_out,
		.pf = PF_INET,
		//process packet after routing process
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_FIRST,
		.owner = THIS_MODULE
	}
};

static int __init sknf_init(void)
{
	if (nf_register_hooks(nfho_in,  ARRAY_SIZE(nfho_in))) {
		printk(KERN_ERR"nf_register_hook() failed\n");
		return -1;
	}
	return 0;
}

static void __exit sknf_exit(void)
{
	nf_unregister_hooks(nfho_in,  ARRAY_SIZE(nfho_in));
}

module_init(sknf_init);
module_exit(sknf_exit);
MODULE_AUTHOR("ray.chang");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("check tcp header for input packets and add tcp option for output packets");