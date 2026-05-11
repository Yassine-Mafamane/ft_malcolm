#ifndef FT_MALCOM_H
# define FT_MALCOM_H

#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>


# define ARES_OP_REQUEST    1
# define ARES_OP_REPLY      2
# define ARES_HRD_ETHERNET  1

# define IPV4_ADDR_LEN		4

#define ARP_OPCODE_OFFSET	20

typedef struct s_ArpPacket {
	uint8_t		dest[ETHER_ADDR_LEN];	// Destination hardware address (MAC)
	uint8_t		sender[ETHER_ADDR_LEN];	// Sender hardware address (MAC)
	uint16_t	ether_type;				// Ethernet type (0x0806 for ARP)
	uint16_t	hrd;					// Hardware type
	uint16_t	pro;					// Protocol type
	uint8_t		hln;					// Hardware address length
	uint8_t		pln;					// Protocol address length
	uint16_t	op;						// Operation code (request or reply)
	uint8_t		sha[ETHER_ADDR_LEN];	// Sender hardware address (MAC)
	uint8_t		spa[IPV4_ADDR_LEN];		// Sender protocol address (IP)
	uint8_t		tha[ETHER_ADDR_LEN];	// Target hardware address (MAC)
	uint8_t		tpa[IPV4_ADDR_LEN];		// Target protocol address (IP)
} t_ArpPacket;

// The following struct is used to store the program argumets.
typedef struct s_Arguments {
	uint8_t		src_ip[IPV4_ADDR_LEN];		// Source protocol address (IP v4).  Data written in network byte order.
	uint8_t		src_mac[ETHER_ADDR_LEN];	// Source hardware address (MAC)
	uint8_t		tar_ip[IPV4_ADDR_LEN];		// Target protocol address (IP v4). Data written in network byte order.
	uint8_t		tar_mac[ETHER_ADDR_LEN];	// Target hardware address (MAC)
} t_Arguments;



// Global variable to store the program arguments
#ifndef ARGS
# define ARGS
extern t_Arguments	args;
#endif

// Request
int			parse_request(char * buff, t_ArpPacket * data);
void		show_request_info(t_ArpPacket * data);


// utils
static int	hex_to_val(char c);
int			parse_mac(const char *str, uint8_t mac[6]);
int			parse_ip(char *str, uint8_t *ip);


// net
int			run_arp_spoofing(int interface_index);
int			find_interface();

#endif