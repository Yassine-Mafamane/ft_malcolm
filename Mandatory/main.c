#include "ft_malcom.h"

t_Arguments	args;

int parse_arguments(int argc, char *argv[]) {

	if (parse_ip(argv[1], args.src_ip) || parse_ip(argv[3], args.tar_ip))
		return (1);

	if (parse_mac(argv[2], args.src_mac) < 0 || parse_mac(argv[4], args.tar_mac) < 0)
		return (1);

	// Debugging

	// char	str[INET_ADDRSTRLEN];

	// if (inet_ntop(AF_INET, args.src_ip, str, INET_ADDRSTRLEN) == NULL) {
	// 	perror("inet_ntop");
	// 	return (1);
	// }

	// printf("Source IP : %s\n", str);

	// if (inet_ntop(AF_INET, args.tar_ip, str, INET_ADDRSTRLEN) == NULL) {
	// 	perror("inet_ntop");
	// 	return (1);
	// }

	// printf("Target IP : %s\n", str);

	// printf("Source Mac : %.02x:%.02x:%.02x:%.02x:%.02x:%.02x\n", args.src_mac[0], args.src_mac[1], args.src_mac[2], args.src_mac[3], args.src_mac[4], args.src_mac[5]);
	// printf("Target Mac : %.02x:%.02x:%.02x:%.02x:%.02x:%.02x\n", args.tar_mac[0], args.tar_mac[1], args.tar_mac[2], args.tar_mac[3], args.tar_mac[4], args.tar_mac[5]);

	return (0);
}

int	main(int argc, char *argv[]) {

	// This variable will be used to check that the AF_PACKET is comming from the same interface as the addresses belong to.
	// And also to send the reply packet through the same interface.
	int	interface_index;

	if (argc != 5) {
		printf("Usage: %s <source IP> <source MAC> <target IP> <target MAC>\n", argv[0]);
		return (1);
	}

	// Arguments parsing...
	bzero(&args, sizeof(args));

	if (parse_arguments(argc, argv) != 0)
		return (1);

	// Interface validation...
	if ((interface_index = find_interface()) == -1)
		return (1);

	// ARP spoofing...
	if (run_arp_spoofing(interface_index) < 0)
		return (1);

	printf("ARP spoofing attempt completed. Please check the target system to verify if the attack was successful.\n");
	printf("The attack may be unsuccessful if the target system is not vulnerable to ARP spoofing, or if there is a race condition.\n");
	printf("For more reliability, you can use other atack techniques in the bonus part.\n");
	return (0);
}
