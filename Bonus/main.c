#include "ft_malcom.h"

t_Arguments	args;

int	parse_addr(char	*addr) {

	static int	addr_index = 0;

	switch (addr_index) {
		case 0:
			if (parse_ip(addr, args.src_ip))
				return (1);
			break ;
		case 1:
			if (parse_mac(addr, args.src_mac) < 0)
				return (1);
			break ;
		case 2:
			if (parse_ip(addr, args.tar_ip))
				return (1);
			break ;
		case 3:
			if (parse_mac(addr, args.tar_mac) < 0)
				return (1);
			break ;
		default:
			fprintf(stderr, "Too many addresses provided\n");
			return (1);
	}

	addr_index++;
	return (0);
}

int	parse_option(char *option) {

	if (strcmp(option, "-f") == 0) {
		args.attack_type = REPLY_FLOODING;
	} else if (strcmp(option, "-s") == 0) {
		args.attack_type = REPLY_SPOOFING_SOLICITED;
	} else if (strcmp(option, "-r") == 0) {
		args.attack_type = REQUEST_SPOOFING;
	} else if (strcmp(option, "-v") == 0) {
		args.verbose = true;
	} else if (strcmp(option, "-p") == 0) {
		args.proxy = true;
	} else if (strcmp(option, "-pp") == 0) {
		args.proxy_listen_port = 8080;
	} else {
		fprintf(stderr, "Unknown option : %s\n", option);
		return (1);
	}

	return (0);
}

int parse_arguments(int argc, char *argv[]) {

	// Setting default values for the options :
	args.proxy = false;
	args.verbose = false;
	args.proxy_listen_port = 8080;
	args.attack_type = REPLY_SPOOFING;

	for (int i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			if (parse_option(argv[i]) != 0)
				return (1);
		} else if (parse_addr(argv[i]) != 0)
			return (1);
	}

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

	if (argc < 5) {
		printf("Usage: %s [options] <source IP> <source MAC> <target IP> <target MAC>\n", argv[0]);
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
	if (args.attack_type == REQUEST_SPOOFING && arp_request_spoof(interface_index) < 0)
		return (1);
	else if (arp_reply_spoof(interface_index) < 0)
		return (1);

	printf("ARP spoofing attempt completed. Please check the target system to verify if the attack was successful.\n");
	printf("The attack may be unsuccessful if the target system is not vulnerable to ARP spoofing, or if there is a race condition.\n");
	return (0);
}
