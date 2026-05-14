#include "ft_malcom.h"

int create_listen_socket() {
	int 				listen_sock;
	struct sockaddr_in	addr;

	if ((listen_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		return -1;
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons(atoi("8080")); // TODO : use port passed as argument
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
	int					victim_sock;

	victim_addr_len = sizeof(victim_addr);

	if ((victim_sock = accept(listen_sock, (struct sockaddr*)&victim_addr, &victim_addr_len)) < 0) {
		perror("accept");
		return -1;
	}

	// TODO : check that the victim is the one connecting ...

	printf("Victim connected to the proxy!\n");
	printf("Victim IP: %s\n", inet_ntoa(victim_addr.sin_addr));

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
	server_addr.sin_port = htons(atoi("8080")); // TODO : use the port passed as argument
	server_addr.sin_addr.s_addr = *(uint32_t*)args.src_ip;

	if (connect(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
		perror("connect");
		return -1;
	}
	printf("Connected to the server!\n");
	return server_sock;
}

int	proxy_http() {
	int listen_sock, victim_sock, server_sock;

	if ((listen_sock = create_listen_socket()) < 0) {
		fprintf(stderr, "Failed to create listen socket\n");
		return -1;
	}

	if ((victim_sock = handle_victim_connections(listen_sock)) < 0) {
		fprintf(stderr, "Failed to handle victim connections\n");
		return -1;
	}

	if ((server_sock = connect_to_server()) < 0) {
		fprintf(stderr, "Failed to connect to server\n");
		return -1;
	}

	// Read the HTTP request from the victim and forward it to the server
	char buffer[4096];
	ssize_t bytes_read;

	bytes_read = recv(victim_sock, buffer, sizeof(buffer), 0);
	if (bytes_read < 0) {
		perror("recv");
		return -1;
	}

	printf("Received HTTP request from victim:\n%s\n", buffer);

	if (send(server_sock, buffer, bytes_read, 0) < 0) {
		perror("send");
		return -1;
	}

	// Read the HTTP response from the server and forward it to the victim
	bytes_read = recv(server_sock, buffer, sizeof(buffer), 0);
	if (bytes_read < 0) {
		perror("recv");
		return -1;
	}

	printf("Received HTTP response from server:\n%s\n", buffer);

	if (send(victim_sock, buffer, bytes_read, 0) < 0) {
		perror("send");
		return -1;
	}

	return 0;
}