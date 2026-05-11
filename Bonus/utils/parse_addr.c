
#include "../ft_malcom.h"

// Convert a single hex character to its value (0-15)
static int hex_to_val(char c)
{
		if (c >= '0' && c <= '9')
			return (c - '0');
		if (c >= 'a' && c <= 'f')
			return (c - 'a' + 10);
		if (c >= 'A' && c <= 'F')
			return (c - 'A' + 10);
		return (-1);
}

int parse_mac(const char *str, uint8_t mac[6])
{
	int 		i = 0;
	const char	*original_str = str;
	
	if (strlen(str) != 17)
		goto error;

	if (strcmp(str, "00:00:00:00:00:00") == 0 || strcmp(str, "ff:ff:ff:ff:ff:ff") == 0) {
		fprintf(stderr, "Not acceptable MAC : %s\n", str);
		return (-1);
	}

	while (i < 6) {
		int high = hex_to_val(*str++);
		int low  = hex_to_val(*str++);

		if (high == -1 || low == -1)
			goto error;

		mac[i++] = (uint8_t)((high << 4) | low);

		if (i < 6 && *str++ != ':')
			goto error;
	}
	return (0);

error:
	fprintf(stderr, "MAC not in presentation format : %s\n", original_str);
	return (-1);
}

int parse_ip(char *str, uint8_t *ip)
{
	if (strcmp(str, "0.0.0.0") == 0 || strcmp(str, "255.255.255.255") == 0) {
		fprintf(stderr, "Not acceptable IP : %s\n", str);
		return (1);
	}

	int s = inet_pton(AF_INET, str, ip);

	if (s <= 0) {
		if (s == 0)
			fprintf(stderr, "IP not in presentation format : %s\n", str);
		else
			perror("inet_pton");
		return (1);
	}
	return (0);
}
