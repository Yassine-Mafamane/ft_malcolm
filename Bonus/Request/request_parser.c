#include "../ft_malcom.h"
#include <string.h>

int parse_request(char * buff, t_ArpPacket * request) {
    memcpy(&(request->dest), buff, ETHER_ADDR_LEN);
    buff += ETHER_ADDR_LEN;
    memcpy(&(request->sender), buff, ETHER_ADDR_LEN);
    buff += ETHER_ADDR_LEN;
    memcpy(&(request->ether_type), buff, sizeof(uint16_t));
    buff += sizeof(uint16_t);
    memcpy(&(request->hrd), buff, sizeof(uint16_t));
    buff += sizeof(uint16_t);
    memcpy(&(request->pro), buff, sizeof(uint16_t));
    buff += sizeof(uint16_t);

    memcpy(&(request->hln), buff, sizeof(uint8_t));
    if (request->hln > ETHER_ADDR_LEN) {
        fprintf(stderr, "Invalid hardware address length in ARP request\n");
        return 1;
    }
    buff += sizeof(uint8_t);

    memcpy(&(request->pln), buff, sizeof(uint8_t));
    if (request->pln > IPV4_ADDR_LEN) {
        fprintf(stderr, "Invalid protocol address length in ARP request\n");
        return 1;
    }
    buff += sizeof(uint8_t);

    memcpy(&(request->op), buff, sizeof(uint16_t));
    buff += sizeof(uint16_t);
    memcpy(&(request->sha), buff, request->hln * sizeof(uint8_t));
    buff += request->hln * sizeof(uint8_t);
    memcpy(&(request->spa), buff, request->pln * sizeof(uint8_t));
    buff += request->pln * sizeof(uint8_t);
    memcpy(&(request->tha), buff, request->hln * sizeof(uint8_t));
    buff += request->hln * sizeof(uint8_t);
    memcpy(&(request->tpa), buff, request->pln * sizeof(uint8_t));
    return 0;
}

void show_request_info(t_ArpPacket * request) {
    char ip_str[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, request->spa, ip_str, INET_ADDRSTRLEN);
    printf("    IP address of request : %s\n", ip_str);
    
    printf(
        "    MAC address of request : %02x:%02x:%02x:%02x:%02x:%02x\n", 
        request->sender[0], 
        request->sender[1], 
        request->sender[2], 
        request->sender[3], 
        request->sender[4], 
        request->sender[5]
    );
}