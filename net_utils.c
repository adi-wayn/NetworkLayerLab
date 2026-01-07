#include "net_utils.h"
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>

// ===== Checksum =====
unsigned short int calculate_checksum(void *data, unsigned int bytes) {
	unsigned short int *data_pointer = (unsigned short int *)data;
	unsigned int total_sum = 0;

	// Main summing loop.
	while (bytes > 1)
	{
		total_sum += *data_pointer++; // Some magic pointer arithmetic.
		bytes -= 2;
	}

	// Add left-over byte, if any.
	if (bytes > 0)
		total_sum += *((unsigned char *)data_pointer);

	// Fold 32-bit sum to 16 bits.
	while (total_sum >> 16)
		total_sum = (total_sum & 0xFFFF) + (total_sum >> 16);

	// Return the one's complement of the result.
	return (~((unsigned short int)total_sum));
}

// ===== Time / RTT =====
double time_diff_ms(const struct timeval *start, const struct timeval *end) {
    return (end->tv_sec - start->tv_sec) * 1000.0 +
           (end->tv_usec - start->tv_usec) / 1000.0;
}

// ===== Build ICMP Echo Request =====
int build_icmp_echo_request(char *buf, int bufsize,
                            uint16_t id, uint16_t seq,
                            const void *payload, int payload_len)
{
    int pkt_len = sizeof(struct icmphdr) + payload_len;
    if (pkt_len > bufsize) return -1;

    struct icmphdr icmp;
    memset(&icmp, 0, sizeof(icmp));
    icmp.type = ICMP_ECHO;
    icmp.code = 0;
    icmp.un.echo.id = htons(id);
    icmp.un.echo.sequence = htons(seq);
    icmp.checksum = 0;

    memset(buf, 0, pkt_len);
    memcpy(buf, &icmp, sizeof(icmp));
    if (payload_len > 0 && payload)
        memcpy(buf + sizeof(icmp), payload, payload_len);

    unsigned short csum = calculate_checksum(buf, pkt_len);
    ((struct icmphdr *)buf)->checksum = csum;

    return pkt_len;
}

// ===== Receive with poll =====
int recv_icmp_packet(int sock, char *buf, int bufsize,
                     struct sockaddr_in *src,
                     int timeout_ms)
{
    struct pollfd pfd;
    pfd.fd = sock;
    pfd.events = POLLIN;
    pfd.revents = 0;

    int ret = poll(&pfd, 1, timeout_ms);
    if (ret == 0) return 0;              // timeout
    if (ret < 0) {
        if (errno == EINTR) return -2;   // interrupted (Ctrl+C)
        return -1;
    }

    if (!(pfd.revents & POLLIN)) {
        return -1;
    }

    socklen_t slen = sizeof(*src);
    int n = recvfrom(sock, buf, bufsize, 0, (struct sockaddr *)src, &slen);
    if (n < 0) {
        if (errno == EINTR) return -2;
        return -1;
    }
    return n;
}

void parse_ip_icmp(const char *buf, struct iphdr **ip, struct icmphdr **icmp)
{
    *ip = (struct iphdr *)buf;
    *icmp = (struct icmphdr *)(buf + (*ip)->ihl * 4);
}

// ===== Build IPv4 Header =====
int build_ipv4_header(char *buf, int bufsize, const char *src_ip, const char *dst_ip,
                      int ttl, int payload_len){

    if (bufsize < (int)sizeof(struct iphdr))
        return -1;

    struct iphdr *ip = (struct iphdr *)buf;
    memset(ip, 0, sizeof(struct iphdr));

    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + payload_len);

    // Identification with a counter
    static uint16_t ip_id_counter = 0;
    ip->id = htons(ip_id_counter++);

    ip->frag_off = htons(0);
    ip->ttl = ttl;
    ip->protocol = IPPROTO_ICMP;
    ip->check = 0;

    // Source address
    if (src_ip != NULL) {
        if (inet_pton(AF_INET, src_ip, &ip->saddr) != 1)
            return -1;
    } else {
        ip->saddr = 0; // Let the OS fill in the source address
    }

    // Destination address
    if (inet_pton(AF_INET, dst_ip, &ip->daddr) != 1)
        return -1;

    // Compute IPv4 header checksum (only header bytes)
    ip->check = calculate_checksum(ip, sizeof(struct iphdr));

    return sizeof(struct iphdr);
}

// ===== Build Packet for Traceroute =====
int build_packet_for_traceroute(char *buf, int bufsize,
                                const char *src_ip,
                                const char *dst_ip,
                                int ttl,
                                uint16_t id,
                                uint16_t seq,
                                const void *payload,
                                int payload_len){
                                    
    int ip_len = sizeof(struct iphdr);

    if (bufsize < ip_len)
        return -1;

    /* 1) Build ICMP inside the buffer AFTER the IP header */
    int icmp_len = build_icmp_echo_request(buf + ip_len,
                                          bufsize - ip_len,
                                          id,
                                          seq,
                                          payload,
                                          payload_len);

    if (icmp_len < 0)
        return -1;

    /* 2) Build IPv4 header at the start of the buffer */
    int res = build_ipv4_header(buf,
                                bufsize,
                                src_ip,
                                dst_ip,
                                ttl,
                                icmp_len);

    if (res < 0)
        return -1;

    /* Total packet length = IP header + ICMP */
    return ip_len + icmp_len;
}