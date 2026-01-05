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