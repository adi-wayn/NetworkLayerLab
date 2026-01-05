#ifndef NET_UTILS_H
#define NET_UTILS_H

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <poll.h>

/*
 * @brief Size of the buffer used to store the ICMP packet (including the header).
 * @note The buffer size is set to 1024 bytes, which is more than enough for the ICMP packet.
 * @attention The buffer size should be at least the size of the ICMP header, which is 8 bytes.
*/
#define BUFFER_SIZE 1024

// ===== Checksum =====
unsigned short int calculate_checksum(void *data, unsigned int bytes);

// ===== Time / RTT =====
double time_diff_ms(const struct timeval *start, const struct timeval *end);

// ===== ICMP packet building (for ping and traceroute) =====
int build_icmp_echo_request(char *buf, int bufsize,
                            uint16_t id, uint16_t seq,
                            const void *payload, int payload_len);

// ===== Receive + parse =====
int recv_icmp_packet(int sock, char *buf, int bufsize,
                     struct sockaddr_in *src,
                     int timeout_ms);

// extracts pointers inside recv buffer
void parse_ip_icmp(const char *buf, struct iphdr **ip, struct icmphdr **icmp);

#endif