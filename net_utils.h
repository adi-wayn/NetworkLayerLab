#ifndef NET_UTILS_H
#define NET_UTILS_H

#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <poll.h>
#include <netinet/in.h>

/*
 * @brief Size of the buffer used to store the ICMP packet (including the header).
 * @note The buffer size is set to 1024 bytes, which is more than enough for the ICMP packet.
 * @attention The buffer size should be at least the size of the ICMP header, which is 8 bytes.
*/
#define BUFFER_SIZE 1024

// ===== Checksum =====
unsigned short int calculate_checksum(void *data, unsigned int bytes);

// ===== TCP helpers =====
struct pseudo_header_tcp {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t  placeholder;
    uint8_t  protocol;
    uint16_t tcp_length;
};

int get_local_ip_for_target(const char *target_ip, char *out_ip, size_t out_sz);

int build_tcp_syn_packet(char *packet, int packet_size,
                         const char *src_ip, const char *dst_ip,
                         uint16_t src_port, uint16_t dst_port,
                         uint32_t seq);

int build_tcp_rst_packet(char *packet, int packet_size,
                         const char *src_ip, const char *dst_ip,
                         uint16_t src_port, uint16_t dst_port,
                         uint32_t seq, uint32_t ack_seq);

void parse_ip_tcp(const char *buf, struct iphdr **ip, struct tcphdr **tcp);
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

// ===== Build IPv4 Header =====
int build_ipv4_header(char *buf, int bufsize, const char *src_ip, const char *dst_ip,
                      int ttl, int payload_len);

// ===== Build Packet for Traceroute =====
int build_packet_for_traceroute(char *buf, int bufsize,
                                const char *src_ip,
                                const char *dst_ip,
                                int ttl,
                                uint16_t id,
                                uint16_t seq,
                                const void *payload,
                                int payload_len);

#endif