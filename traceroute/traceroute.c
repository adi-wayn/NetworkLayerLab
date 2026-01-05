#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>

#include "net_utils.h"

#define TTL_MAX 64
#define MAX_HOPS 30
#define PROBES_PER_HOP 3
#define TR_TIMEOUT_MS 1000


static int match_icmp_error_probe(const char *recvbuf, int recvlen,int expected_outer_type,
                                     uint16_t expected_id, uint16_t expected_seq)
{
    if (recvlen < (int)(sizeof(struct iphdr) + sizeof(struct icmphdr)))
        return 0;

    struct iphdr *outer_ip = (struct iphdr *)recvbuf;
    int outer_ip_len = outer_ip->ihl * 4;

    if (outer_ip_len < 20 || recvlen < outer_ip_len + (int)sizeof(struct icmphdr))
        return 0;


    struct icmphdr *outer_icmp = (struct icmphdr *)(recvbuf + outer_ip_len);

    if (outer_icmp->type != expected_outer_type)
        return 0;

    const char *inner_ip_buf = (const char *)(outer_icmp + 1);

    int inner_min = outer_ip_len + sizeof(struct icmphdr) + sizeof(struct iphdr);
    if (recvlen < inner_min)
        return 0;

    struct iphdr *inner_ip = (struct iphdr *)inner_ip_buf;
    int inner_ip_len = inner_ip->ihl * 4;

    int need = outer_ip_len + (int)sizeof(struct icmphdr) + inner_ip_len + (int)sizeof(struct icmphdr);
    if (recvlen < need)
        return 0;


    struct icmphdr *inner_icmp = (struct icmphdr *)(inner_ip_buf + inner_ip_len);

    uint16_t inner_id  = ntohs(inner_icmp->un.echo.id);
    uint16_t inner_seq = ntohs(inner_icmp->un.echo.sequence);

    return (inner_id == expected_id && inner_seq == expected_seq);
}


int main(int argc, char *argv[]) {

    char *dest_ip = NULL;
    int opt;

    while ((opt = getopt(argc, argv, "a:")) != -1) {
        if (opt == 'a')
            dest_ip = optarg;
        else {
            fprintf(stderr, "Usage: %s -a <destination_ip>\n", argv[0]);
            return 1;
        }
    }

    if (!dest_ip) {
        fprintf(stderr, "Error: -a <destination_ip> is required\n");
        fprintf(stderr, "Usage: %s -a <destination_ip>\n", argv[0]);
        return 1;
    }

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;

    if (inet_pton(AF_INET, dest_ip, &dest_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid IPv4: %s\n", dest_ip);
        return 1;
    }

    /* socket for sending (custom IP header) */
    int send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (send_sock < 0) {
        perror("send socket");

        if (errno == EACCES || errno == EPERM)
			fprintf(stderr, "You need to run the program with sudo.\n");
        return 1;
    }

    int one = 1;
    if (setsockopt(send_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt(IP_HDRINCL)");
        close(send_sock);
        return 1;
    }

    /* socket for receiving ICMP */
    int recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (recv_sock < 0) {
        perror("recv socket");
        close(send_sock);
        return 1;
    }

    printf("traceroute to %s, %d hops max\n", dest_ip, MAX_HOPS);

    char packet[BUFFER_SIZE];
    char recvbuf[BUFFER_SIZE];

    uint16_t id = (uint16_t)getpid();
    uint16_t seq = 1;

    const char *payload = "HELLO_TRACEROUTE";
    int payload_len = strlen(payload) + 1;

    for (int ttl = 1; ttl <= TTL_MAX && ttl <= MAX_HOPS; ttl++){

        fflush(stdout);

        int got_ip_this_hop = 0;
        struct in_addr hop_addr;
        double rtts[PROBES_PER_HOP];
        int ok[PROBES_PER_HOP];
        memset(ok, 0, sizeof(ok));
        memset(rtts, 0, sizeof(rtts));
        int reached_dest = 0;
        int dest_unreach = 0;

        for (int probe = 0; probe < PROBES_PER_HOP; probe++) {

            memset(packet, 0, sizeof(packet));
            memset(recvbuf, 0, sizeof(recvbuf));

            uint16_t sent_seq = seq;
            int pkt_len = build_packet_for_traceroute(
                packet, sizeof(packet),
                NULL, dest_ip,
                ttl,
                id, sent_seq,
                payload, payload_len
            );
            seq++;

            if (pkt_len < 0) {
                fprintf(stderr, "\nFailed to build traceroute packet\n");
                close(send_sock);
                close(recv_sock);
                return 1;
            }

            struct timeval start, end;
            gettimeofday(&start, NULL);

            if (sendto(send_sock, packet, pkt_len, 0,
                       (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
                perror("sendto");
                close(send_sock);
                close(recv_sock);
                return 1;
            }

            struct sockaddr_in src_addr;
            memset(&src_addr, 0, sizeof(src_addr));

            int matched = 0;
            int final_type = -1;

            struct timeval listen_start, now;
            gettimeofday(&listen_start, NULL);

            while (1) {
                /* calculate remaining timeout */
                gettimeofday(&now, NULL);
                double elapsed = time_diff_ms(&listen_start, &now);
                int remaining = TR_TIMEOUT_MS - (int)elapsed;

                if (remaining <= 0) {
                    /* timeout */
                    ok[probe] = 0;
                    break;
                }

                memset(recvbuf, 0, sizeof(recvbuf));

                int n = recv_icmp_packet(recv_sock, recvbuf, sizeof(recvbuf),
                                        &src_addr, remaining);

                if (n == 0) {
                    /* timed out in poll */
                    ok[probe] = 0;
                    break;
                }
                if (n < 0) {
                    /* recv error - treat like timeout */
                    ok[probe] = 0;
                    break;
                }

                /* parse packet */
                struct iphdr *ip_hdr;
                struct icmphdr *icmp_hdr;
                parse_ip_icmp(recvbuf, &ip_hdr, &icmp_hdr);

                /* check if packet matches our probe */
                if (icmp_hdr->type == ICMP_TIME_EXCEEDED) {

                    if (!match_icmp_error_probe(recvbuf, n, ICMP_TIME_EXCEEDED, id, sent_seq))
                        continue;

                    final_type = ICMP_TIME_EXCEEDED;
                }

                else if (icmp_hdr->type == ICMP_DEST_UNREACH) {

                    if (!match_icmp_error_probe(recvbuf, n, ICMP_DEST_UNREACH, id, sent_seq))
                        continue;

                    final_type = ICMP_DEST_UNREACH;
                }

                else if (icmp_hdr->type == ICMP_ECHOREPLY) {

                    if (src_addr.sin_addr.s_addr != dest_addr.sin_addr.s_addr) continue;

                    if (ntohs(icmp_hdr->un.echo.id) != id || ntohs(icmp_hdr->un.echo.sequence) != sent_seq) continue;

                    final_type = ICMP_ECHOREPLY;
                }

                else {
                    continue;
                }

                /* now we have a matched packet -> compute RTT */
                gettimeofday(&end, NULL);
                rtts[probe] = time_diff_ms(&start, &end);
                ok[probe] = 1;

                /* store hop ip (first match) */
                if (!got_ip_this_hop) {
                    hop_addr = src_addr.sin_addr;
                    got_ip_this_hop = 1;
                }

                matched = 1;
                break;
            }

            /* after loop: decide behavior */
            if (!matched) {
                continue;
            }

            if (final_type == ICMP_ECHOREPLY) {
                reached_dest = 1;
                break;
            }

            if (final_type == ICMP_DEST_UNREACH) {
                dest_unreach = 1;
                break;
            }
        }

        printf("%d ", ttl);

        if (!got_ip_this_hop) {
            printf("* * *\n");
            continue;
        }
        printf("%s ", inet_ntoa(hop_addr));

        for (int i = 0; i < PROBES_PER_HOP; i++) {
            if (!ok[i]) printf("* ");
            else printf("%.3fms ", rtts[i]);
        }

        if (reached_dest) {
            close(send_sock);
            close(recv_sock);
            return 0;
        }

        if (dest_unreach) {
            printf("Destination unreachable\n");
            close(send_sock);
            close(recv_sock);
            return 1;
        }

        printf("\n");
    }

    printf("Destination unreachable (max hops reached)\n");
    close(send_sock);
    close(recv_sock);
    return 0;
}