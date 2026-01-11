// 1. Includes
#include <stdint.h>
#include <stddef.h>

#include <arpa/inet.h>
#include <poll.h>
#include <sys/time.h>

#include <netinet/in.h>     // חשוב שיהיה לפני tcp.h בהרבה מערכות
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "../net_utils.h" 
#include <unistd.h>   // בשביל close()


/*
 * IMPORTANT:
 * On some systems, struct tcphdr visibility/layout depends on this.
 * Must be defined BEFORE including <netinet/tcp.h>.
 */
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif

#include <netinet/tcp.h>
#include <netinet/udp.h>

// 2. Defines & Structs
// כאן תגדירי קבועים וגם את מבנה ה-Pseudo Header לחישוב Checksum של TCP/UDP

// 3. Helper Functions (פונקציות עזר)
/*
 * @brief A checksum function that returns 16 bit checksum for data.
 * @param data The data to do the checksum for.
 * @param bytes The length of the data in bytes.
 * @return The checksum itself as 16 bit unsigned number.
 * * This function is taken from RFC1071.
 */
unsigned short checksum(void *data, unsigned int bytes) {
    unsigned short *data_pointer = (unsigned short *)data;
    unsigned int total_sum = 0;

    // Main summing loop
    while (bytes > 1) {
        total_sum += *data_pointer++;
        bytes -= 2;
    }

    // Add left-over byte, if any
    if (bytes > 0)
        total_sum += *((unsigned char *)data_pointer);

    // Fold 32-bit sum to 16 bits
    while (total_sum >> 16)
        total_sum = (total_sum & 0xFFFF) + (total_sum >> 16);

    return (~((unsigned short)total_sum));
}

// מבנה עזר לחישוב Checksum של TCP
struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

// ===== TCP parsing helpers by offsets (no struct tcphdr dependency) =====
static uint16_t read_u16_net(const unsigned char *p) {
    uint16_t v;
    memcpy(&v, p, sizeof(v));
    return ntohs(v);
}
static uint32_t read_u32_net(const unsigned char *p) {
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return ntohl(v);
}

// TCP header offsets (RFC793)
#define TCP_OFF_SRC_PORT  0
#define TCP_OFF_DST_PORT  2
#define TCP_OFF_SEQ       4
#define TCP_OFF_ACK       8
#define TCP_OFF_DATAOFF   12  // upper 4 bits
#define TCP_OFF_FLAGS     13

// Flags bits
#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20

// פונקציה שבונה ושולחת חבילת TCP SYN
void scan_tcp_port(char *target_ip, int port) {
    // 1. יצירת Raw Socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) { perror("Socket creation failed"); return; }

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt IP_HDRINCL failed");
        close(sock);
        return;
    }
    // timeout 1s
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    char src_ip[INET_ADDRSTRLEN];
    if (get_local_ip_for_target(target_ip, src_ip, sizeof(src_ip)) < 0) {
        fprintf(stderr, "Failed to determine local IP for target %s\n", target_ip);
        close(sock);
        return;
    }

    // הגדרת כתובת היעד
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    if (inet_pton(AF_INET, target_ip, &dest.sin_addr) != 1) {
        perror("inet_pton");
        close(sock);
        return;
    }

    //בחירת פורט מקור ומספר חבילה seq
    uint16_t src_port = 12345;
    uint32_t seq = (uint32_t)rand();


    // build_tcp_syn_packet בונה SYN
    char packet[4096];
    int pkt_len = build_tcp_syn_packet(packet, sizeof(packet),
                                       src_ip,
                                       target_ip,
                                       src_port,
                                       (uint16_t)port,
                                       seq);

    if (pkt_len < 0) {
        fprintf(stderr, "build_tcp_syn_packet failed\n");
        close(sock);
        return;
    }

    // שליחת החבילה
    if (sendto(sock, packet, pkt_len, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto(SYN)");
        close(sock);
        return;
    }

    // קבלת התשובה
    char buffer[4096];
    struct sockaddr_in saddr;
    socklen_t saddr_size = sizeof(saddr);

    int data_size = recvfrom(sock, buffer, sizeof(buffer), 0,
                             (struct sockaddr*)&saddr, &saddr_size);
    if (data_size <= 0) {
        close(sock);
        return;
    }

    // ===== Parse received packet (IP + TCP) without struct tcphdr =====
    struct iphdr *rip = (struct iphdr *)buffer;
    int ip_hdr_bytes = rip->ihl * 4;
    if (data_size < ip_hdr_bytes + 20) {  // 20 = minimal TCP header
        close(sock);
        return;
    }

    unsigned char *tcp_ptr = (unsigned char *)buffer + ip_hdr_bytes;

    uint16_t tcp_src_port = read_u16_net(tcp_ptr + TCP_OFF_SRC_PORT);
    uint16_t tcp_dst_port = read_u16_net(tcp_ptr + TCP_OFF_DST_PORT);
    uint32_t tcp_seq      = read_u32_net(tcp_ptr + TCP_OFF_SEQ);

    uint8_t flags = *(uint8_t *)(tcp_ptr + TCP_OFF_FLAGS);
    int syn = (flags & TCP_FLAG_SYN) != 0;
    int ack = (flags & TCP_FLAG_ACK) != 0;
    int rst = (flags & TCP_FLAG_RST) != 0;

    // סינון - כדי לבדוק שהחבילה שקיבלנו באמת קשורה לסריקה שלנו
    if (saddr.sin_addr.s_addr == dest.sin_addr.s_addr &&
        tcp_src_port == (uint16_t)port &&
        tcp_dst_port == src_port)
    {
        // SYN+ACK => הפורט פתוח
        if (syn && ack) {
            printf("Port %d is OPEN (TCP)\n", port);

            // =================================================
            // הדרישה במטלה: אחרי SYN-ACK חייבים לשלוח RST
            // =================================================
            uint32_t their_seq = tcp_seq;
            uint32_t my_ack = their_seq + 1;
            uint32_t my_seq = seq + 1;

            char rst_pkt[4096];
            int rst_len = build_tcp_rst_packet(
                rst_pkt, sizeof(rst_pkt),
                src_ip,
                target_ip,
                src_port,
                (uint16_t)port,
                my_seq,
                my_ack
            );

            if (rst_len > 0) {
                sendto(sock, rst_pkt, rst_len, 0, (struct sockaddr *)&dest, sizeof(dest));
            }
        }
        // RST => הפורט סגור
        else if (rst) {
            // printf("Port %d is CLOSED (TCP)\n", port);
        }
    }

    close(sock);
}

// ======================================================
// פונקציה לסריקת פורט UDP
// שולחת UDP ריק ומחכה לתשובה:
// 1) אם מגיע UDP מהיעד -> הפורט פתוח
// 2) אם מגיע ICMP Port Unreachable -> הפורט סגור
// 3) אם אין תשובה (timeout) -> נחשב כסגור / filtered
// ======================================================
void scan_udp_port(char *target_ip, int port) {

    // ===== 0) בניית כתובת היעד =====
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port   = htons((uint16_t)port);

    if (inet_pton(AF_INET, target_ip, &dest.sin_addr) != 1) {
        perror("inet_pton");
        return;
    }

    // ===== 1) יצירת Socket UDP לשליחת הבדיקה =====
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) {
        perror("socket(UDP)");
        return;
    }

    // ===== 2) יצירת Raw Socket ל-ICMP =====
    // נועד לתפוס הודעות "Port Unreachable"
    // (דורש sudo)
    int icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (icmp_sock < 0) {
        perror("socket(ICMP RAW)");
        close(udp_sock);
        return;
    }

    // ===== 3) שליחת חבילת UDP ריקה =====
    // אין Payload – מספיק "לדפוק בדלת"
    if (sendto(udp_sock, NULL, 0, 0,
               (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto(UDP)");
        close(icmp_sock);
        close(udp_sock);
        return;
    }

    // ===== 4) המתנה לתשובה: UDP או ICMP =====
    struct pollfd pfds[2];

    // UDP socket
    pfds[0].fd = udp_sock;
    pfds[0].events = POLLIN;
    pfds[0].revents = 0;

    // ICMP socket
    pfds[1].fd = icmp_sock;
    pfds[1].events = POLLIN;
    pfds[1].revents = 0;

    // Timeout של שנייה אחת
    int ret = poll(pfds, 2, 1000);
    if (ret <= 0) {
        // Timeout / שגיאה → במטלה מתייחסים כ-filtered או סגור
        close(icmp_sock);
        close(udp_sock);
        return;
    }

    // ===== 5) אם קיבלנו תשובת UDP =====
    // זה אומר שיש שירות שמאזין -> הפורט פתוח
    if (pfds[0].revents & POLLIN) {
        char buf[2048];
        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);

        int n = recvfrom(udp_sock, buf, sizeof(buf), 0,
                         (struct sockaddr *)&from, &fromlen);

        if (n >= 0 &&
            from.sin_addr.s_addr == dest.sin_addr.s_addr) {
            printf("Port %d is OPEN (UDP)\n", port);
        }

        close(icmp_sock);
        close(udp_sock);
        return;
    }

    // ===== 6) אם קיבלנו ICMP =====
    // נבדוק אם זו הודעת "Port Unreachable"
    if (pfds[1].revents & POLLIN) {
        char buf[4096];
        struct sockaddr_in src;

        // פונקציה שכבר קיימת אצלך ב-net_utils
        int n = recv_icmp_packet(icmp_sock, buf, sizeof(buf), &src, 1000);
        if (n > 0) {
            struct iphdr   *outer_ip = NULL;
            struct icmphdr *icmp     = NULL;

            // פירוק IP + ICMP
            parse_ip_icmp(buf, &outer_ip, &icmp);

            // ICMP Destination Unreachable (type=3)
            // Port Unreachable (code=3)
            if (icmp && icmp->type == 3 && icmp->code == 3) {

                // בתוך ה-ICMP נמצא ה-IP המקורי + 8 בתים מה-UDP
                unsigned char *inner =
                    (unsigned char *)icmp + sizeof(struct icmphdr);

                int inner_len = n -
                    ((outer_ip ? outer_ip->ihl * 4 : 0) +
                     sizeof(struct icmphdr));

                if (inner_len >= (int)sizeof(struct iphdr)) {
                    struct iphdr *inner_ip = (struct iphdr *)inner;
                    int inner_ip_len = inner_ip->ihl * 4;

                    // בדיקה שזה באמת UDP
                    if (inner_ip->protocol == IPPROTO_UDP &&
                        inner_len >= inner_ip_len + (int)sizeof(struct udphdr)) {

                        struct udphdr *inner_udp =
                            (struct udphdr *)(inner + inner_ip_len);

                        uint16_t dport = ntohs(inner_udp->dest);

                        // אם זה הפורט שסורקים – הוא סגור
                        if (dport == (uint16_t)port) {
                            // לא מדפיסים CLOSED כדי לא להציף
                            // printf("Port %d is CLOSED (UDP)\n", port);
                        }
                    }
                }
            }
        }

        close(icmp_sock);
        close(udp_sock);
        return;
    }

    close(icmp_sock);
    close(udp_sock);
}


typedef enum {
    SCAN_TCP,
    SCAN_UDP
} scan_type_t;

int main(int argc, char *argv[]) {
    char *target_ip = NULL;
    scan_type_t scan_type = SCAN_TCP; // ברירת מחדל

    // ===== Parse arguments =====
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
            target_ip = argv[++i];
        }
        else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            if (strcmp(argv[i + 1], "TCP") == 0) {
                scan_type = SCAN_TCP;
            } else if (strcmp(argv[i + 1], "UDP") == 0) {
                scan_type = SCAN_UDP;
            } else {
                fprintf(stderr, "Invalid scan type: %s (use TCP or UDP)\n", argv[i + 1]);
                return 1;
            }
            i++;
        }
    }

    if (!target_ip) {
        fprintf(stderr, "Usage: %s -a <host> -t <TCP|UDP>\n", argv[0]);
        return 1;
    }

    // ===== Scan ports =====
    for (int port = 1; port <= 65535; port++) {
        if (scan_type == SCAN_TCP) {
            scan_tcp_port(target_ip, port);
        } else {
            scan_udp_port(target_ip, port);
        }
    }

    return 0;
}

