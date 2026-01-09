// 1. Includes
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
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
    
//?
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
    uint32_t seq = (uint32_t)random();

    //  באפר (Buffer) להחזקת החבילה שאנחנו רוצים לשלוח
    //build_tcp_syn_packet- לוקח את הבאפרר ובונה לי בתוכו חבילת TCP SYNתקינה /ומחזיר את גודל החבילה 
    char packet[4096];
    int pkt_len = build_tcp_syn_packet(packet, sizeof(packet),
                                       src_ip,          // מקור (המחשב שלנו)
                                       target_ip,       // יעד
                                       src_port,        // src port-הפורת בוא היעד יחזיר תשובה
                                       (uint16_t)port,  // dst port
                                       seq);            // seq number
//בודק אם הפונקציה הצליחה לבנות את החבילה

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
//פירוק התשובה שהתקבלה
    struct iphdr *rip;
    struct tcphdr *rtcp;
    parse_ip_tcp(buffer, &rip, &rtcp);

    //סינון - כדי לבדוק שהחבילה שקיבלנו באמת קשורה לסריקה שלנו
    if (saddr.sin_addr.s_addr == dest.sin_addr.s_addr &&
        ntohs(rtcp->source) == port &&
        ntohs(rtcp->dest) == src_port)
    {
    // SYN+ACK => הפורט פתוח
    if (rtcp->syn == 1 && rtcp->ack == 1) {
         printf("Port %d is OPEN (TCP)\n", port);
 // =================================================
            // 13) הדרישה במטלה:
            // אחרי שקיבלנו SYN-ACK חייבים לשלוח RST
            // כדי לא להשאיר חיבור פתוח/חצי-פתוח.
            // =================================================
            // סורקים את מה שקיבלנו 
        uint32_t their_seq = ntohl(rtcp->seq);
        //אישור  את ה SYN של השרת
        uint32_t my_ack = their_seq + 1;
        //מקדמים את הרצף שלנו 
        uint32_t my_seq = seq + 1;
        char rst_pkt[4096];
//סוגר את הפורט ע"י שליחת RST
        int rst_len = build_tcp_rst_packet(
            rst_pkt, sizeof(rst_pkt),
            src_ip,          // מקור
            target_ip,       // יעד
            src_port,        // src port
            (uint16_t)port,  // dst port
            my_seq,          // seq
            my_ack           // ack_seq
        );
        if (rst_len > 0) {
                sendto(sock, rst_pkt, rst_len, 0, (struct sockaddr *)&dest, sizeof(dest));
            }

        }
        // RST => הפורט סגור
        else if (rtcp->rst == 1) {
            // בדרך כלל לא מדפיסים CLOSED כדי לא להציף 65535 שורות,
            // אבל אם את רוצה - תפתחי את השורה:
            // printf("Port %d is CLOSED (TCP)\n", port);
        }
    }

    close(sock);
}



// פונקציה שבונה ושולחת חבילת UDP
void scan_udp_port(char *target_ip, int port) {
    // 1. יצירת Socket
    // 2. בניית IP Header
    // 3. בניית UDP Header
    // 4. שליחה
    // 5. המתנה לתשובה (או Timeout)
}

// 4. Main Function
int main(int argc, char *argv[]) {
    // 1. קליטת ארגומנטים (IP וסוג סריקה)
    
    // 2. לולאה שעוברת על כל הפורטים (1 עד 65535)
    for (int i = 1; i <= 65535; i++) {
        if (scan_type == TCP) {
            scan_tcp_port(target_ip, i);
        } else {
            scan_udp_port(target_ip, i);
        }
    }
    
    return 0;
}