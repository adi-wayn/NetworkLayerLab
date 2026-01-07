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
    if (sock < 0) {
        perror("Socket creation failed");
        return;
    }
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt IP_HDRINCL failed");
        close(sock);
        return;
    }
    // הגדרת כתובת היעד
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    inet_pton(AF_INET, target_ip, &dest.sin_addr);

    // באפר (Buffer) להחזקת החבילה
    char packet[4096];
    memset(packet, 0, 4096);

    // מצביעים לכותרות בתוך הבאפר
    struct iphdr *iph = (struct iphdr *) packet;
    struct tcphdr *tcph = (struct tcphdr *) (packet + sizeof(struct iphdr));

    // 2. בניית IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->id = htons(54321); // סתם מספר מזהה
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0; // בינתיים 0, נחשב בסוף
    iph->saddr = NULL; // נשתמש בכתובת IP של המחשב שלנו
    iph->daddr = dest.sin_addr.s_addr;

    // חישוב Checksum ל-IP
    iph->check = checksum((unsigned short *)packet,sizeof(struct iphdr));

    // 3. בניית TCP Header (עם דגל SYN)
    tcph->source = htons(12345); // פורט מקור אקראי
    tcph->dest = htons(port);
    tcph->seq = htonl(random());
    tcph->ack_seq = 0;
    tcph->doff = 5; // גודל ה-Header
    tcph->fin = 0;
    tcph->syn = 1; // *** הדלקת דגל SYN - דפיקה בדלת ***
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons(5840); /* Maximum window size */
    tcph->check = 0; // בינתיים 0
    tcph->urg_ptr = 0;

    // 4. חישוב TCP Checksum (דורש Pseudo Header)
    struct pseudo_header psh;
    psh.source_address = NULL;
    psh.dest_address = dest.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    char *pseudogram = malloc(psize);

    memcpy(pseudogram, (char*) &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));

    tcph->check = checksum((unsigned short*) pseudogram, psize);
    free(pseudogram);

    // 5. שליחת החבילה
    if (sendto(sock, packet, iph->tot_len, 0, (struct sockaddr *) &dest, sizeof(dest)) < 0) {
        perror("Sendto failed");
        close(sock);
        return;
    }
    // 5. המתנה לתשובה וניתוח שלה (SYN-ACK או RST)
    char buffer[4096];
    struct sockaddr_in saddr;
    socklen_t saddr_size = sizeof(saddr);
    
    // נשתמש ב-poll או פשוט נגדיר timeout ב-setsockopt (לפשטות כאן נשתמש בלולאה פשוטה עם recv)
    // הגדרת זמן המתנה (Timeout) של שנייה אחת
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    int data_size = recvfrom(sock, buffer, 4096, 0, (struct sockaddr*)&saddr, &saddr_size);
    if (data_size < 0) {
    perror("recvfrom");
    }
    if (data_size > 0) {
        // פירוק התשובה
        struct iphdr *recv_iph = (struct iphdr *)buffer;
        struct tcphdr *recv_tcph = (struct tcphdr *)(buffer + (recv_iph->ihl * 4));

        // בדיקה אם התשובה היא מהפורט שסרקנו
        if (saddr.sin_addr.s_addr == dest.sin_addr.s_addr && ntohs(recv_tcph->source) == port) {
            // אם קיבלנו SYN ו-ACK (הפורט פתוח)
            if (recv_tcph->syn == 1 && recv_tcph->ack == 1) {
                printf("Port %d is OPEN (TCP)\n", port);
                
                // שלב בונוס: שליחת RST לסגירת החיבור (כמו שביקשו במטלה)
                // כאן תוכלי להוסיף קוד ששולח חזרה חבילת RST, אבל ההדפסה היא העיקר.
            } else if (recv_tcph->rst == 1) {
                // הפורט סגור
                printf("Port %d is CLOSED (TCP)\n", port);

            }
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