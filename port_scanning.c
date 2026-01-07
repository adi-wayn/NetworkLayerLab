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
    iph->saddr = inet_addr("1.2.3.4"); // הערה: עדיף להשיג את ה-IP האמיתי שלך, אבל לצורך התרגיל זה עשוי לעבוד או לדרוש IP אמיתי
    iph->daddr = dest.sin_addr.s_addr;

    // חישוב Checksum ל-IP
    iph->check = checksum((unsigned short *) packet, iph->tot_len);
    // 3. בניית TCP Header (עם דגל SYN)
    // 4. שליחה
    // 5. המתנה לתשובה וניתוח שלה (SYN-ACK או RST)
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