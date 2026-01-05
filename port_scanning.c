// 1. Includes
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>


// 2. Defines & Structs
// כאן תגדירי קבועים וגם את מבנה ה-Pseudo Header לחישוב Checksum של TCP/UDP

// 3. Helper Functions (פונקציות עזר)
unsigned short checksum(void *b, int len) {
    // העתק-הדבק מנספח C במטלה או מימוש עצמאי
}

// פונקציה שבונה ושולחת חבילת TCP SYN
void scan_tcp_port(char *target_ip, int port) {
    // 1. יצירת Socket
    // 2. בניית IP Header
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