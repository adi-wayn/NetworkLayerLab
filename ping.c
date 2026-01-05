/*
 * @file ping.c
 * @version 1.0
 * @brief A simple implementation of the ping program using raw sockets.
 * @note The program sends an ICMP ECHO REQUEST packet to the destination address and waits for an ICMP ECHO REPLY packet.
*/

#include <stdio.h> // Standard input/output definitions
#include <stdlib.h> // Standard library definitions (exit, atoi)
#include <arpa/inet.h> // Definitions for internet operations (inet_pton, inet_ntoa)
#include <netinet/in.h> // Internet address family (AF_INET, AF_INET6)
#include <netinet/ip.h> // Definitions for internet protocol operations (IP header)
#include <netinet/ip_icmp.h> // Definitions for internet control message protocol operations (ICMP header)
#include <errno.h> // Error number definitions. Used for error handling (EACCES, EPERM)
#include <string.h> // String manipulation functions (strlen, memset, memcpy)
#include <sys/socket.h> // Definitions for socket operations (socket, sendto, recvfrom)
#include <sys/time.h> // Time types (struct timeval and gettimeofday)
#include <unistd.h> // UNIX standard function definitions (getpid, close, sleep)
#include <getopt.h> // Command-line argument parsing (getopt)
#include <signal.h> // Signal handling (signal, SIGINT)
#include <math.h> // Mathematical functions (sqrt)
#include "net_utils.h" // Header file for the program (calculate_checksum function and some constants)


/****************************************************************************************
 * 										CONSTANTS										*
 ****************************************************************************************/

/*
 * @brief Timeout value in milliseconds for the poll(2) function.
 * @note The poll(2) function will wait for this amount of time for the socket to become ready for reading.
 * @attention If the socket is not ready for reading after this amount of time, the function will return 0.
 * @note The default value is 2000 milliseconds (2 seconds).
*/
#define TIMEOUT 10000

/*
 * @brief The time to sleep between sending ping requests in seconds.
 * @note Default value is 1 second.
*/
#define SLEEP_TIME 1

/*
 * @brief Main function of the program.
 * @param argc Number of command-line arguments.
 * @param argv Array of command-line arguments.
 * @return 0 on success, 1 on failure.
 * @note The program requires one command-line argument: the destination IP address.
*/

volatile sig_atomic_t stop = 0;

void handle_sigint(int sig) {
    (void)sig;
    stop = 1;
}

int main(int argc, char *argv[]) {

	char *dest_ip = NULL;
	int count = -1;     // -1 = אינסופי (ברירת מחדל)
	int flood = 0;

	int opt;
	while ((opt = getopt(argc, argv, "a:c:f")) != -1) {
		switch (opt) {
			case 'a':
				dest_ip = optarg;
				break;

			case 'c':
				count = atoi(optarg);
				if (count <= 0) {
					fprintf(stderr, "Error: -c must be a positive integer\n");
					return 1;
				}
				break;

			case 'f':
				flood = 1;
				break;

			default:
				fprintf(stderr, "Usage: %s -a <ip> [-c <count>] [-f]\n", argv[0]);
				return 1;
		}
	}

	if (dest_ip == NULL) {
		fprintf(stderr, "Error: -a <ip> is required\n");
		fprintf(stderr, "Usage: %s -a <ip> [-c <count>] [-f]\n", argv[0]);
		return 1;
	}

	if (optind < argc) {
		fprintf(stderr, "Error: unexpected argument: %s\n", argv[optind]);
		fprintf(stderr, "Usage: %s -a <ip> [-c <count>] [-f]\n", argv[0]);
		return 1;
	}

	signal(SIGINT, handle_sigint);

	// Structure to store the destination address.
	// Even though we are using raw sockets, creating from zero the IP header is a bit complex,
	// we use the structure to store the destination address.
	struct sockaddr_in destination_address;

	// Just some buffer to store the ICMP packet itself. We zero it out to make sure there are no garbage values.
	char buffer[BUFFER_SIZE] = {0};

	// The payload of the ICMP packet. Can be anything, as long as it's a valid string.
	// We use some garbage characters, as well as some ASCII characters, to test the program.
	char *msg = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$^&*()_+{}|:<>?~`-=[]',.";

	// Payload size of the ICMP packet.
	// We need to add 1 to the size of the payload, as we need to include the null-terminator of the string.
	int payload_size = strlen(msg) + 1;

	// Reset the destination address structure to zero, to make sure there are no garbage values.
	// As we only need to set the IP address and the family, we can set the rest of the structure to zero.
	memset(&destination_address, 0, sizeof(destination_address));

	// We need to set the family of the destination address to AF_INET, as we are using the IPv4 protocol.
	destination_address.sin_family = AF_INET;

	// Try to convert the destination IP address from the user input to a binary format.
	// Could fail if the IP address is not valid.
	if (inet_pton(AF_INET,dest_ip, &destination_address.sin_addr) <= 0)
	{
		fprintf(stderr, "Error: \"%s\" is not a valid IPv4 address\n", dest_ip);
		return 1;
	}

	// Create a raw socket with the ICMP protocol.
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

	// Error handling if the socket creation fails (could happen if the program isn't run with sudo).
	if (sock < 0)
	{
		perror("socket(2)");

		// Check if the error is due to permissions and print a message to the user.
		// Some magic constants for the error numbers, which are defined in the errno.h header file.
		if (errno == EACCES || errno == EPERM)
			fprintf(stderr, "You need to run the program with sudo.\n");
		
		return 1;
	}

	// The sequence number of the ping request.
	// It starts at 0 and is incremented by 1 for each new request.
	// Good for identifying the order of the requests.
	int seq = 1;
	int sent = 0;
	int received = 0;

	double rtt_min = 0.0;
	double rtt_max = 0.0;
	double rtt_sum = 0.0;
	double rtt_sum_sq = 0.0;

	struct timeval program_start, program_end;
	gettimeofday(&program_start, NULL);

	fprintf(stdout, "Pinging %s with %d bytes of data:\n", dest_ip, payload_size);

	// The main loop of the program.
	while (!stop && (count == -1 || sent < count))
	{
		// Zero out the buffer to make sure there are no garbage values.
		memset(buffer, 0, sizeof(buffer));

		// Build the ICMP ECHO REQUEST packet.
		int pkt_len = build_icmp_echo_request(
			buffer, sizeof(buffer),
			(uint16_t)getpid(),
			(uint16_t)seq,
			msg, payload_size);

		// Error handling if the packet building fails.
		if (pkt_len < 0) {
			fprintf(stderr, "Failed to build ICMP packet\n");
			break;
		}

		// Increment the sequence number for the next request.		
		seq++;


		// Calculate the time it takes to send and receive the packet.
		struct timeval start, end;
		gettimeofday(&start, NULL);

		// Try to send the ICMP packet to the destination address.
		if (sendto(sock, buffer, pkt_len, 0,(struct sockaddr *)&destination_address, sizeof(destination_address)) <= 0){
			perror("sendto(2)");
			close(sock);
			return 1;
		}

		sent++;

		/* ===== receive ICMP reply using net_utils ===== */
		struct sockaddr_in source_address;
		memset(&source_address, 0, sizeof(source_address));

		int n = recv_icmp_packet(sock, buffer, sizeof(buffer),
								&source_address, TIMEOUT);

		if (n == 0) {
			fprintf(stderr, "Request timeout for icmp_seq %d, aborting.\n", seq - 1);
			break;
		}
		if (n == -2) {
			/* Interrupted by Ctrl+C (EINTR) */
			break;
		}
		if (n < 0) {
			perror("recv_icmp_packet");
			close(sock);
			return 1;
		}

		/* We got a packet */
		gettimeofday(&end, NULL);

		/* Parse headers */
		struct iphdr *ip_header;
		struct icmphdr *icmp_header;
		parse_ip_icmp(buffer, &ip_header, &icmp_header);

		/* Handle reply */
		if (icmp_header->type == ICMP_ECHOREPLY) {
			float pingPongTime = ((float)(end.tv_usec - start.tv_usec) / 1000) +
								((end.tv_sec - start.tv_sec) * 1000);
			received++;

			rtt_sum += pingPongTime;
			rtt_sum_sq += pingPongTime * pingPongTime;
			if (received == 1) {
				rtt_min = pingPongTime;
				rtt_max = pingPongTime;
			} else {
				if (pingPongTime < rtt_min) rtt_min = pingPongTime;
				if (pingPongTime > rtt_max) rtt_max = pingPongTime;
			}

			fprintf(stdout, "%ld bytes from %s: icmp_seq=%d ttl=%d time=%.2fms\n",
					(ntohs(ip_header->tot_len) - (ip_header->ihl * 4) - sizeof(struct icmphdr)),
					inet_ntoa(source_address.sin_addr),
					ntohs(icmp_header->un.echo.sequence),
					ip_header->ttl,
					pingPongTime);
		}
		else {
			fprintf(stderr, "ICMP error from %s: type=%d code=%d (unreachable/other)\n",
					inet_ntoa(source_address.sin_addr),
					icmp_header->type,
					icmp_header->code);
			break;
		}

		// Sleep for 1 second before sending the next request.
		if (!flood)
			sleep(SLEEP_TIME);
	}

	gettimeofday(&program_end, NULL);

	double total_time_ms =
		(program_end.tv_sec - program_start.tv_sec) * 1000.0 +
		(program_end.tv_usec - program_start.tv_usec) / 1000.0;

	int loss = sent - received;
	double loss_percent = (sent > 0) ? ((double)loss / sent) * 100.0 : 0.0;
	double avg_rtt = (received > 0) ? (rtt_sum / received) : 0.0;

	double mdev = 0.0;
	if (received > 0) {
		double mean = avg_rtt;
		double variance = (rtt_sum_sq / received) - (mean * mean);
		if (variance < 0) variance = 0;  // בגלל floating point errors
		mdev = sqrt(variance);
	}


	printf("\n--- %s ping statistics ---\n", dest_ip);
	printf("%d packets transmitted, %d received, %.1f%% packet loss, time %.2fms\n",
		sent, received, loss_percent, total_time_ms);

	if (received > 0) {
		printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3fms\n",
       rtt_min, avg_rtt, rtt_max, mdev);
	}

	// Close the socket and return 0 to the operating system.
	close(sock);

	return 0;
}