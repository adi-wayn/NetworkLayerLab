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
#include <poll.h> // Poll API for monitoring file descriptors (poll)
#include <errno.h> // Error number definitions. Used for error handling (EACCES, EPERM)
#include <string.h> // String manipulation functions (strlen, memset, memcpy)
#include <sys/socket.h> // Definitions for socket operations (socket, sendto, recvfrom)
#include <sys/time.h> // Time types (struct timeval and gettimeofday)
#include <unistd.h> // UNIX standard function definitions (getpid, close, sleep)
#include <getopt.h> // Command-line argument parsing (getopt)
#include <signal.h> // Signal handling (signal, SIGINT)
#include <math.h> // Mathematical functions (sqrt)
#include "ping.h" // Header file for the program (calculate_checksum function and some constants)

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

	// Create an ICMP header structure and set the fields to the desired values.
	struct icmphdr icmp_header;

	// Set the type of the ICMP packet to ECHO REQUEST (PING).
	icmp_header.type = ICMP_ECHO;

	// Set the code of the ICMP packet to 0 (As it isn't used in the ECHO type).
	icmp_header.code = 0;

	// Set the ping identifier to the process ID of the program.
	// This field is used to identify the ping request.
	// Each program has a different process ID, so it's a good value to use.
	icmp_header.un.echo.id = htons(getpid());

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

	// Create a pollfd structure to wait for the socket to become ready for reading.
	// Used for receiving the ICMP reply packet, as it may take some time to arrive or not arrive at all.
	struct pollfd fds[1];

	// Set the file descriptor of the socket to the pollfd structure.
	fds[0].fd = sock;

	// Set the events to wait for to POLLIN, which means the socket is ready for reading.
	fds[0].events = POLLIN;

	fprintf(stdout, "Pinging %s with %d bytes of data:\n", dest_ip, payload_size);

	// The main loop of the program.
	while (!stop && (count == -1 || sent < count))
	{
		// Zero out the buffer to make sure there are no garbage values.
		memset(buffer, 0, sizeof(buffer));

		// Set the sequence number of the ping request, and update the value for the next request.
		icmp_header.un.echo.sequence = htons(seq++);

		// Set the checksum of the ICMP packet to 0, as we need to calculate it.
		icmp_header.checksum = 0;

		// Copy the ICMP header structure to the buffer.
		memcpy(buffer, &icmp_header, sizeof(icmp_header));

		// Copy the payload of the ICMP packet to the buffer.
		memcpy(buffer + sizeof(icmp_header), msg, payload_size);

		// Calculate the checksum of the ICMP packet.
		icmp_header.checksum = calculate_checksum(buffer, sizeof(icmp_header) + payload_size);

		// Set the checksum of the ICMP packet to the calculated value.
		// Instead of using the memcpy function, we can just set the value directly.
		struct icmphdr *pckt_hdr = (struct icmphdr *)buffer;
		pckt_hdr->checksum = icmp_header.checksum;

		// Calculate the time it takes to send and receive the packet.
		struct timeval start, end;
		gettimeofday(&start, NULL);

		// Try to send the ICMP packet to the destination address.
		if (sendto(sock, buffer, (sizeof(icmp_header) + payload_size), 0, (struct sockaddr *)&destination_address, sizeof(destination_address)) <= 0)
		{
			perror("sendto(2)");
			close(sock);
			return 1;
		}

		sent++;

		// Poll the socket to wait for the ICMP reply packet.
		int ret = poll(fds, 1, TIMEOUT);

		// The poll(2) function returns 0 if the socket is not ready for reading after the timeout.
		if (ret == 0){
			fprintf(stderr, "Request timeout for icmp_seq %d, aborting.\n", seq - 1);
			break;
		}

		// The poll(2) function returns a negative value if an error occurs.
		else if (ret < 0){
			if (errno == EINTR) {
				// poll was interrupted by SIGINT (Ctrl+C)
				break;
			}
			perror("poll(2)");
			close(sock);
			return 1;
		}

		// Now we need to check if the socket actually has data to read.
		if (fds[0].revents & POLLIN)
		{
			// Temporary structure to store the source address of the ICMP reply packet.
			struct sockaddr_in source_address;

			// Zero out the buffer and the source address structure to make sure there are no garbage values.
			memset(buffer, 0, sizeof(buffer));
			memset(&source_address, 0, sizeof(source_address));

			// Try to receive the ICMP reply packet from the destination address.
			// Shouldn't fail, as we already checked if the socket is ready for reading.
			if (recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&source_address, &(socklen_t){sizeof(source_address)}) <= 0)
			{
				perror("recvfrom(2)");
				close(sock);
				return 1;
			}

			// Calculate the time it takes to send and receive the packet.
			gettimeofday(&end, NULL);

			// Start to extract the IP header and the ICMP header from the received packet.
			struct iphdr *ip_header = (struct iphdr *)buffer;

			// ICMP header is located after the IP header, so we need to skip the IP header.
			// IP header size is determined by the ihl field, which is the first 4 bits of the header.
			// The ihl field is the number of 32-bit words in the header, so we need to multiply it by 4 to get the size in bytes.
			struct icmphdr *icmp_header = (struct icmphdr *)(buffer + ip_header->ihl * 4);

			// Check if the ICMP packet is an ECHO REPLY packet.
			// We may receive other types of ICMP packets, so we need to check the type field.
			if (icmp_header->type == ICMP_ECHOREPLY)
			{
				// Calculate the time it takes to send and receive the packet.
				float pingPongTime = ((float)(end.tv_usec - start.tv_usec) / 1000) + ((end.tv_sec - start.tv_sec) * 1000);
				received++;

				rtt_sum += pingPongTime;
				rtt_sum_sq += pingPongTime * pingPongTime;
				if (received == 1) {
					rtt_min = pingPongTime;
					rtt_max = pingPongTime;
				}
				else {
					if (pingPongTime < rtt_min) rtt_min = pingPongTime;
					if (pingPongTime > rtt_max) rtt_max = pingPongTime;
				}


				// Print the result of the ping request.
				// The result includes the number of bytes received (the payload size),
				// the destination IP address, the sequence number, the TTL value, and the time it takes to send and receive the packet.
				fprintf(stdout, "%ld bytes from %s: icmp_seq=%d ttl=%d time=%.2fms\n",
						(ntohs(ip_header->tot_len) - (ip_header->ihl * 4) - sizeof(struct icmphdr)), 
						inet_ntoa(source_address.sin_addr),
						ntohs(icmp_header->un.echo.sequence),
						ip_header->ttl, 
						pingPongTime);
			}

			// If the ICMP packet isn't an ECHO REPLY packet, we need to print an error message.
			else {
				fprintf(stderr, "ICMP error from %s: type=%d code=%d (unreachable/other)\n",
					inet_ntoa(source_address.sin_addr),
					icmp_header->type,
					icmp_header->code);
				break;
			}
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