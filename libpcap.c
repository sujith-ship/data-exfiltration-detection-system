#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <mysql/mysql.h>
#include <netdb.h> // Include netdb.h for addrinfo

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethhdr *eth_header;
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    time_t timestamp;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    char dst_host[100];
    int src_port, dst_port;
    char protocol[4];
    char query[1024];
    MYSQL *conn;
   
    // Get the timestamp
    timestamp = header->ts.tv_sec;
    char date_str[11];
    strftime(date_str, sizeof(date_str), "%Y-%m-%d", localtime(&timestamp));

    // Get the Ethernet header
    eth_header = (struct ethhdr *)packet;

    // Get the IP header
    ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));

    // Get the source and destination IP addresses
    inet_ntop(AF_INET, &(ip_header->saddr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->daddr), dst_ip, INET_ADDRSTRLEN);

    // Resolve the IP addresses to hostnames
    struct addrinfo hints = {0}; // Initialize hints
    hints.ai_family = AF_INET; // Set address family to IPv4
    hints.ai_socktype = SOCK_STREAM; // Set socket type to stream

    struct addrinfo *dst_peer;
    if (getaddrinfo(dst_ip, "0", &hints, &dst_peer) != 0) {
        printf("getaddrinfo error for dst IP!\n");
        return;
    }

    if (dst_peer != NULL) {
        getnameinfo(dst_peer->ai_addr, dst_peer->ai_addrlen, dst_host, sizeof(dst_host), NULL, 0, NI_NAMEREQD);
        freeaddrinfo(dst_peer);
    } else {
        printf("dst_peer is NULL\n");
        return;
    }

    // Determine the protocol and ports
    if (ip_header->protocol == IPPROTO_TCP) {
        strcpy(protocol, "tcp");
        // Get the TCP header
        tcp_header = (struct tcphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));

        src_port = ntohs(tcp_header->source);
        dst_port = ntohs(tcp_header->dest);

        // Calculate packet length
        int length = header->len;

        // Prepare the SQL statement for TCP packets
        snprintf(query, sizeof(query), "INSERT INTO TRAFFIC1 (date, src_ip, dst_ip, dst_host, protocol, src_port_id, dst_port_id, length) VALUES ('%s', '%s', '%s', '%s', '%s', %d, %d, %d)",
                 date_str, src_ip, dst_ip, dst_host, protocol, src_port, dst_port, length);

    } else if (ip_header->protocol == IPPROTO_UDP) {
        strcpy(protocol, "udp");
        // Get the UDP header
        udp_header = (struct udphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));

        src_port = ntohs(udp_header->source);
        dst_port = ntohs(udp_header->dest);

        // Calculate packet length
        int length = header->len;

        // Prepare the SQL statement for UDP packets
        snprintf(query, sizeof(query), "INSERT INTO TRAFFIC1 (date, src_ip, dst_ip, dst_host, protocol, src_port_id, dst_port_id, length) VALUES ('%s', '%s', '%s', '%s', '%s', %d, %d, %d)",
                 date_str, src_ip, dst_ip, dst_host, protocol, src_port, dst_port, length);
    }

    // Connect to the MySQL database
    conn = mysql_init(NULL);
    if (!conn) {
        fprintf(stderr, "Error initializing MySQL connection: %s\n", mysql_error(conn));
        return;
    }

    if (!mysql_real_connect(conn, "localhost", "root", "root123", "TRAFFIC_NETWORK", 0, NULL, 0)) {
       fprintf(stderr, "Error connecting to the database: %s\n", mysql_error(conn));
        mysql_close(conn);
        return;
    }

    // Execute the SQL statement
    if (mysql_query(conn, query)) {
        fprintf(stderr, "Error inserting data into the database: %s\n", mysql_error(conn));
    }

    // Close the database connection
    mysql_close(conn);
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Set the interface to "enp1s0"
    char *interface = "enp1s0";

    // Open the interface for live capture
    handle = pcap_open_live(interface, 65535, 1, 100, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
        return 1;
    }

    // Set the filter expression for desired ports and protocols
    char filter_exp[] = "tcp and port 22 or port 3389 or port 389 or port 2049 or port 3306 or port 1812 or port 69 or port 161 or port 139 or port 548 or port 445 or port 3260 or port 3261 or port 135 or port 20 or port 21 or port 23 or port 80 or port 8080 or port 433 or port 161 or port 110 or port 143 or port 67 or port 68 or port 53 or port 69 or port 161 or port 5800 or port 5900";
   
    struct bpf_program fp;

    // Compile the filter expression
    if (pcap_compile(handle, &fp, filter_exp, 0, 0) == -1) {
        fprintf(stderr, "pcap_compile() failed: %s\n", pcap_geterr(handle));
        return 1;
    }

    // Set the filter
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "pcap_setfilter() failed: %s\n", pcap_geterr(handle));
        return 1;
    }

    // Loop through the packets and process them with got_packet
    pcap_loop(handle, -1, got_packet, NULL);

    // Clean up
    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}