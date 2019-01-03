#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#define TIMESTR_LEN 50

char *msg_usage = "usage:\n"
    "\tfilter <file.pcap> [BPF Syntax]\n";

void packet_handler(u_char *arg, const struct pcap_pkthdr *header, const u_char *content){

    // Convert timestamp to format string
    struct tm *local_time;
    char timestr[TIMESTR_LEN];
    time_t local_tv_sec;
    
    local_tv_sec = header->ts.tv_sec;
    local_time = localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "%Y-%m-%d %H:%M:%S", local_time);
    
    // Get Address Info
    const struct ether_header *ethernetHeader;
    const struct ip *ipHeader;
    const struct tcphdr *tcpHeader;
    char sourceIp[INET_ADDRSTRLEN], destIp[INET_ADDRSTRLEN];
    u_int sourcePort, destPort;
    // Get Ethernet Header
    ethernetHeader = (struct ether_header *)content;
    // If this is an IP Packet, get ip header
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
        ipHeader = (struct ip *)(content + sizeof(struct ether_header));
        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);
        // If this is a TCP Packet, get TCP Header
        if (ipHeader->ip_p == IPPROTO_TCP) {
            tcpHeader = (struct tcphdr *)(content + sizeof(struct ether_header) + sizeof(struct ip));
            sourcePort = ntohs(tcpHeader->th_sport);
            destPort = ntohs(tcpHeader->th_dport);
        }
        else return;
    }
    else return;

    // Output
    printf("------ Packet ------\n"
    "Time: %s\n"
    "Length: %d bytes\n"
    "Captured length: %d bytes\n"
    "Source IP: %s\n"
    "Source Port: %d\n"
    "Destination IP: %s\n"
    "Destination Port: %d\n"
    "\n",
    timestr, header->len, header->caplen, sourceIp, sourcePort, destIp, destPort);
}

int main(int argc, char *argv[]) {
    // Check Arguments
    if(argc < 2 || argc >3) {
        fprintf(stderr, "%s", msg_usage);
        exit(EXIT_FAILURE);
    }

    // Map Arguments
    char *filename = argv[1];
    char *bpf_syntax = "";
    if(argc == 3) bpf_syntax = argv[2];

    // Read file
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(filename, errbuf);
    if(!handle) {
        fprintf(stderr, "Cannot load %s\n" , errbuf);
        exit(EXIT_FAILURE);
    }

    // Compile BPF filter
    struct bpf_program fp;
    if(pcap_compile(handle, &fp, bpf_syntax, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Cannot compile BPF: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        exit(1);
    }
    
    // Apply the compiled filter
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Cannot apply filter %s: %s\n", bpf_syntax, pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }

    // Iterate Packets
    if(pcap_loop(handle, -1, packet_handler, NULL) == -1){
        fprintf(stderr, "pcap_loop(): %s", pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        exit(1);
    }
    puts("------ END ------");

    // Free Memory
    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}
