# Simple Pcap Filter
#### A C program with libpcap that can load .pcap file and filter with BPF Syntax

## Compilation
```
make
```

## Usage
``` bash
filter <file.pcap> [BPF Syntax]
```

## Detail
#### Read file
pcap_open_offline() can read file path directly, and if error occur, the message will be store in errbuf.

```c
pcap_t *pcap_open_offline(const char *fname, char *errbuf);
```
```c
...
#include <pcap/pcap.h>
...

char errbuf[PCAP_ERRBUF_SIZE];
pcap_t *handle = pcap_open_offline(filename, errbuf);
```

#### Compile BPF

```c
int pcap_compile(pcap_t *p, struct bpf_program *fp, const char *str, int optimize, bpf_u_int32 netmask);
```
```c
...
#include <pcap/pcap.h>
...

struct bpf_program fp;
pcap_compile(handle, &fp, bpf_syntax, 1, PCAP_NETMASK_UNKNOWN)
```

#### Apply BPF filter

```c
int pcap_setfilter(pcap_t *p, struct bpf_program *fp);
```
```c
...
#include <pcap/pcap.h>
...

pcap_setfilter(handle, &fp)
```

#### Iterate Packets

```c
int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user);
```
```c
...
#include <pcap/pcap.h>
...

pcap_loop(handle, -1, packet_handler, NULL)
```

#### Callback Function
```c
typedef void (*pcap_handler)(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
```

#### Struct pcap_pkthdr
```c
struct pcap_pkthdr {
	struct timeval ts;	/* time stamp */
	bpf_u_int32 caplen;	/* length of portion present */
	bpf_u_int32 len;	/* length this packet (off wire) */
};
```

#### Get Time
```c
...
#include <pcap/pcap.h>
...

struct tm *local_time;
char timestr[TIMESTR_LEN];
time_t local_tv_sec;

local_tv_sec = header->ts.tv_sec;
local_time = localtime(&local_tv_sec);
strftime(timestr, sizeof timestr, "%Y-%m-%d %H:%M:%S", local_time);
```

#### Get Time
```c
...
#include <pcap/pcap.h>
...

struct tm *local_time;
char timestr[TIMESTR_LEN];
time_t local_tv_sec;

local_tv_sec = header->ts.tv_sec;
local_time = localtime(&local_tv_sec);
strftime(timestr, sizeof timestr, "%Y-%m-%d %H:%M:%S", local_time);
```

####
```c
...
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
...

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
```