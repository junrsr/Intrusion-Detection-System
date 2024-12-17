#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pcap.h>

struct packet_details {
  struct pcap_pkthdr *header;
  unsigned char *packet;
  int verbose;
};

void dispatch(struct pcap_pkthdr *header, 
              const unsigned char *packet,
              int verbose);

#endif
