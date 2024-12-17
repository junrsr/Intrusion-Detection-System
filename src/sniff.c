#include "sniff.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>

#include "dispatch.h"

static pcap_t *pcap_handle = NULL;

void got_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet){
  // If verbose is set to 1, dump raw packet to terminal
  int verbose = *(int*) args;
  if (verbose) {
    dump(packet, header->len);
  }
  // Dispatch packet for processing
  dispatch((struct pcap_pkthdr *)header, packet, verbose);
}

void close_pcap(){
  // close pcap handle effectively
  pcap_close(pcap_handle);
}


// Application main sniffing loop
void sniff(char *interface, int verbose) {
  
  char errbuf[PCAP_ERRBUF_SIZE];

  // Open the specified network interface for packet capture. pcap_open_live() returns the handle to be used for the packet
  // capturing session. check the man page of pcap_open_live()
  pcap_handle = pcap_open_live(interface, 4096, 1, 1000, errbuf);
  if (pcap_handle == NULL) {
    fprintf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
  } else {
    printf("SUCCESS! Opened %s for capture\n", interface);
  }

  // Capture packet one packet everytime the loop runs using pcap_next(). This is inefficient.
  // A more efficient way to capture packets is to use use pcap_loop() instead of pcap_next().
  // See the man pages of both pcap_loop() and pcap_next().

  if (pcap_loop(pcap_handle, -1, got_packet, (unsigned char*) &verbose) < 0){
      printf("No packet received. %s\n", pcap_geterr(pcap_handle)); 
  }
}

// Utility/Debugging method for dumping raw packet data
void dump(const unsigned char *data, int length) {
  unsigned int i;
  static unsigned long pcount = 0;
  // Decode Packet Header
  struct ether_header *eth_header = (struct ether_header *) data;

  printf("\n\n === PACKET %ld HEADER ===", pcount);
  printf("\nSource MAC: ");
  for (i = 0; i < 6; ++i) {
    // ether_shost[i] refers to each individual byte -> displays it in hexadecimal format
    printf("%02x", eth_header->ether_shost[i]);
    if (i < 5) {
      printf(":");
    }
  }

  printf("\nDestination MAC: ");
  for (i = 0; i < 6; ++i) {
    // prints all 6 bytes for destination MAC address
    printf("%02x", eth_header->ether_dhost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nType: %hu\n", eth_header->ether_type);
  printf(" === PACKET %ld DATA == \n", pcount);

  // Decode Packet Data (Skipping over the header)
  int data_bytes = length - ETH_HLEN; // how many bytes of data sub header
  const unsigned char *payload = data + ETH_HLEN; // point to the start of the non-header data
  const static int output_sz = 20; // Output this many bytes at a time

  while (data_bytes > 0) {
    // output bytes is the smaller between output bytes and data bytes
    int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
    // Print data in raw hexadecimal form
    for (i = 0; i < output_sz; ++i) {
      if (i < output_bytes) {
        printf("%02x ", payload[i]);
      } else {
        printf ("   "); // Maintain padding for partial lines
      }
    }
    printf ("| ");
    // Print data in ascii form
    for (i = 0; i < output_bytes; ++i) {
      char byte = payload[i];
      if (byte > 31 && byte < 127) {
        // Byte is in printable ascii range
        printf("%c", byte);
      } else {
        printf(".");
      }
    }

    printf("\n");
    // point to next bit of unanalysed data
    payload += output_bytes;
    data_bytes -= output_bytes;
  }
  pcount++;
}
