#include "analysis.h"
#include "dispatch.h"

#include <pthread.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <stdlib.h>
#include <string.h> // to access strstr

// mutex locks for shared variables
static pthread_mutex_t syn_count_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t arp_responses_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t google_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t bbc_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t ip_list_lock = PTHREAD_MUTEX_INITIALIZER;

// shared variables
static int synCount = 0;
static int arpResponses = 0;
static int google = 0;
static int bbc = 0;
static int ipListSize = 0; // acts as a pointer to current value
static int ipListCapacity = 8; // default capacity
static uint32_t *ipList = NULL;


void initialiseIPList(){
  // create the IP list if haven't already
  if (ipList == NULL){
    ipList = (uint32_t *) calloc(ipListCapacity, sizeof(uint32_t));
  }
}

void resizeIPList(){
  ipListCapacity *= 2; // double the capacity
  ipList = (uint32_t *) realloc(ipList, ipListCapacity * sizeof(uint32_t)); // resize the ip list
}

int isUniqueIP(uint32_t sourceAddress){
  // return false if the ip address is already in the list
  for (int i = 0; i < ipListSize; i++){
    if (ipList[i] == sourceAddress){
      return 0;
    }
  }

  // return true otherwise
  return 1;
}

void viewReport(){
  // print out the intrusion detection 
  printf("\nIntrusion Detection Report:");
  printf("\n%d SYN packets detected from %d different IPs (syn attack)", synCount, ipListSize);
  printf("\n%d ARP responses (cache poisoning)", arpResponses);
  printf("\n%d URL Blacklist violations (%d google and %d bbc)", google + bbc, google, bbc);

  // free allocated memory
  free(ipList);

}

void dumpData(struct tcphdr *tcp_hdr, struct ip *ip_hdr){
  // tcp header
  printf(" === TCP Information ===");
  printf("\nSource Port: %d | ", ntohs(tcp_hdr->source));
  printf("Desintation Port: %d", ntohs(tcp_hdr->dest));
  printf("\nSequence Number: %u", ntohl(tcp_hdr->seq));
  printf("\nAcknowledgement Number: %u", ntohl(tcp_hdr->ack_seq));
  printf("\nData Offset: %d | ", tcp_hdr->doff);
  printf("Reserved: %d | ", tcp_hdr->res1);
  printf("Window: %d", tcp_hdr->window);
  printf("\nFIN: %d | ", tcp_hdr->fin);
  printf("SYN: %d | ", tcp_hdr->syn);
  printf("RST: %d | ", tcp_hdr->rst);
  printf("PSH: %d | ", tcp_hdr->psh);
  printf("ACK: %d | ", tcp_hdr->ack);
  printf("URG: %d", tcp_hdr->urg);
  printf("\nChecksum: %d | ", tcp_hdr->check);
  printf("Urgent Pointer: %d", tcp_hdr->urg_ptr);

  // ip header
  printf("\n === IP Information ===");
  printf("\nVersion: %d | ", ip_hdr->ip_v);
  printf("IHL: %d | ", ip_hdr->ip_hl);
  printf("Type of Service: %d | ", ip_hdr->ip_tos);
  printf("Total Length: %d", ip_hdr->ip_len);
  printf("\nIdentification: %d | ", ip_hdr->ip_id);
  printf("Fragment Offset: %d", ip_hdr->ip_off);
  printf("\nTime to Live: %d | ", ip_hdr->ip_ttl);
  printf("Protocol: %d | ", ip_hdr->ip_p);
  printf("Header Checksum: %d", ntohs(ip_hdr->ip_sum));
  printf("\nSource Address: %s", inet_ntoa(ip_hdr->ip_src));
  printf("\nDesination Address: %s", inet_ntoa(ip_hdr->ip_dst));
}


int checkSYN(struct tcphdr *tcp_hdr){
  // store the appropriate values for syn
  int fin = tcp_hdr->fin;  
  int syn = tcp_hdr->syn;
  int rst = tcp_hdr->rst;
  int psh = tcp_hdr->psh;
  int ack = tcp_hdr->ack;
  int urg = tcp_hdr->urg;
  
  // check if the syn is active and all other flags are inactive
  if (syn && !fin && !rst && !psh && !ack && !urg){
    return 1;
  }
  // return 0 (false) if it isn't an syn attack
  return 0;
}



void analyse(struct pcap_pkthdr *header, const unsigned char *packet, int verbose) {
  // lock the ip list in the critical region
  pthread_mutex_lock(&ip_list_lock);
  initialiseIPList(); // create the IP list if it hasn't already been done
  pthread_mutex_unlock(&ip_list_lock);

  // store the ether, tcp and ip data in relevant packets
  struct ether_header *eth_hdr = (struct ether_header *) packet;
  struct ip *ip_hdr = (struct ip *) (packet + ETH_HLEN);
  struct tcphdr *tcp_hdr = (struct tcphdr *) (packet + ETH_HLEN + (ip_hdr->ip_hl * 4));

  // dump the data to the terminal if the verbose is on
  if (verbose){
    dumpData(tcp_hdr, ip_hdr);
  }

  // if we detect an SYN attack
  if (checkSYN(tcp_hdr)){
    // lock the variables in the syn count critical region
    pthread_mutex_lock(&syn_count_lock);
    synCount++; // increment the attack counter
    pthread_mutex_unlock(&syn_count_lock);

    // store the source address
    uint32_t sourceAddress = ip_hdr -> ip_src.s_addr;
    
    // lock the ip list in the critical region
    pthread_mutex_lock(&ip_list_lock);

    // if it is a unique IP address
    if (isUniqueIP(sourceAddress)){
      // check if the list is full
      if (ipListSize >= ipListCapacity){
        // resize the list
        resizeIPList();
      }
      
      ipList[ipListSize] = sourceAddress; // add it to the list
      ipListSize++; // increment the list size
    }

    // unlock data now leaving critical region
    pthread_mutex_unlock(&ip_list_lock);
  }
  
  // if we detect arp cache poisoning
  if (ntohs(eth_hdr -> ether_type) == ETH_P_ARP){
    // lock the variables in the critical region
    pthread_mutex_lock(&arp_responses_lock);
    arpResponses++; // increment the arp responses variable
    pthread_mutex_unlock(&arp_responses_lock);
  }
  
  
  // if we detect blacklisted urls
  if (ntohs(tcp_hdr->dest) == 80){
    // decode packet data skipping header
    const unsigned char *payload = packet + ETH_HLEN + (ip_hdr->ip_hl * 4) + (tcp_hdr->doff * 4); // point to the start of the non-header data
    int payloadSize = (header->len) - ETH_HLEN - (ip_hdr->ip_hl * 4) - (tcp_hdr->doff * 4); // how many bytes of data sub header

    // return if no payload to process
    if (payloadSize <= 0){
      return;
    }
    
    // string to read contents from packet
    char *dataContent  = (char *) malloc(payloadSize + 1);
    // exit if unable to allocate memory
    if (!dataContent){
      perror("Failed to allocate memory for payload data");
      exit(EXIT_FAILURE);
    }
    
    // print data in ascii form
    int endOfString = 0;
    for (int i = 0; i < payloadSize; ++i) {
      char byte = payload[i];
      if (byte > 31 && byte < 127){
        dataContent[endOfString] = byte;
        endOfString++;
      }
    }

    // add exit character to string
    dataContent[endOfString] = '\0';
    
    if (strstr(dataContent, "www.google.co.uk")){
      // print that a violation is detected
      if (verbose){
        printf("\n==============================");
        printf("\nBlacklisted URL violation detected");
        printf("\nSource IP address: %s", inet_ntoa(ip_hdr->ip_src));
        printf("\nDesination IP address: %s (google)", inet_ntoa(ip_hdr->ip_dst));
        printf("\n==============================");
      }
      
      // lock the variables in the google blacklisted critical region
      pthread_mutex_lock(&google_lock);
      google++; // increment the google count
      pthread_mutex_unlock(&google_lock);
    }


    if ( strstr(dataContent, "www.bbc.co.uk")){
      if (verbose){
        printf("\n==============================");
        printf("\nBlacklisted URL violation detected");
        printf("\nSource IP address: %s", inet_ntoa(ip_hdr->ip_src));
        printf("\nDesination IP address: %s (bbc)", inet_ntoa(ip_hdr->ip_dst));
        printf("\n==============================");
      }
      
      // lock the variables in the bbc blacklisted critical region
      pthread_mutex_lock(&bbc_lock);
      bbc++; // increment the bbc count
      pthread_mutex_unlock(&bbc_lock);
    }

    free(dataContent);

  }
}