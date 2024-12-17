#include "dispatch.h"
#include "sniff.h"
#include "queue.h"
#include "analysis.h"
#include <pthread.h>
#include <pcap.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>

#define NUM_WORKER_THREADS 8 // constant variable denoting the number of threads we are using, matches number of cores

// structure for the work queue
static struct queue *work_queue;

// mutex lock required for shared queue
static pthread_mutex_t queue_mutex_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_not_empty_cond = PTHREAD_COND_INITIALIZER;
static pthread_t threads[NUM_WORKER_THREADS]; // 
static int terminate = 0; // boolean flag to determine whether the threadpool program should terminate

// worker function
void *handle_connection (void *arg){
  while (1){
    // lock the mutex queue 
    pthread_mutex_lock(&queue_mutex_lock);

    // while the queue is empty and we haven't received a flag to terminate the solution
    while (isempty(work_queue) && !terminate){
      // wait on a condition variable
      pthread_cond_wait(&queue_not_empty_cond, &queue_mutex_lock);
    }

    // if the queue is empty and we want to terminate looping
    if (isempty(work_queue) && terminate){
      // unlovk the mutex queue
      pthread_mutex_unlock(&queue_mutex_lock);
      break; // break out the loop
    }

    // dequeue the element from the mutex queue and unlock it
    struct packet_details *worker_item = dequeue(work_queue);
    pthread_mutex_unlock(&queue_mutex_lock);

    // process the packet
    analyse(worker_item->header, worker_item->packet, worker_item->verbose);

    // free memory allocated for packet_data structure
    free(worker_item->header);
    free(worker_item->packet);
    free(worker_item);
  }

  return NULL;
}

void handle_sigint(){
  // lock the queue mutex
  pthread_mutex_lock(&queue_mutex_lock);
  
  // terminate the program
  terminate = 1;

  // broadcast and unlock the mutex queue
  pthread_cond_broadcast(&queue_not_empty_cond);
  pthread_mutex_unlock(&queue_mutex_lock);

  // join the worker threads to ensure all tasks completed
  for (int i = 0; i < NUM_WORKER_THREADS; i++){
    pthread_join(threads[i], NULL);
  }

  // deallocate the queue
  destroy_queue(work_queue);
  
  // display the report
  viewReport();

  // close pcap properly to prevent memory leaks
  close_pcap();

  // terminate the program
  exit(0);

}

void initialise_threads(){
  // for each thread
  for (int i = 0; i < NUM_WORKER_THREADS; i++){
    // raise error if we can't create the thread
    if (pthread_create(&threads[i], NULL, handle_connection, NULL) != 0){
      perror("Failed to create worker thread");
      exit(EXIT_FAILURE);
    }
  }
}

void dispatch(struct pcap_pkthdr *header, const unsigned char *packet, int verbose) {
  static int initialised = 0;

  // initialise if not already done so
  if (!initialised){
    // handle signal interrupt
    signal(SIGINT, handle_sigint);
  
    // create the work queue
    work_queue = create_queue();

    // create worker threads
    initialise_threads();

    initialised = 1;
  }
  
  // allocate memory for packet details
  struct packet_details *pktdtls = malloc(sizeof(struct packet_details));
  if (pktdtls == NULL) {
    perror("Failed to allocate memory for packet details");
    exit(EXIT_FAILURE);
  }
  
  // assign the header
  pktdtls->header = malloc(sizeof(struct pcap_pkthdr));
  if (!pktdtls->header){
    // exit if unable to assign header
    perror("Failed to allocate memory for packet header");
    free(pktdtls);
    exit(EXIT_FAILURE);
  }
  *(pktdtls->header) = *header;

  // assign the packet data
  pktdtls->packet = malloc(header->len);
  if (!pktdtls->header){
    // exit if unable to assign data
    perror("Failed to allocate memory for packet header");
    free(pktdtls->header);
    free(pktdtls);
    exit(EXIT_FAILURE);
  }
  memcpy((void *)pktdtls->packet, (void *)packet, header->len);

  // assign the verbose
  pktdtls->verbose = verbose;

  // lock the queue and enqueue the packet details
  pthread_mutex_lock(&queue_mutex_lock);
  enqueue(work_queue, pktdtls);

  // free the packet details after added to the queue
  free(pktdtls);

  // signal that the queue is not empty
  pthread_cond_signal(&queue_not_empty_cond);
  pthread_mutex_unlock(&queue_mutex_lock);

}
