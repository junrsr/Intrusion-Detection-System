#include <stdio.h>
#include <stdlib.h>
#include "queue.h"
#include "dispatch.h"

struct queue *create_queue(void){
  struct queue *q=(struct queue *)malloc(sizeof(struct queue)); // create a queue structure
  // set the head and tail to null by default
  q->head=NULL;
  q->tail=NULL;
  return(q); // return its pointer
}

void destroy_queue(struct queue *q){
  // whiel the queue is empty
  while(!isempty(q)){
    // dequeue every item and free memory
    struct packet_details *item = dequeue(q);
    free(item->header);
    free(item->packet);
    free(item);
  }
  // free memory for the queue itself
  free(q);
}

int isempty(struct queue *q){
  // check if the  queue is empty
  return(q->head==NULL);
}

void enqueue(struct queue *q, struct packet_details *item){
  // create a new node to enqueue
  struct node *new_node=(struct node *)malloc(sizeof(struct node));
  
  // assign a deep copy of the packet details structure to the new node
  new_node->item=(struct packet_details *) malloc (sizeof (struct packet_details));
  *(new_node -> item) = *item;

  // set the next element for the new node to be null
  new_node->next=NULL;
  
  // set the head and tail to the new node if the queue is empty
  if(isempty(q)){
    q->head=new_node;
    q->tail=new_node;
  }
  // add the new node to the tail of the queue
  else{
    q->tail->next=new_node;
    q->tail=new_node;
  }
}

struct packet_details *dequeue(struct queue *q){
  // return an error if the qeuue is empty (can't dequeue)
  if(isempty(q)){
    printf("Error: attempt to dequeue from an empty queue");
    return NULL;
  }

  // store the item from the head node
  struct node *head_node = q->head;
  struct packet_details *item = head_node->item;

  // update the head node from the queue
  q->head = q->head->next;
  
  // if the list is empty, update the tail to null
  if(q->head==NULL){
    q->tail=NULL;
  }

  // free the memory associated with the head node
  free(head_node);

  // return the dequeued item
  return item;
  
}