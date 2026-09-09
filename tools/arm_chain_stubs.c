int memfd_leak = -1;
#include <stdio.h>
#include <stdint.h>
#include <stdatomic.h>

uint64_t consumer_calls;
uint64_t consumer_success;
_Atomic int punch_consume_stop;
_Atomic int punch_consume_go;
_Atomic int main_route_delay_usec;
uint64_t pipe_prepare_request;
uint64_t pipe_prepare_done;

void slide_probe(const char *stage) {
  fprintf(stderr, "[probe] %s\n", stage);
}
uint64_t kaslr_base;
uint64_t kaslr_slide;
int kaslr_done;
