// Non-platform binary that sandboxes itself with sandbox_init(), for §4.4 candidate fixtures.
#include <fcntl.h>
#include <sandbox.h>
#include <stdio.h>

int main(void) {
  char *err = NULL;
  if (sandbox_init(kSBXProfileNoWrite, SANDBOX_NAMED, &err)) {
    fprintf(stderr, "sandbox_init: %s\n", err);
    return 1;
  }
  int fd = open("/private/tmp/buckle_sbinit_probe", O_CREAT | O_WRONLY, 0644);
  printf("open fd=%d\n", fd);
  return 0;
}
