#include <stdio.h>
#include <time.h>


int main(void) {
  srand(time(NULL));
  int i, out;
  for(i=0; i < 0x32; i++)
  {
    out = rand() % 100;
    printf("%d\n", out);
  }
}
