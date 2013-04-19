#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

unsigned int table[16][16];

int main (void) 
{
  FILE *f;
  int i, j;
  
  f = fopen("data","r");
  for (i = 0; i < 16; i++)
    fscanf (f, "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
            &table[i][0], &table[i][1], &table[i][2], &table[i][3],
            &table[i][4], &table[i][5], &table[i][6], &table[i][7],
            &table[i][8], &table[i][9], &table[i][10], &table[i][11],
            &table[i][12], &table[i][13], &table[i][14], &table[i][15]);
  fclose(f);
  
  for (i = 0; i < 16; i++) {
    printf("{");
    for (j = 0; j < 16; j++) {
      if (j < 15) {
        if (table[i][j] & 0x00000080)
          printf("(byte)0x%02x,", table[i][j]);
        else
          printf("0x%02x,", table[i][j]);
      } else {
        if (table[i][j] & 0x00000080)
          printf("(byte)0x%02x", table[i][j]);
        else
          printf("0x%02x", table[i][j]);
      }
    }
    if (i < 15)
      printf("},\n");
    else
      printf("}");
  }
  return 0;
}
