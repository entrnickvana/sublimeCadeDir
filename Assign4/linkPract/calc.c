

#include "mult.h"
#include "divi.h"



int main(int argc, char* argv[]){

  int arg1 = atoi(argv[1]);
  int arg2 = atoi(argv[2]);
  int arg3 = atoi(argv[3]);

  printf("%d\n",mult(divi(arg1, arg2), arg3));
  
  return 1;
  
}
