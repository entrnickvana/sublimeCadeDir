#include<stdio.h>
#include "csapp.h"
#include<stdlib.h>


int main()
{
	int pid = fork();
	if(pid == 0){
		printf("Bye from child\n");
		exit(17);
	} else {

	int childStatus; //&mystatus;
	printf("Hello From Parent\n");

	Waitpid(pid, &childStatus, 0);
	printf("CT: child result: %d\n", WEXITSTATUS(childStatus));

	}

	printf("Bye\n");
	return 0;

}