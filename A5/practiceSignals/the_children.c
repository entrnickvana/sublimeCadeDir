
#include<stdio.h>
#include<stdlib.h>
#include "csapp.h"

#define show_each_N 1000

int main()
{
	int count = 0;
	int pid = fork();
	while(1)
	{
		int pid = fork(); // begin new fork

		if(pid == 0) // if child is a mod of 1000 print id
			return count++ /show_each_N;		
		else
		{
			int childrenStatus; // prepare a status
			waitpid(pid, &childrenStatus, 0);  // wait
			if(count%show_each_N == 0)
				printf("Child: %d was just reaped\n\n", childrenStatus);
			
		}

	count++;		// increment cont

	}
}