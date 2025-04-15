// SPDX-License-Identifier: GPL-2.0-only

#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>

#include "strlen.h"

int main(void)
{
	int i, cnt = 10000;
	struct timespec start, end;
	double elapsed;
	char str[128] = "0123456789abcdefghijklmnopqrstuvwxyz";
	size_t len_comm, len_zbb;

	len_comm = strlen_comm(str);
	len_zbb = strlen_zbb(str);
	if (len_comm != len_zbb) {
		printf("len_comm != len_zbb. len_comm=%ld len_zbb=%ld\n", len_comm, len_zbb);
		return -1;
	}
	printf("len_comm=len_zbb=%ld\n", len_comm);

	clock_gettime(CLOCK_MONOTONIC, &start);
	for (i = 0; i < cnt; i++)
		strlen_comm(str);
	clock_gettime(CLOCK_MONOTONIC, &end);
	elapsed = (end.tv_sec - start.tv_sec)*1000000000 + (end.tv_nsec - start.tv_nsec);
	printf("strlen_comm Elapsed time: %f ns\n", elapsed/cnt);

	clock_gettime(CLOCK_MONOTONIC, &start);
	for (i = 0; i < cnt; i++)
		strlen_zbb(str);
	clock_gettime(CLOCK_MONOTONIC, &end);
	elapsed = (end.tv_sec - start.tv_sec)*1000000000 + (end.tv_nsec - start.tv_nsec);
	printf("strlen_zbb Elapsed time: %f ns\n", elapsed/cnt);
}
