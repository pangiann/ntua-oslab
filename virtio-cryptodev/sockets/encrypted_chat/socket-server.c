/*
 * socket-server.c
 * Simple TCP/IP communication using sockets
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 */

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "cryptodev.h"
#include "socket-common.h"
unsigned char key[] = "pangiannchristop";
unsigned char iv[] = "christopnipangia";
unsigned char *buf;

void *safe_malloc(size_t size)
{
	void *p;

	if ((p = malloc(size)) == NULL) {
		fprintf(stderr, "Out of memory, failed to allocate %zd bytes\n",
			size);
		exit(1);
	}

	return p;
}


/* Insist until all of the data has been written */
ssize_t insist_write(int fd, const void *buf, size_t cnt)
{
	ssize_t ret;
	size_t orig_cnt = cnt;

	while (cnt > 0) {
	        ret = write(fd, buf, cnt);
	        if (ret < 0)
	                return ret;
	        buf += ret;
	        cnt -= ret;
	}

	return orig_cnt;
}

int main(void)
{
  	char addrstr[INET_ADDRSTRLEN];
  	int server_sd, client_sd, send_to_sd, newsd, action;
  	ssize_t n;
  	socklen_t len;
  	struct sockaddr_in sa;
  	int client_socket[MAX_CLIENTS];
  	fd_set inset;
  	int max_sd = 0;
  	for (int i = 0; i < MAX_CLIENTS; i++) {
  		client_socket[i] = 0;
  	}



  	signal(SIGPIPE, SIG_IGN);

  	/* Create TCP/IP socket, used as main chat channel */
  	if ((server_sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
  		perror("socket");
  		exit(1);
  	}
  	fprintf(stderr, "Created TCP socket\n");

  	/* Bind to a well-known port */
  	memset(&sa, 0, sizeof(sa));
  	sa.sin_family = AF_INET;
  	sa.sin_port = htons(TCP_PORT);
  	sa.sin_addr.s_addr = htonl(INADDR_ANY);
  	if (bind(server_sd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
  		perror("bind");
  		exit(1);
  	}
  	fprintf(stderr, "Bound TCP socket to port %d\n", TCP_PORT);

  	/* Listen for incoming connections */
  	if (listen(server_sd, TCP_BACKLOG) < 0) {
  		perror("listen");
  		exit(1);
  	}
    buf = safe_malloc(DATA_SIZE+1);
    memset(buf, '\0', DATA_SIZE+1);
  	/* Loop forever, accept()ing connections */
  	for (;;) {
  		// clear socket set
  		FD_ZERO(&inset);

  		// add server sd to set
  		FD_SET(server_sd, &inset);
  		max_sd = server_sd;


  		for (int i = 0; i < MAX_CLIENTS; i++) {
  			client_sd = client_socket[i];

  			if (client_sd > 0)
  				  FD_SET(client_sd, &inset);

  			if (client_sd > max_sd)
  					max_sd = client_sd;
  		}

  		action = select(max_sd + 1, &inset, NULL, NULL, NULL);
  		if ((action < 0) && (errno!=EINTR)) {
  			perror("select");
  			exit(1);
  		}

  		// incoming connection
  		if (FD_ISSET(server_sd, &inset)) {
  			if ((newsd = accept(server_sd, (struct sockaddr *)&sa, &len)) < 0) {
  				perror("accept");
  				exit(1);
  			}
  			if (!inet_ntop(AF_INET, &sa.sin_addr, addrstr, sizeof(addrstr))) {
  				perror("could not format IP address");
  				exit(1);
  			}
  			fprintf(stderr, "Incoming connection from %s:%d\n",
  				addrstr, ntohs(sa.sin_port));
  			for (int i = 0; i < MAX_CLIENTS; i++) {
  				if (client_socket[i] == 0) {
  					client_socket[i] = newsd;
  					break;
  				}
  			}

  		}

  		//incomming message from a client socket
  		for (int i = 0; i < MAX_CLIENTS; i++) {

  				client_sd = client_socket[i];
  				if (FD_ISSET(client_sd, &inset)) {

  					if ((n = read(client_sd, buf, DATA_SIZE)) == 0) {
  						 getpeername(client_sd, (struct sockaddr*) &sa, &len);
  						 printf("Host with ip:port %s:%d disconnected\n", inet_ntop(AF_INET, &sa.sin_addr, addrstr, sizeof(addrstr)), ntohs(sa.sin_port));
  						 close(client_sd);
  						 client_socket[i] = 0;
  					}
  					else
  					{
  						buf[n] = '\0';
  						for (int k = 0; k < MAX_CLIENTS; k++) {
  							if (client_socket[k] == 0 || client_socket[k] == client_sd) {
  								continue;
  							}
  							send_to_sd = client_socket[k];
  							insist_write(send_to_sd, buf, DATA_SIZE+1);
  						}
  					}
  			 }
  		}



  	}

  	/* This will never happen */
  	return 1;
}
