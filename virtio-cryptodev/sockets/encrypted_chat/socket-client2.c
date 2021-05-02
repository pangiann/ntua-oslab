/*
 * socket-client.c
 * Simple TCP/IP communication using sockets
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 * Christopni (aka Nikos Christopoulos)
 * PanGiann (aka Panagiotis Giannoulis)
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
#include "socket-common.h"

#include <fcntl.h>

#include <sys/ioctl.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <crypto/cryptodev.h>
char format[15] = "%c[1;32m%s: ";
char format2[15] = "\033[0m%s";
unsigned char key[] = "pangiannchristo";
unsigned char iv[]  = "christopnipangi";
unsigned char *name;
unsigned char *buf;
unsigned char *message;
struct session_op sess;

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





int encrypt(int cfd, unsigned char *arr, int size)
{

        struct crypt_op cryp;

	      unsigned char   encrypted[size];

				//initialize to zero cryp struct
        memset(&cryp, 0, sizeof(cryp));

        /*
         * Encrypt data.in to data.encrypted
         */
        cryp.ses = sess.ses;
        cryp.len = size;
        cryp.src = arr;
        cryp.dst = encrypted;
        cryp.iv = iv;
        cryp.op = COP_ENCRYPT;

        if (ioctl(cfd, CIOCCRYPT, &cryp)) {
                perror("ioctl(CIOCCRYPT)");
                return 1;
        }


				/* transfer data to result array */
        for (int i = 0; i  < size; i++){
                arr[i] = encrypted[i];
        }

        return 0;
}

int decrypt(int cfd, unsigned char *arr, int size){


        struct crypt_op cryp;
        unsigned char   decrypted[size];

        memset(&cryp, 0, sizeof(cryp));

        /*
         * Decrypt data.encrypted to data.decrypted
         */
        cryp.ses = sess.ses;
        cryp.len = size;
        cryp.src = arr;
        cryp.dst = decrypted;
        cryp.iv = iv;
        cryp.op = COP_DECRYPT;
        if (ioctl(cfd, CIOCCRYPT, &cryp)) {
                perror("ioctl(CIOCCRYPT)");
                return 1;
        }

	      memset(arr, '\0', size);
        int i = 0;
        while(decrypted[i] != '\0'){
                arr[i] = decrypted[i];
                i++;
        }
	      arr[i] = '\0';
        return 0;
}


int main(int argc, char *argv[])
  {
  	int client_sd, port, action;
  	ssize_t n;

  	char *hostname;
  	struct hostent *hp;
  	struct sockaddr_in sa;
  	fd_set inset;
  	int max_sd = 0;

  	if (argc != 4) {
  		fprintf(stderr, "Usage: %s hostname port login_name\n", argv[0]);
  		exit(1);
  	}
  	hostname = argv[1];
  	port = atoi(argv[2]);
  	if (port > 65535 || port < 1025) {
  		perror("Wrong port");
  		exit(1);
  	}
  	if (strlen(argv[3]) > 10) {
  		perror("Names can only be between 1 - 10 characters");
  		exit(1);
  	}

  	/* Create TCP/IP socket, used as main chat channel */
  	if ((client_sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
  		perror("socket");
  		exit(1);
  	}
  	fprintf(stderr, "Created TCP socket\n");

  	/* Look up remote hostname on DNS */
  	if ( !(hp = gethostbyname(hostname))) {
  		printf("DNS lookup failed for host %s\n", hostname);
  		exit(1);
  	}


  	/* Connect to remote TCP port */
  	sa.sin_family = AF_INET;
  	sa.sin_port = htons(port);
  	memcpy(&sa.sin_addr.s_addr, hp->h_addr, sizeof(struct in_addr));
  	fprintf(stderr, "Connecting to remote host... "); fflush(stderr);
  	if (connect(client_sd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
  		perror("connect");
  		exit(1);
  	}
  	fprintf(stderr, "Connected.\n");

    /* allocate buffers in memory and initialize them to zero */
    name = safe_malloc(DATA_SIZE+1);
    buf = safe_malloc(DATA_SIZE+1);
    message = safe_malloc(DATA_SIZE+1);
    memset(name, '\0', DATA_SIZE+1);
    memset(buf, '\0', DATA_SIZE+1);
    memset(message, '\0', DATA_SIZE+1);

    /* open crypto device driver */
  	int cfd = open("/dev/crypto", O_RDWR);
  	if (cfd < 0) {
  		perror("open(/dev/crypto)");
  		return 1;
  	}


  	int size_of_name = strlen(argv[3]) +  strlen(format);
  	snprintf(name, size_of_name, "%c[1;32m%s: ", 27, argv[3]);
  	name[size_of_name] = '\0';


  	memset(&sess, 0, sizeof(sess));


  	/*
  	 * Get crypto session for AES128
  	 */




  	sess.cipher = CRYPTO_AES_CBC;
  	sess.keylen = KEY_SIZE;
  	sess.key = key;


  	if (ioctl(cfd, CIOCGSESSION, &sess)) {
  		perror("ioctl(CIOCGSESSION)");
  		return 1;
  	}

    /* encrypt name in order to send it to network */
  	encrypt(cfd, name, DATA_SIZE);

  	for (;;) {


  		FD_ZERO(&inset);
  		FD_SET(client_sd, &inset);
      FD_SET(STDIN_FILENO, &inset);
      /* choose max sd */
  		max_sd = STDIN_FILENO > client_sd ? STDIN_FILENO : client_sd;

  		action = select(max_sd + 1, &inset, NULL, NULL, NULL);
  		if (action < 0 && errno != EINTR) {
  			perror("select");
  			exit(1);
  		}

  		// receiving message
  		if (FD_ISSET(client_sd, &inset)) {

  			n = read(client_sd, buf, DATA_SIZE+1);
  			if (n < 0) {
  				perror("read");
  				exit(1);
  			}
  			buf[DATA_SIZE] = '\0';

  			decrypt(cfd, buf, DATA_SIZE);
  			if (insist_write(0, buf, strlen(buf)) != strlen(buf)) {
  				perror("write");
  				exit(1);
  			}

  		}
  		// sending message

  		if (FD_ISSET(STDIN_FILENO, &inset)) {

  			// send name with color to server
  			if (insist_write(client_sd, name, DATA_SIZE) != DATA_SIZE) {
  				perror("write");
  				exit(1);
  			}

  			do {
					n = read(1, buf, DATA_SIZE-strlen(format2)-1);

	  			//printf("n = %d\n\n", n);
	  			if (n < 0) {
	  				perror("read");
	  				exit(1);
	  			}
	  			buf[n] = '\0';
	        /*
	  			now we have to encrypt the message and send it to server
	  			*/

	  			snprintf(message, strlen(buf) + strlen(format2)+1, "\033[0m%s", buf);
	  			encrypt(cfd, message, DATA_SIZE);

	  			// send message to server
	  			if (insist_write(client_sd, message, DATA_SIZE) != DATA_SIZE) {
	  				perror("write");
	  				exit(1);
	  			}
				} while (buf[n-1] != '\n');

  		}

  	}

  	free(name);
		free(buf);
		free(message);
		if (ioctl(cfd, CIOCFSESSION, &sess.ses)) {
			perror("ioctl(CIOCFSESSION)");
			return 1;
		}
  	if (close(cfd) < 0) {
  		perror("close(fd)");
  		return 1;
  	}

  	return 0;
}
