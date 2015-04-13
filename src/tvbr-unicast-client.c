/*****************************************************************************
 * tvbr-unicast-client.c :  TV-Unicaster over HTTP
 *****************************************************************************
 * Copyright (C) 2006 Binet Réseau
 * $Id: tvbr-unicast-client.c 957 2007-02-22 15:57:41Z vinz2 $
 *
 * Authors: Vincent Zanotti <vincent.zanotti@m4x.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
 *****************************************************************************/

#include "tvbr-unicast.h"

// TODO: regler le probleme de la non-fermeture du tvbr-unicast-client lorsque la connection apache est coupee

/**
 *  Parameters
 */
#define URL_PATH "/stream/"
#define DATA_TIMEOUT 2

#define IPC_TIMEOUT 2000
#define UDP_BUFFER 2000
#define LOGBUFFER_SIZE 1024

/**
 *  Global variables
 */
int verbosity = 0;
int log_fd = 0;
pid_t log_pid = 0;

int ipc_socket;
int udp_socket;

/**
 *  Prototypes
 */
inline void log_do (const int, const char *, const char *, va_list)
		__attribute__((format(printf,3,0)));

void cleanup_handler (void);
void signal_handler (int);

void cgi_headers (const int, const char *);
void cgi_error (const int, const char *, ...)
		__attribute__((format(printf,2,3)));

/**
 *  Logging function
 */
inline void log_do (const int minverb, const char *prefix, const char *format, va_list ap)
{
	int written_prefix, written_message;
	time_t t;
	struct tm stm;
	char timebuf[20];
	char logbuffer[LOGBUFFER_SIZE];

	/* Min verbosity */
	if (verbosity < minverb)
		return;

	/* Initialization */
	if (log_fd == 0)
	{
		log_fd = open("/var/log/tvbr-unicast/client.log", O_APPEND | O_CREAT | O_NONBLOCK | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
		log_pid = getpid();
	}

	/* Time of day */
	t = time(NULL);
	if (localtime_r (&t, &stm) == NULL)
		return;
	if (strftime (timebuf, sizeof(timebuf), "%b %d %H:%M:%S", &stm) == 0)
		return;

	/* Writing */
	if (log_fd > 0)
	{
		written_prefix = snprintf(logbuffer, LOGBUFFER_SIZE - 2, "%s tvbr-client[%d]: %s: ", timebuf, log_pid, prefix);
		if (written_prefix < 0)
			return;

		written_message = vsnprintf(logbuffer + written_prefix, LOGBUFFER_SIZE - written_prefix - 1, format, ap);
		if (written_message < 0)
			return;

		logbuffer[written_prefix+written_message  ] = '\n';
		logbuffer[written_prefix+written_message+1] = 0;

		if (write(log_fd, logbuffer, written_prefix+written_message+1) < 0)
		{
			close(log_fd);
			log_fd = 0;
		}
	}
}
void log_debug (const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	log_do (2, "Debug", format, ap);
	va_end(ap);
}
void log_info (const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	log_do (1, "Info", format, ap);
	va_end(ap);
}
void log_warn (const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	log_do (0, "Warning", format, ap);
	va_end(ap);
}
void log_error (const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	log_do (-1, "Error", format, ap);
	va_end(ap);
}

/**
 *  Cleanup handlers & signal handlers
 */
void cleanup_handler ()
{
	if (log_fd > 0)
	{
		close(log_fd);
		log_fd = 0;
	}
	if (udp_socket > 0)
	{
		udpsocket_close(udp_socket);
		udp_socket = 0;
	}
	if (ipc_socket > 0)
	{
		shutdown(ipc_socket, SHUT_RDWR);
		close(ipc_socket);
		ipc_socket = 0;
	}
}
void signal_handler (int sig)
{
	if (sig == SIGHUP)
	{
		close(log_fd);
		log_fd = 0;
	}
	else if (sig == SIGPIPE)
	{
		log_info ("broken pipe (IPC)");
		cleanup_handler();
		exit (0);
	}
	else
	{
		cleanup_handler();
		exit (0);
	}
}

/**
 *  CGI Helpers
 */
void cgi_headers (const int status, const char *mimetype)
{
	/* HTTP Status */
	switch (status)
	{
		case 500:
			printf("Status: 500 Internal Server Error\n");
			break;
		case 404:
			printf("Status: 404 Not Found\n");
			break;
		case 403:
			printf("Status: 403 Forbidden\n");
			break;
		case 401:
			printf("Status: 401 Authorization Required\n");
			break;
		case 200:
		default:
			printf("Status: 200 OK\n");
	}

	/* Content type & message */
	printf("Content-Type: %s; charset=ISO-8859-1\n", mimetype);
	printf("\n");
}
void cgi_error (const int status, const char *format, ...)
{
	const char *title;
	va_list ap;
	va_start(ap, format);

	switch (status)
	{
		case 500:
			title = "Server error!";
			break;
		case 404:
			title = "Object not found!";
			break;
		case 403:
			title = "Access forbidden!";
			break;
		case 401:
			title = "Authentication required!";
			break;
		default:
			title = NULL;
			break;
	}

	if (title != NULL)
	{
		time_t t = time(NULL);
		char buffer[200];
		strftime(buffer, sizeof(buffer), "%c", localtime(&t));

		cgi_headers(status, "text/html");

		printf("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n");
		printf("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\n  http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n");
		printf("<html xmlns=\"http://www.w3.org/1999/xhtml\" lang=\"en\" xml:lang=\"en\">\n");
		printf("<head>\n\t<title>%s</title>\n\t<link rev=\"made\" href=\"mailto:tv@frankiz.polytechnique.fr\" />\n", title);
		printf("\t<style type=\"text/css\"><!--/*--><![CDATA[/*><!--*/\n\t\t body { color: #000000; background-color: #FFFFFF; }\n");
		printf("\t\ta:link { color: #0000CC; }\n\t\t p, address {margin-left: 3em;}\n\t\tspan {font-size: smaller;}\n");
		printf("\t/*]]>*/--></style>\n</head>\n");

		printf("<body>\n\t<h1>%s</h1>\n\t<p>", title);
		vprintf(format, ap);
		printf("</p>\n\t<p>If you think this is a server error, please contact  the <a href=\"mailto:tv@frankiz.polytechnique.fr\">webmaster</a>.</p>\n");

		printf("\t<h2>Error %d</h2>\n", status);
		printf("\t<address><a href=\"/\">%s</a><br /><span>%s<br />%s</span></adress>\n", getenv("SERVER_NAME"), buffer, getenv("SERVER_SOFTWARE"));
		printf("</body>\n</html>\n");
	}
	else
	{
		cgi_headers(status, "text/plain");
		vprintf(format, ap);
	}
	va_end(ap);
}

/**
 *  Main function
 */
extern char **environ;
int main (int argc, char **argv)
{
	char *query_string;
	char query_ip[IPC_IP_LENGTH];
	short query_port = 0;
	char *host_ip;

	struct in_addr udp_addr;
	struct sockaddr_in udp_from;
	unsigned int udp_fromlen = sizeof (udp_from);
	unsigned char udp_buffer[UDP_BUFFER];
	int udp_read;

	struct sockaddr_un ipc_server;
	ipc_packet ipc_packet;
	unsigned char ipc_buffer[IPC_BUFFER];
	int ipc_read;
	struct in_addr ipc_host_addr;
	int optval;

	struct timeval tv;

	/* Parameters */
	verbosity = 1;

	query_string = getenv("REQUEST_URI");
	if (query_string == NULL)
	{
		cgi_error (404, "This script was unable to determine which channel you requested.");
		cleanup_handler ();
		exit (1);
	}
	if (strncmp(query_string, URL_PATH, strlen(URL_PATH)) != 0)
	{
		cgi_headers (500, "text/plain");
		printf("This script must be recompiled with the up2date HTTP path:\n");
		printf("\tConfigured path: %s\n", URL_PATH);
		printf("\tUsed path:       %s\n", query_string);
		cleanup_handler ();
		exit (1);
	}
	query_string += strlen(URL_PATH);

	host_ip = getenv("REMOTE_ADDR");
	if (host_ip == NULL || !inet_aton(host_ip, &ipc_host_addr))
	{
		cgi_error (404, "This script was unable to determine your originating IP.");
		cleanup_handler ();
		exit (1);
	}

	/* Signals */
	signal (SIGHUP, &signal_handler);
	signal (SIGINT, &signal_handler);
	signal (SIGTERM, &signal_handler);
	signal (SIGQUIT, &signal_handler);
	signal (SIGPIPE, &signal_handler);

	/* Initializing IPC with server */
	ipc_socket = socket(PF_UNIX, SOCK_STREAM, 0);
	if (ipc_socket < 0)
	{
		cgi_error (403, "The script was unable to contact authorization server.");
		log_warn("unable to contact authorization server (%s)", strerror(errno));
		cleanup_handler ();
		exit (1);
	}

	optval = IPC_BUFFER;
	if (setsockopt(ipc_socket, SOL_SOCKET, SO_RCVBUF, &optval, sizeof(optval)) < 0)
	{
		cgi_error (403, "The script was unable to contact authorization server.");
		log_warn("Unable to set SO_RCVBUF on IPC socket (%s)", strerror(errno));
		cleanup_handler ();
		exit (1);
	}
	if (setsockopt(ipc_socket, SOL_SOCKET, SO_SNDBUF, &optval, sizeof(optval)) < 0)
	{
		cgi_error (403, "The script was unable to contact authorization server.");
		log_warn("Unable to set SO_SNDBUF on IPC socket (%s)", strerror(errno));
		cleanup_handler ();
		exit (1);
	}

	ipc_server.sun_family = AF_UNIX;
	strncpy(ipc_server.sun_path, IPC_SOCKET, sizeof(ipc_server.sun_path));
	ipc_server.sun_path[sizeof(ipc_server.sun_path)-1] = '\0';
	if (connect(ipc_socket, (struct sockaddr*) &ipc_server, sizeof(ipc_server)) < 0)
	{
		cgi_error (403, "The script was unable to contact authorization server.");
		log_warn("unable to contact authorization server (%s)", strerror(errno));
		cleanup_handler ();
		exit (1);
	}

	/* Logging SOR */
	log_info("Handling request for '%s' by %s", query_string, host_ip);

	/* Translation request -> ip */
	if (!ipc_encode_access_request(&ipc_packet, ipc_buffer, ipc_host_addr.s_addr, query_string))
	{
		cgi_error (403, "The script was unable to contact authorization server.");
		log_warn("unable to build authorization request");
		cleanup_handler ();
		exit (1);
	}
	if (send(ipc_socket, ipc_buffer, ipc_packet.packet_length, MSG_NOSIGNAL) != (int)ipc_packet.packet_length)
	{
		cgi_error (403, "The script was unable to contact authorization server.");
		log_warn("sending of authorization request failed (%s)", strerror(errno));
		cleanup_handler ();
		exit (1);
	}

	while (query_port == 0)
	{
		struct pollfd pfd;
		pfd.fd = ipc_socket;
		pfd.events = POLLIN|POLLPRI;

		if (poll(&pfd, 1, IPC_TIMEOUT) <= 0)
		{
			cgi_error (500, "The script was unable to contact authorization server.");
			log_warn("timed out while waiting for answer from Authorization server");
			cleanup_handler ();
			exit (1);
		}

		ipc_read = ipc_recv(ipc_socket, ipc_buffer, IPC_BUFFER, 0);
		if (ipc_read < 0)
		{
			cgi_error (403, "The script was unable to contact authorization server.");
			log_warn("receiving authorization answer failed (%s)", strerror(errno));
			cleanup_handler ();
			exit (1);
		}

		if (ipc_read > 0)
		{
			if (ipc_decode(ipc_buffer, (unsigned int)ipc_read, &ipc_packet))
			{
				switch (ipc_packet.headers.type)
				{
					case IPC_ACCESS_ACCEPT:
						strncpy(query_ip, (char *) ipc_packet.payload.access_accept.query_ip, IPC_IP_LENGTH);
						query_ip[IPC_IP_LENGTH] = '\0';
						query_port = ipc_packet.payload.access_accept.query_port;
						break;

					case IPC_ACCESS_DENY:
						cgi_error (ipc_packet.payload.access_deny.status,
							     "Authorization server denied your access:<br />%s",
							     ipc_packet.payload.access_deny.answer);
						log_warn("authorization denied (%d: %s)", ipc_packet.payload.access_deny.status, ipc_packet.payload.access_deny.answer);
						cleanup_handler ();
						exit (1);
						break;

					case IPC_NOOP:
						break;

					case IPC_URLLIST:
					case IPC_BWGROUP_LIST:
					case IPC_CONNECTION_LIST:
					case IPC_ACCESS_REQUEST:
					case IPC_URLLIST_GET:
					case IPC_BWGROUP_GET:
					case IPC_CONNECTION_GET:
						log_debug("ignoring unhandeld message type");
						break;

					default:
						cgi_error (403, "The script was unable to contact authorization server.");
						log_warn("unknown type of IPC message, aborting");
						cleanup_handler ();
						exit (1);
						break;
				}
			}
		}

		if (ipc_read == 0)
		{
			cgi_error (403, "The script was unable to contact authorization server.");
			log_warn("connection with authorization server terminated unexpectedly");
			cleanup_handler ();
			exit (1);
			break;
		}
	}

	/* Opening udp source socket */
	inet_aton(query_ip, &udp_addr);
	udp_socket = udpsocket_ropen(INADDR_ANY, udp_addr.s_addr, query_port);
	if (udp_socket < 0)
	{
		cgi_error (500, "The script was unable to obtain datas for the channel you requested.");
		cleanup_handler ();
		exit (1);
	}
	log_info("starting streaming of '%s' (%s:%d) for %s", query_string, query_ip, query_port, host_ip);

	/* CGI Headers && new stdout flags */
	fcntl(STDOUT_FILENO, F_SETFL, O_NONBLOCK);
	cgi_headers(200, "video/mpeg");

	/* Main loop */
	for (;;)
	{
		fd_set rfds;
		int maxsocket;

		/* Preparing poll */
		FD_ZERO(&rfds);
		FD_SET(udp_socket, &rfds);
		FD_SET(ipc_socket, &rfds);

		maxsocket = (udp_socket > ipc_socket ? udp_socket : ipc_socket);

		tv.tv_sec = DATA_TIMEOUT;
		tv.tv_usec = 0;

		/* Polling */
		select(maxsocket + 1, &rfds, NULL, NULL, &tv);

		/* Checking IPC */
		if (FD_ISSET(ipc_socket, &rfds))
		{
			for (;;)
			{
				ipc_read = ipc_recv(ipc_socket, ipc_buffer, IPC_BUFFER, MSG_DONTWAIT);
				if (ipc_read < 0)
				{
					if (errno == EAGAIN)
						break;

					log_warn("unknown error on ipc socket (%s)", strerror(errno));
					cleanup_handler ();
					exit (1);
					break;
				}

				if (ipc_read > 0)
				{
					if (ipc_decode(ipc_buffer, (unsigned int)ipc_read, &ipc_packet))
					{
						switch (ipc_packet.headers.type)
						{
							case IPC_NOOP:
							case IPC_ACCESS_ACCEPT:
								/* Ignoring */
								break;

							case IPC_ACCESS_DENY:
								log_info("authorization server asked for EOT");
								cleanup_handler ();
								exit (0);
								break;

							case IPC_URLLIST:
							case IPC_BWGROUP_LIST:
							case IPC_CONNECTION_LIST:
								log_info("receiving unsollicited list from authorization server");
								break;

							case IPC_ACCESS_REQUEST:
							case IPC_URLLIST_GET:
							case IPC_BWGROUP_GET:
							case IPC_CONNECTION_GET:
								log_warn("server type of IPC message, aborting");
								cleanup_handler ();
								exit (1);
								break;

							default:
								log_warn("unknown type of IPC message, aborting");
								cleanup_handler ();
								exit (1);
								break;
						}
					}
				}

				if (ipc_read == 0)
				{
					log_info("connection with Authorization server terminated");
					cleanup_handler ();
					exit (0);
					break;
				}
			}
		}

		/* Checking datas */
		if (FD_ISSET(udp_socket, &rfds))
		{
			for (;;)
			{
				udp_read = recvfrom(udp_socket, udp_buffer, UDP_BUFFER, MSG_DONTWAIT, (struct sockaddr *)&udp_from, &udp_fromlen);
				if (udp_read < 0)
				{
					if (errno == EAGAIN)
						break;

					log_warn("unknown error on udp multicast socket (%s)", strerror(errno));
					cleanup_handler ();
					exit (1);
					break;
				}

				if (udp_read > 0)
				{
					if ((int)fwrite(udp_buffer, 1, udp_read, stdout) != udp_read)
					{
						log_info("broken pipe");
						cleanup_handler ();
						exit (0);
						break;
					}
					fflush(stdout);
				}

				if (udp_read == 0)
				{
					cleanup_handler ();
					exit (0);
					break;
				}
			}
		}

		/* Checking EOF */
		if (!FD_ISSET(udp_socket, &rfds) && !FD_ISSET(ipc_socket, &rfds))
			break;
	}

	/* Cleaning up */
	cleanup_handler ();
	return 0;
}
