/*****************************************************************************
 * relay.c :  Relay an udp stream from a multicast addr to any addr.
 *****************************************************************************
 * Copyright (C) 2006 Binet Réseau
 * $Id: relay.c 957 2007-02-22 15:57:41Z vinz2 $
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

#define _GNU_SOURCE
#ifndef __GNUC__
#  define  __attribute__(x)  /* */
#endif

#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <inttypes.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <zlib.h>
#include "log.h"
#include "udpsocket.h"

/**
 * Constants & macros
 */
#define UDP_BUFFER 2000

#define FREE(a) if (a) { free(a); (a) = NULL; }

/**
 * Global variables
 */
int verbosity = 0;

/**
 * Prototypes
 */
void sigalarm_block (void);
void sigalarm_unblock (void);
void sigterm_handler (int)
		__attribute((noreturn));
void sigalarm_handler (int)
		__attribute((noreturn));
void terminate (void);

int prepare_socket(char *, struct in_addr *, struct sockaddr_in *, int);

void usage (void);

/**
 * Logging
 */
void log_info (const char *format, ...)
{
	va_list ap;
	if (verbosity >= 1)
	{
		fprintf(stderr, "Info: ");
		va_start(ap, format);
		vfprintf(stderr, format, ap);
		va_end(ap);
		fprintf(stderr, "\n");
	}
}
void log_error (const char *format, ...)
{
	va_list ap;
	if (verbosity >= 0)
	{
		fprintf(stderr, "Error: ");
		va_start(ap, format);
		vfprintf(stderr, format, ap);
		va_end(ap);
		fprintf(stderr, "\n");
	}
}

/**
 * Signal handlers & closers
 */
void sigalarm_block ()
{
	sigset_t ens;
	sigemptyset(&ens);
	sigaddset(&ens, SIGALRM);

	sigprocmask(SIG_BLOCK, &ens, NULL);
}
void sigalarm_unblock ()
{
	sigset_t ens;
	sigset_t old;
	sigemptyset(&ens);

	sigprocmask(SIG_BLOCK, &ens, &old);

	if (sigismember(&old, SIGALRM))
	{
		sigaddset(&ens, SIGALRM);
		sigprocmask(SIG_UNBLOCK, &ens, NULL);
	}
}
void sigterm_handler (int sig)
{
	terminate();
	exit(1);
}
void sigalarm_handler (int sig)
{
	log_info("timer expired ...");
	terminate();
	exit(0);
}
void terminate ()
{
	alarm(0);
	signal(SIGALRM, SIG_DFL);
}

/**
 * "URI" handler
 */
int prepare_socket(char *uri, struct in_addr *laddr, struct sockaddr_in *sockaddr, int wflag)
{
	char *colon = strchr(uri, ':');
	char *ip;
	struct in_addr addr;
	int port;
	int sock;

	/* Pr�paration des valeurs */
	if (colon == NULL)
	{
		log_error("stream `%s' is invalid (not in `A.B.C.D:E' form)", uri);
		return -1;
	}

	port = atoi(colon+1);
	if (port <= 0 || port > 65535)
	{
		log_error("stream `%s' is invalid (not in `A.B.C.D:E' form)", uri);
		return -1;
	}

	ip = strndup(uri, colon - uri);
	if (inet_aton(ip, &addr) == 0)
	{
		log_error("stream `%s' is invalid (not in `A.B.C.D:E' form)", uri);
		free(ip);
		return -1;
	}
	free(ip);

	/* Ouverture du socket */
	if (wflag > 0)
		sock = udpsocket_wopen((laddr != NULL ? laddr->s_addr : INADDR_ANY), addr.s_addr, port);
	else
		sock = udpsocket_ropen((laddr != NULL ? laddr->s_addr : INADDR_ANY), addr.s_addr, port);
	if (sock < 0)
	{
		log_error("unable to open socket for `%s'", uri);
		return -1;
	}

	if (sockaddr != NULL)
	{
		sockaddr->sin_family = AF_INET;
		sockaddr->sin_port = htons(port);
		sockaddr->sin_addr = addr;
	}
	return sock;
}

/**
 * Main functions
 */
void usage ()
{
	printf("Usage: relay [-hvq] [-l <localaddr>] [-d <seconds>] [-n <packets>] <source> <destination>\n");
	printf("   -h, --help            Display this help\n");
	printf("   -v, --verbose         Verbose output\n");
	printf("   -q, --quiet           Quiet output\n");
	printf("   -l, --laddr=ADDR      Use ADDR as local interface address\n");
	printf("   -d, --duration=SECS   Stop dumping after SECS seconds (default: no limit)\n");
	printf("   -n, --count=N         Stop dumping after N packets (default: no limit)\n");
}
int main (int argc, char** argv)
{
	int udp_timeout = -1;
	int udp_packets = -1;
	char udp_buffer[UDP_BUFFER+1];
	sigset_t old_sigmask;
	sigset_t new_sigblock;

	struct in_addr laddr = { INADDR_ANY };
	int src_fd, dst_fd;

	struct sockaddr_in from, sout, sin;
	unsigned int fromlen = sizeof (from);
	int udp_read, udp_written;

	/* Parameters */
	struct option longopts[] = {
		{"help",		0, 0, 'h'},
		{"usage",		0, 0, 'h'},
		{"verbose",		0, 0, 'v'},
		{"quiet",		0, 0, 'q'},
		{"laddr",		1, 0, 'l'},
		{"duration",	1, 0, 'd'},
		{"count",		1, 0, 'n'},
		{0,			0, 0,  0 }
	};
	for (;;)
	{
		char c = getopt_long(argc, argv, "hvql:d:n:", longopts, NULL);
		if (c < 0)
			break;

		switch (c)
		{
			case 'h':
				usage();
				return 0;
			case 'v':
				if (verbosity > 0)
					verbosity ++;
				else
					verbosity = 1;
				break;
			case 'q':
				verbosity = -1;
				break;
			case 'l':
				if (inet_aton(optarg, &laddr) == 0)
				{
					log_error("bad local interface address `%s'", optarg);
					usage();
					return 2;
				}
				break;
			case 'd':
				udp_timeout = atoi(optarg);
				break;
			case 'n':
				udp_packets = atoi(optarg);
				break;
			case '?':
				usage();
				return 3;
			case '0':
			default:
				break;
		}
	}

	if (optind + 2 != argc)
	{
		log_error("you must provide a src addr and a dst addr.");
		usage();
		return 4;
	}

	/* Signal setup */
	sigemptyset(&new_sigblock);
	sigaddset(&new_sigblock, SIGALRM);
	sigprocmask(SIG_BLOCK, &new_sigblock, &old_sigmask);

	signal(SIGINT, sigterm_handler);
	signal(SIGTERM, sigterm_handler);
	signal(SIGALRM, sigalarm_handler);

	/* Timeout setup */
	if (udp_timeout > 0)
	{
		log_info("SAP timeout set to %d seconds", udp_timeout);
		alarm(udp_timeout);
	}

	/* Opening streams */
	src_fd = prepare_socket(argv[optind++], &laddr, &sin,  0);
	dst_fd = prepare_socket(argv[optind++], &laddr, &sout, 1);
	if (src_fd < 0 || dst_fd < 0)
	{
		return 5;
	}

	/* Main loop (polling, recv, send) */
	while (udp_packets != 0)
	{

		/* Receiving message */
		sigalarm_unblock();
		udp_read = recvfrom(src_fd, udp_buffer, UDP_BUFFER, 0, (struct sockaddr*) &from, &fromlen);
		sigalarm_block();

		if (udp_read < 0)
		{
			udpsocket_close(src_fd);
			udpsocket_close(dst_fd);
			return 0;
		}
		log_info("got %d bytes from %s:%d", udp_read, inet_ntoa(from.sin_addr), from.sin_port);

		/* Transmiting message */
		udp_written = sendto(dst_fd, udp_buffer, udp_read, 0, &sout, sizeof(sout));
		if (udp_written != udp_read)
		{
			if (verbosity >= 0)
			{
				if (udp_written < 0)
					log_error("unexpected dst socket error (%s)", strerror(errno));
				else
					log_error("datagram not entirely written to dst socket, aborting (r %d, w %d)", udp_read, udp_written);
			}
			udpsocket_close(src_fd);
			udpsocket_close(dst_fd);
			return 6;
		}
		log_info("send %d bytes to %s:%d", udp_written, inet_ntoa(sout.sin_addr), sout.sin_port);

		if (udp_packets > 0)
			udp_packets --;
	}

	terminate();
	return 0;
}
