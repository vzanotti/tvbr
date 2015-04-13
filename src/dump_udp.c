/*****************************************************************************
 * dump_dup.c :  Dump UDP multicast stream
 *****************************************************************************
 * Copyright (C) 2006 Binet Réseau
 * $Id: dump_udp.c 957 2007-02-22 15:57:41Z vinz2 $
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
#include <stdarg.h>
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

int streams = 0;
int *sockets = NULL;
int *files = NULL;

/**
 * Prototypes
 */
void sigterm_handler (int)
		__attribute((noreturn));
void sigalarm_handler (int)
		__attribute((noreturn));
void terminate (void);

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
	int i = 0;
	alarm(0);
	signal(SIGALRM, SIG_DFL);

	for (i = 0; i < streams; i++)
	{
		if (sockets[i] > 0)
			udpsocket_close(sockets[i]);
		if (files[i] > 0)
			close(files[i]);
	}
	FREE(files);
	FREE(sockets);
	streams = 0;
}

/**
 * Main functions
 */
void usage ()
{
	printf("Usage: dump_udp [-hvq] [-l <localaddr>] [-d <seconds>] [-n <packets>] <prefix> <ip>:<port> [...]\n");
	printf("Usage: dump_udp [-hvq] [-l <localaddr>] [-d <seconds>] [-n <packets>] - <ip>:<port>\n");
	printf("   -h, --help            Display this help\n");
	printf("   -v, --verbose         Verbose output\n");
	printf("   -q, --quiet           Quiet output\n");
	printf("   -l, --laddr=ADDR      Use ADDR as local interface address\n");
	printf("   -d, --duration=SECS   Stop dumping after SECS seconds (default: 3 secs)\n");
	printf("   -n, --count=N         Stop dumping after N packets (default: no limit)\n");
}
int main (int argc, char** argv)
{
	int udp_timeout = 3;
	int udp_packets = -1;
	char udp_buffer[UDP_BUFFER+1];
	int udp_read, udp_write;
	in_addr_t laddr = INADDR_ANY;
	int i;
	sigset_t old_sigmask;
	sigset_t new_sigblock;

	char *prefix;

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
	while(1)
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
				laddr = inet_addr(optarg);
				if (laddr == INADDR_NONE)
				{
					log_error("bad local interface address `%s'", optarg);
					usage();
					return 1;
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
				return 1;
			case '0':
			default:
				break;
		}
	}

	if (optind + 1 >= argc)
	{
		log_error("you must provide a prefix, and at least one stream.");
		usage();
		return 1;
	}

	prefix = argv[optind++];
	if (strcmp(prefix, "-") == 0 && argc > optind + 1)
	{
		log_error("only one stream can be dumped on stdout.");
		return 1;
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

	/* Preparing streams */
	streams = argc - optind;
	files = malloc(streams * sizeof(int));
	sockets = malloc(streams * sizeof(int));
	if (files == NULL || sockets == NULL)
	{
		log_error("unable to malloc files/sockets tables");
		return 1;
	}
	memset(files, 0, streams * sizeof(int));
	memset(sockets, 0, streams * sizeof(int));

	/* Opening streams & files */
	for (i = optind; i < argc; i++)
	{
		char *colon = strchr(argv[i], ':');
		char *ip, *file;
		struct in_addr addr;
		int port;

		/* Préparation des valeurs */
		if (colon == NULL)
		{
			log_error("stream `%s' is invalid (not in `A.B.C.D:E' form)", argv[i]);
			return 1;
		}

		port = atoi(colon+1);
		if (port <= 0 || port > 65535)
		{
			log_error("stream `%s' is invalid (not in `A.B.C.D:E' form)", argv[i]);
			return 1;
		}

		ip = strndup(argv[i], ((int) colon - (int) argv[i]));
		if (inet_aton(ip, &addr) == 0)
		{
			log_error("stream `%s' is invalid (not in `A.B.C.D:E' form)", argv[i]);
			free(ip);
			terminate();
			return 1;
		}
		free(ip);

		/* Ouverture du fichier */
		if (strcmp(prefix, "-") == 0)
		{
			files[i-optind] = STDOUT_FILENO;
		}
		else
		{
			file = malloc(strlen(prefix) + 15 + 5 + 5 + 2);
			if (file == NULL)
			{
				log_error("unable to malloc filename");
				free(file);
				terminate();
				return 1;
			}
			sprintf(file, "%s%s.%d.ts", prefix, inet_ntoa(addr), port);

			files[i-optind] = open(file, O_CREAT | O_EXCL | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
			if (files[i-optind] < 0)
			{
				log_error("unable to open new file `%s' for dumping (%s)", file, strerror(errno));
				free(file);
				terminate();
				return 1;
			}
			free(file);
		}

		/* Ouverture du socket */
		sockets[i-optind] = udpsocket_ropen(INADDR_ANY, addr.s_addr, port);
		if (sockets[i-optind] < 0)
		{
			terminate();
			return 1;
		}
	}


	/* Main loop (polling & dumping) */
	while (udp_packets != 0)
	{
		fd_set rfds;
		int maxsock = 0;
		struct sockaddr_in from;
		socklen_t fromlen = sizeof(from);

		/* Preparing File Descriptor set */
		FD_ZERO(&rfds);
		for (i = 0; i < streams; i++)
		{
			if (sockets[i] > 0 && files[i] > 0)
			{
				FD_SET(sockets[i], &rfds);
				if (sockets[i] > maxsock)
					maxsock = sockets[i];
			}
		}

		/* Selecting read-ready sockets */
		pselect(maxsock + 1, &rfds, NULL, NULL, NULL, &old_sigmask);

		/* Checking sockets */
		for (i = 0; i < streams; i++)
		{
			if (sockets[i] <= 0 || files[i] <= 0)
				continue;

			if (!FD_ISSET(sockets[i], &rfds))
				continue;

			for (;;)
			{
				udp_read = recvfrom(sockets[i], udp_buffer, UDP_BUFFER, MSG_DONTWAIT, (struct sockaddr *)&from, &fromlen);
				udp_buffer[udp_read] = '\0';
				if (udp_read < 0)
				{
					if (errno == EAGAIN)
						break;

					log_error("unknown error on udp multicast socket (%s)", strerror(errno));
					udpsocket_close(sockets[i]);
					close(files[i]);
					sockets[i] = files[i] = -1;
					break;
				}

				if (udp_packets > 0)
					udp_packets--;

				if (udp_read > 0)
				{
					errno = 0;
					udp_write = write(files[i], udp_buffer, udp_read);
					if (udp_write < udp_read)
					{
						log_error("unknown error on dumpfile (%s)", strerror(errno));
						udpsocket_close(sockets[i]);
						close(files[i]);
						sockets[i] = files[i] = -1;
						break;
					}
				}

				if (udp_read == 0)
				{
					log_info("UDP Source closed the connection");
					udpsocket_close(sockets[i]);
					close(files[i]);
					sockets[i] = files[i] = -1;
					break;
				}
			}
		}
	}


	terminate();
	return 0;
}
