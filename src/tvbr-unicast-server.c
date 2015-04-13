/*****************************************************************************
 * tvbr-unicast-server.c :  TV-Unicaster Control
 *****************************************************************************
 * Copyright (C) 2006 Binet Réseau
 * $Id: tvbr-unicast-server.c 957 2007-02-22 15:57:41Z vinz2 $
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

/**
 *  Parameters
 */
#define CONFIG_BUFFER_SIZE		1024

#define UNICAST_MAX_CHANNELS		64
#define UNICAST_MAX_GROUPS		64
#define UNICAST_MAX_GROUP_PER_ACL	8
#define UNICAST_MAX_ACL			64

#define IPC_DATA_TIMEOUT	1
#define IPC_KEEPALIVE		10
#define IPC_CONNECTIONS		20

/**
 *  Structure definitions
 */
typedef struct {
	char name[IPC_GROUP_LENGTH];
	char url[IPC_URL_LENGTH];
	char ip[IPC_IP_LENGTH];
	uint16_t port;
	uint32_t bandwidth;
} unicast_url;
typedef struct {
	char name[IPC_GROUP_LENGTH];
	int channel_count;
	unicast_url *channels[UNICAST_MAX_CHANNELS];
} unicast_accessgroup;
typedef struct {
	char name[IPC_GROUP_LENGTH];
	uint32_t max_bw;
	uint32_t max_channels;
	uint32_t cur_bw;
	uint32_t cur_channels;
} unicast_bwgroup;

typedef struct {
	uint32_t ip;
	uint32_t mask;
	int access_count;
	int bw_count;
	unicast_accessgroup *access[UNICAST_MAX_GROUP_PER_ACL];
	unicast_bwgroup *bw[UNICAST_MAX_GROUP_PER_ACL];
} unicast_acl;

typedef struct {
	char *tok;
	char *next;
} config_token;

/**
 *  Global variables
 */
int verbosity = 0;
int ipc_socket;
int ipc_sockets[IPC_CONNECTIONS];
uint32_t ipc_ips[IPC_CONNECTIONS];
char ipc_urls[IPC_CONNECTIONS][IPC_URL_LENGTH];
struct timeval ipc_start[IPC_CONNECTIONS];

int unicast_channel_count;
unicast_url unicast_channels[UNICAST_MAX_CHANNELS];
int unicast_access_count;
unicast_accessgroup unicast_access[UNICAST_MAX_GROUPS];
int unicast_bw_count;
unicast_bwgroup unicast_bw[UNICAST_MAX_GROUPS];
int unicast_acl_count;
unicast_acl unicast_acls[UNICAST_MAX_ACL];

/**
 *  Prototypes
 */
inline void log_do (const int, const char *, const char *, va_list)
		__attribute__((format(printf,3,0)));

void terminate_socket_noacl (int);
void terminate_socket (int );

void cleanup_handler (void);
void signal_handler (int)
		__attribute__((noreturn));

inline char *next_token (config_token *);
inline char *first_token (config_token *, char *);

int load_config (const char *config_file);
void compute_acl_limits (void);

void usage (void);

/**
 *  Logging function
 */
inline void log_do (const int minverb, const char *prefix, const char *format, va_list ap)
{
	time_t t;
	struct tm stm;
	char timebuf[20];

	/* Min verbosity */
	if (verbosity < minverb)
		return;

	/* Time of day */
	t = time(NULL);
	if (localtime_r (&t, &stm) == NULL)
		return;
	if (strftime (timebuf, sizeof(timebuf), "%b %d %H:%M:%S", &stm) == 0)
		return;

	/* Writing */
	fprintf(stderr, "%s tvbr-server: %s: ", timebuf, prefix);

	/* Log */
	vfprintf(stderr, format, ap);
	fprintf(stderr, "\n");
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
void terminate_socket_noacl (int i)
{
	struct in_addr addr;
	struct timeval now;
	gettimeofday(&now, NULL);

	addr.s_addr = ipc_ips[i];
	log_info("terminating request for url=%s, ip=%s (duration: %ld seconds)",
		   ipc_urls[i], (ipc_ips[i] > 0 ? inet_ntoa(addr) : "?"),
		   now.tv_sec - ipc_start[i].tv_sec);

	shutdown (ipc_sockets[i], SHUT_RDWR);
	close (ipc_sockets[i]);
	ipc_sockets[i] = 0;
}
void terminate_socket (int i)
{
	terminate_socket_noacl (i);
	compute_acl_limits ();
}
void cleanup_handler ()
{
	int i;

	if (ipc_socket > 0)
	{
		shutdown (ipc_socket, SHUT_RDWR);
		close(ipc_socket);
		ipc_socket = 0;
	}
	for (i = 0; i < IPC_CONNECTIONS; i++)
	{
		if (ipc_sockets[i] > 0)
		{
			terminate_socket (i);
		}
	}
}
void signal_handler (int sig)
{
	if (sig == SIGPIPE)
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
 *  Configuration loading
 */
#define IFTOKEN(token) if (strcmp(ptr, token) == 0)
#define NEXTOKEN ptr = next_token(&tok)
#define BADTOKEN { log_error ("Unknown token '%s' at line %d", ptr, line); fclose (fd); return -1; }
#define IFMISSTOK(str) if (!*ptr) { log_error ("Missing value for '%s' at line %d", str, line); fclose (fd); return -1; }

inline char *next_token (config_token *tok)
{
	int in_string = 0;
	int in_back = 0;

	if (tok == NULL)
		return NULL;

	while (*(tok->next) && (*(tok->next) == ' ' || *(tok->next) == '\t' || *(tok->next) == '\n'))
		tok->next ++;

	tok->tok = tok->next;

	if (*(tok->tok) == '"')
	{
		in_string = 1;
		tok->tok ++;
		tok->next ++;
	}

	while (*(tok->next))
	{
		if (in_string && in_back)
		{
			in_back = 0;
			tok->next ++;
		}
		else if (in_string && !in_back)
		{
			if (*(tok->next) == '\\')
				in_back = 1;
			else if (*(tok->next) == '"')
				in_string = 0;
			tok->next ++;
		}
		else if (!in_string)
		{
			if (*(tok->next) != ' ' && *(tok->next) != '\t' && *(tok->next) != '\n')
			{
				tok->next ++;
			}
			else
			{
				break;
			}
		}
	}

	if (tok->next > tok->tok && *(tok->next-1) == '"')
		tok->next --;
	if (*(tok->next))
		*(tok->next) = '\0';
	tok->next ++;

	return tok->tok;
}
inline char *first_token (config_token *tok, char *str)
{
	if (tok == NULL)
		return NULL;

	tok->tok = str;
	tok->next = str;
	return next_token (tok);
}

int load_config (const char *config_file)
{
	FILE *fd;
	config_token tok;
	char *ptr;
	char buffer[CONFIG_BUFFER_SIZE];
	int line = 0, i;

	/* Opening config file */
	if ((fd = fopen (config_file, "r")) == NULL)
	{
		log_error ("Unable to open conf file '%s' (%s)", config_file, strerror(errno));
		return -1;
	}

	/* Parsing */
	while (!feof (fd))
	{
		line ++;
		if (fgets(buffer, CONFIG_BUFFER_SIZE, fd) == NULL)
		{
			if (!feof (fd))
			{
				log_error ("Error while reading file '%s' (%s)", config_file, strerror(errno));
			}
			break;
		}
		if (strlen(buffer) >= CONFIG_BUFFER_SIZE - 1)
		{
			log_error ("Line length exceeded maximum (%zu > %d), aborting configuration loading", strlen(buffer), CONFIG_BUFFER_SIZE - 2);
			fclose (fd);
			return -1;
		}

		ptr = first_token (&tok, buffer);
		if (*ptr == '#' || *ptr == '\n' || *ptr == '\0')
			continue;

		IFTOKEN("add")
		{
			NEXTOKEN;
			IFTOKEN("channel")
			{
				unicast_url *url = &(unicast_channels[unicast_channel_count++]);
				if (unicast_channel_count > UNICAST_MAX_CHANNELS)
				{
					log_error ("Unable to add another channel, maximum reached (%d)", UNICAST_MAX_CHANNELS);
					fclose (fd);
					return -1;
				}

				url->name[0] = '\0';
				url->url[0] = '\0';
				url->ip[0] = '\0';
				url->port = 0;
				url->bandwidth = 0;

				while (*(NEXTOKEN))
				{
					IFTOKEN("name")
					{
						NEXTOKEN;
						IFMISSTOK("name");
						strncpy(url->name, ptr, sizeof(url->name));
						url->name[sizeof(url->name) - 1] = '\0';
					}
					else IFTOKEN("url")
					{
						NEXTOKEN;
						IFMISSTOK("url");
						strncpy(url->url, ptr, sizeof(url->url));
						url->url[sizeof(url->url) - 1] = '\0';
					}
					else IFTOKEN("ip")
					{
						struct in_addr addr;

						NEXTOKEN;
						IFMISSTOK("ip");
						strncpy(url->ip, ptr, sizeof(url->ip));
						url->ip[sizeof(url->ip) - 1] = '\0';

						if (inet_aton(url->ip, &addr) == 0)
						{
							log_error ("Invalid ip for 'add channel' at line %d", line);
							fclose (fd);
							return -1;
						}
					}
					else IFTOKEN("port")
					{
						NEXTOKEN;
						IFMISSTOK("port");
						url->port = strtoul (ptr, NULL, 10);
					}
					else IFTOKEN("bw")
					{
						NEXTOKEN;
						IFMISSTOK("bw");
						url->bandwidth = strtoul (ptr, NULL, 10);
					}
					else BADTOKEN;
				}

				/* Checking mandatory fields */
				if (url->name[0] == '\0')
				{
					log_error ("New channel at line %d must have a name", line);
					fclose (fd);
					return -1;
				}
				if (url->url[0] == '\0')
				{
					log_error ("New channel at line %d must have an url", line);
					fclose (fd);
					return -1;
				}
				if (url->ip[0] == '\0')
				{
					log_error ("New channel at line %d must have a source ip", line);
					fclose (fd);
					return -1;
				}
				if (url->port == 0)
				{
					log_error ("New channel at line %d must have a source port", line);
					fclose (fd);
					return -1;
				}
				if (url->bandwidth == 0)
				{
					log_error ("New channel at line %d must have a bandwidth value", line);
					fclose (fd);
					return -1;
				}

				log_info ("Adding a new channel: name '%s', url '%s', source '%s:%d', bandwidth %d kbps",
					   url->name, url->url, url->ip, url->port, url->bandwidth);
			}
			else IFTOKEN("access-group")
			{
				unicast_accessgroup *access = &(unicast_access[unicast_access_count++]);
				if (unicast_access_count > UNICAST_MAX_GROUPS)
				{
					log_error ("Unable to add another access-group, maximum reached (%d)", UNICAST_MAX_GROUPS);
					fclose (fd);
					return -1;
				}

				access->name[0] = '\0';
				access->channel_count = 0;

				while (*(NEXTOKEN))
				{
					IFTOKEN("name")
					{
						NEXTOKEN;
						IFMISSTOK("name");
						strncpy(access->name, ptr, sizeof(access->name));
						access->name[sizeof(access->name) - 1] = '\0';
					}
					else IFTOKEN("channels")
					{
						char *bptr, echar;

						NEXTOKEN;
						IFMISSTOK("channels");

						while (*ptr)
						{
							bptr = ptr;
							while (*ptr && *ptr != ',')
							{
								ptr++;
							}
							echar = *ptr;
							*ptr = '\0';

							/* Looking for bptr in channel list */
							for (i = 0; i < unicast_channel_count; i++)
							{
								if (strncmp(unicast_channels[i].name, bptr, sizeof(unicast_channels[i].name)) == 0)
								{
									if (access->channel_count >= UNICAST_MAX_CHANNELS)
									{
										log_error ("In new access-group at line %d: maximum channel count reached (%d)", line, UNICAST_MAX_CHANNELS);
										fclose (fd);
										return -1;
									}

									access->channels[access->channel_count++] = &(unicast_channels[i]);
									break;
								}
							}
							if (i == unicast_channel_count)
							{
								log_error ("In new access-group at line %d: channel '%s' does not exist", line, bptr);
								fclose (fd);
								return -1;
							}

							*ptr = echar;
							if (*ptr)
								ptr++;
						}
					}
					else BADTOKEN;
				}

				/* Checking mandatory field */
				if (access->name[0] == '\0')
				{
					log_error ("New access-group at line %d must have a name", line);
					fclose (fd);
					return -1;
				}

				log_info ("Adding a new access-group: name '%s', %d channels", access->name, access->channel_count);
			}
			else IFTOKEN("bw-group")
			{
				unicast_bwgroup *bwgroup = &(unicast_bw[unicast_bw_count++]);
				if (unicast_bw_count > UNICAST_MAX_GROUPS)
				{
					log_error ("Unable to add another bw-group, maximum reached (%d)", UNICAST_MAX_GROUPS);
					fclose (fd);
					return -1;
				}

				bwgroup->name[0] = '\0';
				bwgroup->max_bw = 0;
				bwgroup->max_channels = 0;

				while (*(NEXTOKEN))
				{
					IFTOKEN("name")
					{
						NEXTOKEN;
						IFMISSTOK("name");
						strncpy(bwgroup->name, ptr, sizeof(bwgroup->name));
						bwgroup->name[sizeof(bwgroup->name) - 1] = '\0';
					}
					else IFTOKEN("max-bw")
					{
						NEXTOKEN;
						IFMISSTOK("max-bw");
						bwgroup->max_bw = strtoul (ptr, NULL, 10);
					}
					else IFTOKEN("max-channels")
					{
						NEXTOKEN;
						IFMISSTOK("max-channels");
						bwgroup->max_channels = strtoul (ptr, NULL, 10);
					}
					else BADTOKEN;
				}

				/* Checking mandatory field */
				if (bwgroup->name[0] == '\0')
				{
					log_error ("New bw-group at line %d must have a name", line);
					fclose (fd);
					return -1;
				}

				log_info ("Adding a new bw-group: name '%s', max-channels %d, max-bw %d kbps",
					    bwgroup->name, bwgroup->max_channels, bwgroup->max_bw);
			}
			else IFTOKEN("acl")
			{
				struct in_addr addr;
				unicast_acl *acl = &(unicast_acls[unicast_acl_count++]);
				unsigned int masklen = 0;
				if (unicast_acl_count > UNICAST_MAX_ACL)
				{
					log_error ("Unable to add another ACL rule, maximum reached (%d)", UNICAST_MAX_ACL);
					fclose (fd);
					return -1;
				}

				acl->ip = 0;
				acl->mask = 0;
				acl->access_count = 0;
				acl->bw_count = 0;

				while (*(NEXTOKEN))
				{
					IFTOKEN("ip")
					{
						struct in_addr parsed_addr;
						char *maskptr;
						NEXTOKEN;
						IFMISSTOK("ip");

						/* Mask */
						maskptr = ptr;
						while (*maskptr && *maskptr != '/')
						{
							maskptr++;
						}
						if (! *maskptr)
						{
							log_error ("Invalid ip/mask for 'add acl' at line %d (missing mask)", line);
							fclose (fd);
							return -1;
						}
						*maskptr = '\0';
						maskptr++;
						masklen = strtoul (maskptr, NULL, 10);

						acl->mask = (0xffffffff << (32-masklen)) & 0xffffffff;

						/* IP */
						if (inet_aton(ptr, &parsed_addr) == 0)
						{
							log_error ("Invalid ip/mask for 'add acl' at line %d", line);
							fclose (fd);
							return -1;
						}
						acl->ip = parsed_addr.s_addr;
					}
					else IFTOKEN("access-groups")
					{
						char *bptr, echar;

						NEXTOKEN;
						IFMISSTOK("access-groups");

						while (*ptr)
						{
							bptr = ptr;
							while (*ptr && *ptr != ',')
							{
								ptr++;
							}
							echar = *ptr;
							*ptr = '\0';

							/* Looking for bptr in access-group list */
							for (i = 0; i < unicast_access_count; i++)
							{
								if (strncmp(unicast_access[i].name, bptr, sizeof(unicast_access[i].name)) == 0)
								{
									if (acl->access_count >= UNICAST_MAX_GROUP_PER_ACL)
									{
										log_error ("In new acl at line %d: maximum access-group count reached (%d)", line, UNICAST_MAX_GROUP_PER_ACL);
										fclose (fd);
										return -1;
									}

									acl->access[acl->access_count++] = &(unicast_access[i]);
									break;
								}
							}
							if (i == unicast_access_count)
							{
								log_error ("In new acl at line %d: access-group '%s' does not exist", line, bptr);
								fclose (fd);
								return -1;
							}

							*ptr = echar;
							if (*ptr)
								ptr++;
						}
					}
					else IFTOKEN("bw-groups")
					{
						char *bptr, echar;

						NEXTOKEN;
						IFMISSTOK("bw-groups");

						while (*ptr)
						{
							bptr = ptr;
							while (*ptr && *ptr != ',')
							{
								ptr++;
							}
							echar = *ptr;
							*ptr = '\0';

							/* Looking for bptr in bw-group list */
							for (i = 0; i < unicast_bw_count; i++)
							{
								if (strncmp(unicast_bw[i].name, bptr, sizeof(unicast_bw[i].name)) == 0)
								{
									if (acl->bw_count >= UNICAST_MAX_GROUP_PER_ACL)
									{
										log_error ("In new acl at line %d: maximum bw-group count reached (%d)", line, UNICAST_MAX_GROUP_PER_ACL);
										fclose (fd);
										return -1;
									}

									acl->bw[acl->bw_count++] = &(unicast_bw[i]);
									break;
								}
							}
							if (i == unicast_bw_count)
							{
								log_error ("In new acl at line %d: bw-group '%s' does not exist", line, bptr);
								fclose (fd);
								return -1;
							}

							*ptr = echar;
							if (*ptr)
								ptr++;
						}
					}
					else BADTOKEN;
				}

				/* Checking mandatory field */
				if (acl->ip == 0)
				{
					log_error ("New acl rule at line %d must have an ip/mask pair", line);
					fclose (fd);
					return -1;
				}

				addr.s_addr = acl->ip;
				log_info ("Adding a new ACL rule: ip %s/%d, bw-group count %d, access-group count %d",
					    inet_ntoa(addr), masklen, acl->bw_count, acl->access_count);
			}
			else BADTOKEN;
		}
		else BADTOKEN;
	}

	fclose (fd);
	return 0;
}

/**
 *  ACL Computing
 */
void compute_acl_limits ()
{
	int i, u, a, g;

	/* Resetting usage */
	for (g = 0; g < unicast_bw_count; g++)
	{
		unicast_bw[g].cur_bw = 0;
		unicast_bw[g].cur_channels = 0;
	}

	/* Recomputing */
	for (i = 0; i < IPC_CONNECTIONS; i++)
	{
		if (ipc_sockets[i] <= 0)
			continue;

		for (u = 0; u < unicast_channel_count; u++)
		{
			if (strncasecmp(unicast_channels[u].url, ipc_urls[i], IPC_URL_LENGTH) == 0)
			{
				for (a = 0; a < unicast_acl_count; a++)
				{
					if ((ipc_ips[i] & unicast_acls[a].mask) != unicast_acls[a].ip)
						continue;
					for (g = 0; g < unicast_acls[a].bw_count; g++)
					{
						unicast_acls[a].bw[g]->cur_bw += unicast_channels[u].bandwidth;
						unicast_acls[a].bw[g]->cur_channels ++;
					}
				}
				break;
			}
		}
	}
}

/**
 *  Usage
 */
void usage ()
{
	printf("Usage: tvbr-server [-hvq] -c <path/to/config>\n");
	printf("   -h, --help            Display this help\n");
	printf("   -v, --verbose         More verbose output\n");
	printf("   -q, --quiet           Quieter output\n");
	printf("   -c, --conffile=FILE   Configuration file\n");
	printf("   -d, --disconnect      Disconnect old streaming process before accepting an IP\n");
}

/**
 *  Main function
 */
int main (int argc, char **argv)
{
	char *conffile = NULL;
	int disconnect = 0;
	int optval = 1;
	int i;

	struct sockaddr_un ipc_server;
	ipc_packet ipc_pkt;
	unsigned char ipc_buffer[IPC_BUFFER];
	int ipc_read;

	struct timeval tv, lastkeepalive;

	struct option longopts[] = {
		{"help",       0, 0, 'h'},
		{"usage",      0, 0, 'h'},
		{"verbose",    0, 0, 'v'},
		{"quiet",      0, 0, 'q'},
		{"conffile",   1, 0, 'c'},
		{"disconnect", 0, 0, 'd'},
		{0,            0, 0,  0 }
	};

	/* Initialization */
	gettimeofday(&lastkeepalive, NULL);
	for (i = 0; i < IPC_CONNECTIONS; i++)
	{
		ipc_sockets[i] = 0;
	}
	unicast_channel_count = 0;
	unicast_access_count = 0;
	unicast_bw_count = 0;
	unicast_acl_count = 0;

	/* Parameters */
	for (;;)
	{
		char c = getopt_long(argc, argv, "hvqc:d", longopts, NULL);
		if (c < 0)
			break;

		switch (c)
		{
			case 'h':
				usage ();
				return 0;
			case 'v':
				verbosity ++;
				break;
			case 'q':
				verbosity --;
				break;
			case 'c':
				conffile = optarg;
				break;
			case 'd':
				disconnect = 1;
				break;
			case '?':
				usage();
				return 1;
			case '0':
			default:
				break;
		}
	}

	if (conffile == NULL)
	{
		log_error("You must provide a configuration file");
		usage ();
		return 1;
	}

	/* Signals */
	signal (SIGHUP, &signal_handler);
	signal (SIGINT, &signal_handler);
	signal (SIGTERM, &signal_handler);
	signal (SIGQUIT, &signal_handler);
	signal (SIGPIPE, &signal_handler);

	/* Loading configuration */
	if (load_config(conffile) < 0)
	{
		return 1;
	}

	/* Preparing IPC Socket */
	ipc_socket = socket(PF_UNIX, SOCK_STREAM, 0);
	if (ipc_socket < 0)
	{
		log_error("Unable to open IPC Unix socket (%s)", strerror(errno));
		cleanup_handler ();
		return 1;
	}
	optval = IPC_BUFFER;
	if (setsockopt(ipc_socket, SOL_SOCKET, SO_RCVBUF, &optval, sizeof(optval)) < 0)
	{
		log_error("Unable to set SO_RCVBUF on IPC socket (%s)", strerror(errno));
		cleanup_handler ();
		return 1;
	}
	if (setsockopt(ipc_socket, SOL_SOCKET, SO_SNDBUF, &optval, sizeof(optval)) < 0)
	{
		log_error("Unable to set SO_SNDBUF on IPC socket (%s)", strerror(errno));
		cleanup_handler ();
		return 1;
	}

	if (unlink(IPC_SOCKET) < 0 && errno != ENOENT)
	{
		log_error("Unable to delete old IPC socket (%s)", strerror(errno));
		cleanup_handler ();
		return 1;
	}

	ipc_server.sun_family = AF_UNIX;
	strncpy(ipc_server.sun_path, IPC_SOCKET, sizeof(ipc_server.sun_path));
	ipc_server.sun_path[sizeof(ipc_server.sun_path)-1] = '\0';
	if (bind(ipc_socket, (struct sockaddr *) &ipc_server, sizeof(ipc_server)) < 0)
	{
		log_error("Unable to bind IPC socket to %s (%s)", IPC_SOCKET, strerror(errno));
		cleanup_handler ();
		return 1;
	}

	if (chmod(IPC_SOCKET, S_IRUSR|S_IWUSR|S_IXUSR | S_IRGRP|S_IWGRP|S_IXGRP | S_IROTH|S_IWOTH|S_IXOTH) < 0)
	{
		log_error("Unable to chmod to 777 socket %s (%s)", IPC_SOCKET, strerror(errno));
		cleanup_handler ();
		return 1;
	}

	if (listen(ipc_socket, 1) < 0)
	{
		log_error("Unable to listen on IPC socket (%s)", strerror(errno));
		cleanup_handler ();
		return 1;
	}

	/* Avoid connection Hang */
	if (fcntl(ipc_socket, F_SETFD, O_NONBLOCK) < 0)
	{
		log_error("Unable to set O_NONBLOCK mode on IPC socket (%s)", strerror(errno));
		cleanup_handler ();
		return 1;
	}

	/* Main loop */
	for (;;)
	{
		fd_set rfds;
		int maxsocket;
		int keepalive = 0;

		/* Keeping connection alive */
		gettimeofday (&tv, NULL);
		if (lastkeepalive.tv_sec + IPC_KEEPALIVE < tv.tv_sec)
		{
			keepalive = 1;
			lastkeepalive = tv;
		}

		/* Preparing select */
		FD_ZERO(&rfds);

		maxsocket = ipc_socket;
		FD_SET(ipc_socket, &rfds);

		for (i = 0; i < IPC_CONNECTIONS; i++)
		{
			if (ipc_sockets[i] > 0)
			{
				FD_SET(ipc_sockets[i], &rfds);
				maxsocket = (maxsocket < ipc_sockets[i] ? ipc_sockets[i] : maxsocket);
			}
		}

		tv.tv_sec = IPC_DATA_TIMEOUT;
		tv.tv_usec = 0;

		/* Selecting */
		select(maxsocket + 1, &rfds, NULL, NULL, &tv);

		/* Accepting new connections */
		if (FD_ISSET(ipc_socket, &rfds))
		{
			int socket = 0;

			while (socket < IPC_CONNECTIONS && ipc_sockets[socket] != 0)
			{
				socket ++;
			}
			if (socket == IPC_CONNECTIONS)
			{
				log_warn("dropping incoming connection (socket list is full)");
				socket = accept(ipc_socket, NULL, NULL);

				if (socket > 0)
				{
					shutdown (socket, SHUT_RDWR);
					close (socket);
				}
			}
			else
			{
				log_info("accepting incoming connection (position %d)", socket);
				ipc_sockets[socket] = accept(ipc_socket, NULL, NULL);
				if (ipc_sockets[socket] < 0)
				{
					ipc_sockets[socket] = 0;
					if (errno != EAGAIN && errno != EWOULDBLOCK)
					{
						log_error("unable to accept incoming connection (%s)", strerror(errno));
					}
				}
				else
				{
					ipc_urls[socket][0] = '\0';
					ipc_ips[socket] = 0;
					gettimeofday(&(ipc_start[socket]), NULL);
				}
			}
		}

		/* Reading sockets + keepalive*/
		for (i = 0; i < IPC_CONNECTIONS; i++)
		{
			if (ipc_sockets[i] <= 0)
				continue;

			if (FD_ISSET(ipc_sockets[i], &rfds))
			{
				while (ipc_sockets[i] > 0)
				{
					ipc_read = ipc_recv(ipc_sockets[i], ipc_buffer, IPC_BUFFER, MSG_DONTWAIT);
					if (ipc_read < 0)
					{
						if (errno == EAGAIN)
							break;

						log_warn("unknown error on ipc socket %d (%s)", i, strerror(errno));
						terminate_socket (i);
						break;
					}

					if (ipc_read > 0)
					{
						if (ipc_decode(ipc_buffer, (unsigned int)ipc_read, &ipc_pkt))
						{
							switch (ipc_pkt.headers.type)
							{
								case IPC_NOOP:
									break;

								case IPC_ACCESS_ACCEPT:
								case IPC_ACCESS_DENY:
								case IPC_URLLIST:
								case IPC_BWGROUP_LIST:
								case IPC_CONNECTION_LIST:
									log_info("ignoring server-type message from client %d", i);
									break;

								case IPC_ACCESS_REQUEST:
								{
									uint32_t host_ip;
									char *query_ip;
									uint32_t query_bw;
									unsigned int query_port;
									int u, j, a, g, c;
									int allowed = 0;

									host_ip = ipc_pkt.payload.access_request.host_ip;

									{
                    struct in_addr log_addr;
                    log_addr.s_addr = host_ip;
                    log_debug("AccessRequest for ip=%s, url=%s",
                        inet_ntoa(log_addr), ipc_pkt.payload.access_request.url);
									}

									/* url -> IP conversion */
									for (u = 0; u < unicast_channel_count; u++)
									{
										if (strncasecmp((char *)ipc_pkt.payload.access_request.url, (char *)unicast_channels[u].url, IPC_URL_LENGTH) == 0)
										{
											break;
										}
									}

									if (u == unicast_channel_count)
									{
										const char *denial = "Requested channel was not found in the database.";
										if (!ipc_encode_access_deny(&ipc_pkt, ipc_buffer, denial, 404))
										{
											log_error("Unable to build AccessDeny packet, aborting");
											cleanup_handler ();
											exit (0);
										}
										if (send(ipc_sockets[i], ipc_buffer, ipc_pkt.packet_length, MSG_NOSIGNAL) != (int)ipc_pkt.packet_length)
										{
											terminate_socket (i);
										}
										else
										{
											struct in_addr log_addr;
											log_addr.s_addr = ipc_ips[i];
											log_info("sent AccessDeny for url=%s, ip=%s (not found)", ipc_urls[i], (ipc_ips[i] > 0 ? inet_ntoa(log_addr) : "?"));
										}
										break;
									}

									query_ip = unicast_channels[u].ip;
									query_port = unicast_channels[u].port;
									query_bw = unicast_channels[u].bandwidth;

									strncpy(ipc_urls[i], (char *) ipc_pkt.payload.access_request.url, IPC_URL_LENGTH);
									ipc_ips[i] = host_ip;

									/* Access control */
									allowed = 1;
									for (j = 0; j < IPC_CONNECTIONS; j++)
									{
										if (j == i)
											continue;
										if (ipc_sockets[j] <= 0)
											continue;
										if (ipc_ips[j] == host_ip)
										{
											const char *denial = "Your IP is already receiving one channel; you can only receive one channel at a time.";
											int socket = (disconnect ? j : i);
											if (!ipc_encode_access_deny(&ipc_pkt, ipc_buffer, denial, 403))
											{
												log_error("Unable to build AccessDeny packet, aborting");
												cleanup_handler ();
												exit (0);
											}
											if (send(ipc_sockets[socket], ipc_buffer, ipc_pkt.packet_length, MSG_NOSIGNAL) != (int)ipc_pkt.packet_length)
											{
												terminate_socket_noacl (socket);
											}
											else
											{
												struct in_addr log_addr;
												log_addr.s_addr = ipc_ips[socket];
												log_info("sent AccessDeny for url=%s, ip=%s (one channel per IP)", ipc_urls[socket], (ipc_ips[socket] > 0 ? inet_ntoa(log_addr) : "?"));
											}
											if (!disconnect)
											{
												allowed = 0;
												break;
											}
										}
									}

									if (!allowed)
									{
										break;
									}

									allowed = 0x2;
									for (a = 0; a < unicast_acl_count; a++)
									{
										if ((host_ip & unicast_acls[a].mask) == unicast_acls[a].ip)
										{
											for (g = 0; g < unicast_acls[a].access_count; g++)
											{
												for (c = 0; c < unicast_acls[a].access[g]->channel_count; c++)
												{
													if (strncmp(unicast_acls[a].access[g]->channels[c]->ip, query_ip, IPC_IP_LENGTH) == 0
														&& unicast_acls[a].access[g]->channels[c]->port == query_port)
													  allowed |= 0x1;
												}
											}
											for (g = 0; g < unicast_acls[a].bw_count; g++)
											{
												if ((unicast_acls[a].bw[g]->cur_bw + query_bw > unicast_acls[a].bw[g]->max_bw
													  && unicast_acls[a].bw[g]->max_bw > 0)
													  || (unicast_acls[a].bw[g]->cur_channels + 1 > unicast_acls[a].bw[g]->max_channels
													  && unicast_acls[a].bw[g]->max_channels > 0))
													allowed &= 0x1;
											}
										}
									}

									if (allowed != 0x3)
									{
										const char *denial = NULL;
										switch (allowed)
										{
											case 0x2:
												denial = "The requested channel is not allowed on this computer.";
												break;
											case 0x1:
												denial = "Too much channels are currently streamed on the network; please ask for a less bandwidth consuming channel, or try again later.";
												break;
										}
										if (!ipc_encode_access_deny(&ipc_pkt, ipc_buffer, denial, 403))
										{
											log_error("Unable to build AccessDeny packet, aborting");
											cleanup_handler ();
											exit (0);
										}
										if (send(ipc_sockets[i], ipc_buffer, ipc_pkt.packet_length, MSG_NOSIGNAL) != (int)ipc_pkt.packet_length)
										{
											terminate_socket (i);
										}
										else
										{
											struct in_addr log_addr;
											log_addr.s_addr = ipc_ips[i];
											if (allowed == 0x01)
												log_info("sent AccessDeny for url=%s, ip=%s (bandwidth limit)", ipc_urls[i], (ipc_ips[i] > 0 ? inet_ntoa(log_addr) : "?"));
											else
												log_info("sent AccessDeny for url=%s, ip=%s (channel denied)", ipc_urls[i], (ipc_ips[i] > 0 ? inet_ntoa(log_addr) : "?"));
										}
										break;
									}

									/* Sending back Access Accept */
									compute_acl_limits ();

									if (!ipc_encode_access_accept(&ipc_pkt, ipc_buffer, query_ip, query_port))
									{
										log_error("Unable to build AccessAccept packet, aborting");
										cleanup_handler ();
										exit (0);
									}

									if (send(ipc_sockets[i], ipc_buffer, ipc_pkt.packet_length, MSG_NOSIGNAL) != (int)ipc_pkt.packet_length)
									{
										terminate_socket (i);
									}
									else
									{
										struct in_addr log_addr;
										log_addr.s_addr = ipc_ips[i];
										log_info("sent AccessAccept for url=%s, ip=%s", ipc_urls[i], (ipc_ips[i] > 0 ? inet_ntoa(log_addr) : "?"));
									}
									break;
								}

								case IPC_URLLIST_GET:
								{
									short int urllist[UNICAST_MAX_CHANNELS];
									int a, g, c;
									uint32_t ip = ipc_pkt.payload.request_list.host_ip;

									{
                    struct in_addr log_addr;
                    log_addr.s_addr = ip;
                    log_debug("UrlList request for ip=%s", inet_ntoa(log_addr));
									}

									memset (urllist, 0, sizeof(urllist));

									for (a = 0; a < unicast_acl_count; a++)
									{
										if ((ipc_pkt.payload.request_list.host_ip & unicast_acls[a].mask) == unicast_acls[a].ip)
										{
											for (g = 0; g < unicast_acls[a].access_count; g++)
											{
												for (c = 0; c < unicast_acls[a].access[g]->channel_count; c++)
												{
													size_t pos = ((size_t)(unicast_acls[a].access[g]->channels[c]) - (size_t)unicast_channels) / sizeof(unicast_url);
													if (pos < 0 || pos > UNICAST_MAX_CHANNELS)
													{
														log_error("Bad channel position found in UrlList, aborting");
														cleanup_handler ();
														exit (0);
													}
													urllist[pos] = 1;
												}
											}
										}
									}

									if (ipc_encode_list_answer_url (&ipc_pkt) < 0)
									{
										log_error("Unable to build UrlList packet, aborting");
										cleanup_handler ();
										exit (0);
									}

									for (c = 0; c < UNICAST_MAX_CHANNELS; c++)
									{
										if (urllist[c] > 0)
										{
											ipc_encode_urllist_add (
													&ipc_pkt, ipc_buffer,
													unicast_channels[c].url,
													unicast_channels[c].ip,
													unicast_channels[c].port);
										}
									}

									if (ipc_encode_answer(&ipc_pkt, ipc_buffer, ip) < 0)
									{
										log_error("Unable to build UrlList packet, aborting");
										cleanup_handler ();
										exit (0);
									}
									if (send(ipc_sockets[i], ipc_buffer, ipc_pkt.packet_length, MSG_NOSIGNAL) != (int)ipc_pkt.packet_length)
									{
										terminate_socket (i);
									}
									else
									{
										struct in_addr log_addr;
										log_addr.s_addr = ipc_ips[i];
										log_info("sent UrlList for url=%s, ip=%s (%d elements)", ipc_urls[i], (ipc_ips[i] > 0 ? inet_ntoa(log_addr) : "?"), ipc_pkt.list_length);
									}
									break;
								}

								case IPC_BWGROUP_GET:
								{
									short int bwlist[UNICAST_MAX_GROUPS];
									int a, g, c;
									uint32_t ip = ipc_pkt.payload.request_list.host_ip;

									{
                    struct in_addr log_addr;
                    log_addr.s_addr = ip;
                    log_debug("BwGroupList request for ip=%s", inet_ntoa(log_addr));
									}

									memset (bwlist, 0, sizeof(bwlist));

									for (a = 0; a < unicast_acl_count; a++)
									{
										if ((ipc_pkt.payload.request_list.host_ip & unicast_acls[a].mask) == unicast_acls[a].ip)
										{
											for (g = 0; g < unicast_acls[a].bw_count; g++)
											{
											  size_t pos = ((size_t)(unicast_acls[a].bw[g]) - (size_t)unicast_bw) / sizeof(unicast_bwgroup);
												if (pos < 0 || pos > UNICAST_MAX_GROUPS)
												{
													log_error("Bad bwgroup position found in BwgroupList, aborting");
													cleanup_handler ();
													exit (0);
												}
												bwlist[pos] = 1;
											}
										}
									}

									if (ipc_encode_list_answer_bw (&ipc_pkt) < 0)
									{
										log_error("Unable to build BwGroupList packet, aborting");
										cleanup_handler ();
										exit (0);
									}

									for (c = 0; c < UNICAST_MAX_GROUPS; c++)
									{
										if (bwlist[c] > 0)
										{
											ipc_encode_bwlist_add (
													&ipc_pkt, ipc_buffer,
													unicast_bw[c].name,
													unicast_bw[c].max_bw,
													unicast_bw[c].cur_bw,
													unicast_bw[c].max_channels,
													unicast_bw[c].cur_channels);
										}
									}

									if (ipc_encode_answer(&ipc_pkt, ipc_buffer, ip) < 0)
									{
										log_error("Unable to build BwGroupList packet, aborting");
										cleanup_handler ();
										exit (0);
									}
									if (send(ipc_sockets[i], ipc_buffer, ipc_pkt.packet_length, MSG_NOSIGNAL) != (int)ipc_pkt.packet_length)
									{
										terminate_socket (i);
									}
									else
									{
										struct in_addr log_addr;
										log_addr.s_addr = ipc_ips[i];
										log_info("sent BwGroupList for url=%s, ip=%s (%d elements)", ipc_urls[i], (ipc_ips[i] > 0 ? inet_ntoa(log_addr) : "?"), ipc_pkt.list_length);
									}
									break;
								}

								case IPC_CONNECTION_GET:
								{
									int c;
									uint32_t ip = ipc_pkt.payload.request_list.host_ip;

									{
                    struct in_addr log_addr;
                    log_addr.s_addr = ip;
                    log_debug("ConnectionList request for ip=%s", inet_ntoa(log_addr));
									}

									if (ipc_encode_list_answer_conn (&ipc_pkt) < 0)
									{
										log_error("Unable to build ConnectionList packet, aborting");
										cleanup_handler ();
										exit (0);
									}

									for (c = 0; c < IPC_CONNECTIONS; c++)
									{
										if (ipc_sockets[c] <= 0)
											continue;
										if (ipc_urls[c][0] == '\0')
											continue;

										ipc_encode_connlist_add (&ipc_pkt, ipc_buffer, ipc_ips[c], ipc_urls[c], ipc_start[c].tv_sec);
									}

									if (ipc_encode_answer(&ipc_pkt, ipc_buffer, ip) < 0)
									{
										log_error("Unable to build ConnectionList packet, aborting");
										cleanup_handler ();
										exit (0);
									}
									if (send(ipc_sockets[i], ipc_buffer, ipc_pkt.packet_length, MSG_NOSIGNAL) != (int)ipc_pkt.packet_length)
									{
										terminate_socket (i);
									}
									else
									{
										struct in_addr log_addr;
										log_addr.s_addr = ipc_ips[i];
										log_info("sent ConnectionList for url=%s, ip=%s (%d elements)", ipc_urls[i], (ipc_ips[i] > 0 ? inet_ntoa(log_addr) : "?"), ipc_pkt.list_length);
									}
									break;
								}

								default:
									log_info("unknown type of IPC message, ignoring");
									break;
							}
						}
					}

					if (ipc_read == 0)
					{
						terminate_socket(i);
						break;
					}
				}
			}
			if (keepalive && ipc_sockets[i] > 0)
			{
				ipc_encode_noop (&ipc_pkt, ipc_buffer);
				if (send(ipc_sockets[i], ipc_buffer, ipc_pkt.packet_length, MSG_NOSIGNAL) != (int)ipc_pkt.packet_length)
				{
					terminate_socket (i);
				}
			}
		}
	}

	/* Cleanup */
	cleanup_handler ();
	return 0;
}
