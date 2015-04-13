/*****************************************************************************
 * dump_sap.c :  Dump SAP announcements (udp / multicast)
 *****************************************************************************
 * Copyright (C) 2006 Binet Réseau
 * $Id: dump_sap.c 957 2007-02-22 15:57:41Z vinz2 $
 *
 * Authors: Vincent Zanotti <vincent.zanotti@m4x.org>
 * Inspired from:
 *	(VLC 0.8.5)/modules/services_discovery/sap.c
 *	(MumuDVB 1.2-17)/tools/sap_recup.c
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
#include <sys/types.h>
#include <zlib.h>
#include "log.h"
#include "udpsocket.h"

/**
 * Configuration
 */
#define SAP_PORT 9875
#define SAP_V4_GLOBAL_ADDRESS	"224.2.127.254"
#define SAP_V4_ORG_ADDRESS	"239.195.255.255"
#define SAP_V4_LOCAL_ADDRESS	"239.255.255.255"
#define SAP_V4_LINK_ADDRESS	"224.0.0.255"
#define SAP_BUFFER		5000

/**
 * Macros
 */
#define DISPLAY_NORMAL		0
#define DISPLAY_CSV		1
#define DISPLAY_ZSV		2
#define DISPLAY_PHPSERIALIZED	3
#define DISPLAY_XML		4

#define FREE(a) if (a) { free(a); (a) = NULL; }

#define REMOVE_ELEM(p_ar,i_oldsize,i_pos)						\
	do												\
	{												\
		if((i_oldsize) - (i_pos) - 1)							\
		{											\
			memmove((p_ar) + (i_pos), (p_ar) + (i_pos) + 1,			\
				((i_oldsize) - (i_pos) - 1) * sizeof(*(p_ar)));		\
		}											\
		if(i_oldsize > 1)									\
		{											\
			(p_ar) = realloc(p_ar, ((i_oldsize) - 1) * sizeof(*(p_ar)));\
		}											\
		else											\
		{											\
			free(p_ar);									\
			(p_ar) = NULL;								\
		}											\
		(i_oldsize)--;									\
	}												\
	while(0)

#define TAB_APPEND(count,tab,p)						\
	if((count) > 0)								\
	{										\
		(tab) = realloc(tab, sizeof(void**) * ((count) + 1));	\
	}										\
	else										\
	{										\
		(tab) = malloc(sizeof(void**));				\
	}										\
	(tab)[count] = (p);							\
	(count)++

#define GET_FIELD(store)					\
	psz_eof = strchr(psz_parse, ' ');			\
	if(psz_eof)							\
	{								\
		*psz_eof=0; store = strdup(psz_parse);	\
	}								\
	else								\
	{								\
		if(i_field != 5)					\
		{							\
			b_invalid = 1; break;			\
		}							\
		else							\
		{							\
			store = strdup(psz_parse);		\
		}							\
	}								\
	psz_parse = psz_eof + 1;				\
	i_field++;

/**
 * Structure definitions
 */
typedef struct sdp_t sdp_t;
typedef struct attribute_t attribute_t;
struct sdp_t
{
	char *psz_sdp;

	/* s= field */
	char *psz_sessionname;

	/* Raw m= and c= fields */
	char *psz_connection;
	char *psz_media;

	/* o field */
	char *psz_username;
	char *psz_network_type;
	char *psz_address_type;
	char *psz_address;
	int64_t i_session_id;

	/* "computed" URI */
	char *psz_uri;

	int           i_in; /* IP version */

	int           i_media;
	int           i_media_type;

	int           i_attributes;
	attribute_t  **pp_attributes;
};
struct attribute_t
{
	char *psz_field;
	char *psz_value;
};

/**
 * Global variables
 */
int verbosity = 0;
int sap_display_mode = DISPLAY_NORMAL;
sdp_t **sdp_announces = NULL;
int sdp_announces_size = 0;

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

void sap_output (void);
void sap_parse (const in_addr_t, const char *, const int);
sdp_t* sdp_parse (char *);
int sdp_connection_parse (sdp_t *);

void sdp_free (sdp_t *);
int sdp_same_session (sdp_t *, sdp_t *);
char *get_attribute (sdp_t *, const char *);
int sap_inflate (unsigned char *, unsigned char **, int);

void usage (void);

/**
 * Logging
 */
void log_debug (const char *format, ...)
{
	va_list ap;
	if (verbosity > 1)
	{
		fprintf(stderr, "Debug: ");
		va_start(ap, format);
		vfprintf(stderr, format, ap);
		va_end(ap);
		fprintf(stderr, "\n");
	}
}
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
void log_warn (const char *format, ...)
{
	va_list ap;
	if (verbosity >= 0)
	{
		fprintf(stderr, "Warning: ");
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
	exit(2);
}
void sigalarm_handler (int sig)
{
	sap_output ();
	log_info("timer expired ...");
	terminate();
	exit(0);
}
void terminate ()
{
	alarm(0);
	signal(SIGALRM, SIG_DFL);
	while (sdp_announces_size > 0)
	{
		sdp_free(sdp_announces[sdp_announces_size-1]);
		REMOVE_ELEM(sdp_announces, sdp_announces_size, (sdp_announces_size - 1));
	}
}

/**
 * Output
 */
void sap_output ()
{
	int i, j;

	if (sap_display_mode == DISPLAY_NORMAL)
	{
		for (i = 0; i < sdp_announces_size; i++)
		{
			printf( "[SAP] name=`%s', uri=`%s'\n",
				sdp_announces[i]->psz_sessionname,
				sdp_announces[i]->psz_uri
				);
			printf("      conn=%s, media=%s\n",
				sdp_announces[i]->psz_connection,
				sdp_announces[i]->psz_media
				);
			printf("      user=%s, nettype=%s, addrtype=%s, addr=%s, sid=%" PRId64 "\n",
				sdp_announces[i]->psz_username,
				sdp_announces[i]->psz_network_type,
				sdp_announces[i]->psz_address_type,
				sdp_announces[i]->psz_address,
				sdp_announces[i]->i_session_id
				);
			for (j = 0; j < sdp_announces[i]->i_attributes; j++)
			{
				printf("      attribute:%s=%s\n",
					sdp_announces[i]->pp_attributes[j]->psz_field,
					sdp_announces[i]->pp_attributes[j]->psz_value
					);
			}
		}
	}
	else if (sap_display_mode == DISPLAY_XML)
	{
		printf("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
		for (i = 0; i < sdp_announces_size; i++)
		{
			char *group = get_attribute(sdp_announces[i], "x-plgroup");
                  if (group == NULL)
				group = get_attribute(sdp_announces[i], "plgroup");

			printf("<sap>\n");
			printf("\t<name>%s</name>\n",
					sdp_announces[i]->psz_sessionname);
			printf("\t<group>%s</group>\n",
					(group ? group : ""));
			printf("\t<uri>%s</uri>\n",
					sdp_announces[i]->psz_uri);
			printf("\t<media>%s</media>\n",
					sdp_announces[i]->psz_media);
			printf("\t<owner>%s</owner>\n",
					sdp_announces[i]->psz_username);
			printf("\t<src nettype=\"%s\" addrtype=\"%s\">%s</src>\n",
					sdp_announces[i]->psz_network_type,
					sdp_announces[i]->psz_address_type,
					sdp_announces[i]->psz_address);
			printf("\t<sid>%" PRId64 "</sid>\n",
					sdp_announces[i]->i_session_id);
			printf("</sap>\n");
		}
	}
	else if (sap_display_mode == DISPLAY_CSV || sap_display_mode == DISPLAY_ZSV)
	{
		char sep = (sap_display_mode == DISPLAY_CSV ? ',' : '\0');
		for (i = 0; i < sdp_announces_size; i++)
		{
			char *group = get_attribute(sdp_announces[i], "x-plgroup");
			if (group == NULL)
				group = get_attribute(sdp_announces[i], "plgroup");

			printf("%s%s%c" "name=%s%c" "uri=%s%c" "media=%s%c" "owner=%s%c" "src=%s %s %s%c" "sid=%"PRId64 "\n",
				 (group != NULL ? "group=" : ""), group, sep,
				 sdp_announces[i]->psz_sessionname, sep,
				 sdp_announces[i]->psz_uri, sep,
				 sdp_announces[i]->psz_media, sep,
				 sdp_announces[i]->psz_username, sep,
				 sdp_announces[i]->psz_network_type, sdp_announces[i]->psz_address_type,
				 	sdp_announces[i]->psz_address, sep,
					sdp_announces[i]->i_session_id
				);
		}
	}
	else if (sap_display_mode == DISPLAY_PHPSERIALIZED)
	{
		char tmp[1];

		/* Array start */
		printf("a:%d:{", sdp_announces_size);

		for (i = 0; i < sdp_announces_size; i++)
		{
			char *group = get_attribute(sdp_announces[i], "x-plgroup");
			if (group == NULL)
				group = get_attribute(sdp_announces[i], "plgroup");

			/* Array start */
			printf("i:%d;a:%d:{", i, (group != NULL ? 1 : 0) + 6);

			/* Group */
			if (group != NULL)
				printf("s:5:\"group\";s:%d:\"%s\";", strlen(group), group);

			/* Name */
			printf("s:4:\"name\";s:%d:\"%s\";", strlen(sdp_announces[i]->psz_sessionname), sdp_announces[i]->psz_sessionname);

			/* URI */
			printf("s:3:\"uri\";s:%d:\"%s\";", strlen(sdp_announces[i]->psz_uri), sdp_announces[i]->psz_uri);

			/* Media */
			printf("s:5:\"media\";s:%d:\"%s\";", strlen(sdp_announces[i]->psz_media), sdp_announces[i]->psz_media);

			/* Owner */
			printf("s:5:\"owner\";s:%d:\"%s\";", strlen(sdp_announces[i]->psz_username), sdp_announces[i]->psz_username);

			/* SRC */
			printf("s:3:\"src\";a:3:{s:7:\"nettype\";s:%d:\"%s\";s:8:\"addrtype\";s:%d:\"%s\";s:4:\"addr\";s:%d:\"%s\";}",
				 strlen(sdp_announces[i]->psz_network_type), sdp_announces[i]->psz_network_type,
				 strlen(sdp_announces[i]->psz_address_type), sdp_announces[i]->psz_address_type,
				 strlen(sdp_announces[i]->psz_address), sdp_announces[i]->psz_address
				);

			/* SID */
			j = snprintf(tmp, 1, "%"PRId64, sdp_announces[i]->i_session_id);
			printf("s:3:\"sid\";s:%d:\"%"PRId64"\";", j, sdp_announces[i]->i_session_id);

			/* Array stop */
			printf("}");
		}

		/* Array stop */
		printf("}");
	}
}

/**
 * SAP/SDP Parsing
 */
void sap_parse(const in_addr_t from, const char* buffer, const int buf_length)
{
	int sap_version, sap_address_type, sap_hash, i;
	int sap_delete = 0, sap_compressed;
	char *sap_sdp, *sap_initial_sdp, *sap_foo;
	sdp_t *p_sdp;

	/* Headers */
	sap_version = buffer[0] >> 5;
	if (sap_version != 1)
	{
		log_debug("[SAP] strange sap version %d found", sap_version);
	}

	sap_address_type = buffer[0] & 0x10;
	if ((buffer[0] & 0x08) != 0)
	{
		log_warn("[SAP] reserved bit incorrectly set");
		return;
	}

	if ((buffer[0] & 0x04) != 0)
	{
		sap_delete = 1;
	}

	if (buffer[0] & 0x02)
	{
		log_warn("[SAP] encrypted packet, unsupported");
		return;
	}

	sap_compressed = buffer[0] & 0x01;
	sap_hash = (buffer[2] << 8) + buffer[3];
	if (sap_hash == 0)
	{
		log_warn("[SAP] discarding announce with null id hash");
		return;
	}

	/* Parsing packet */
	sap_initial_sdp = sap_sdp = (char *)buffer + 4;

	if (sap_address_type == 0)
	{
		sap_sdp += 4;
		if (buf_length <= 9)
		{
			log_warn("[SAP] too short SAP packet");
			return;
		}
	}
	else
	{
		sap_sdp += 16;
		if (buf_length <= 21)
		{
			log_warn("[SAP] too short SAP packet");
			return;
		}
	}

	/* Compressed packets */
	if (sap_compressed)
	{
		uint8_t *p_decompressed_buffer = NULL;
		int i_decompressed_size;

		i_decompressed_size = sap_inflate((uint8_t *)sap_sdp, &p_decompressed_buffer, buf_length - (sap_sdp - (char *)buffer));
		if(i_decompressed_size > 0 && i_decompressed_size < SAP_BUFFER)
		{
			memcpy (sap_sdp, p_decompressed_buffer, i_decompressed_size);
			sap_sdp[i_decompressed_size] = '\0';
			free (p_decompressed_buffer);
		}
	}

	/* Add the size of authentification info */
	if (buf_length < buffer[1] + (sap_sdp - sap_initial_sdp))
	{
		log_warn("[SAP] too short SAP packet");
		return;
	}
	sap_sdp += buffer[1];
	sap_foo = sap_sdp;

	/* Skip payload type */
	/* Handle announces without \0 between SAP and SDP */
	while (*sap_sdp != '\0' && sap_sdp[0] != 'v' && sap_sdp[1] != '=')
	{
		if (sap_sdp - sap_initial_sdp >= buf_length - 5)
		{
			log_warn("[SAP] empty SDP ?");
		}
		sap_sdp++;
	}
	if (*sap_sdp == '\0')
	{
		sap_sdp++;
	}
	if ((sap_sdp != sap_foo) && strcasecmp(sap_foo, "application/sdp"))
	{
		log_warn("[SAP] unhandled content type `%s'", sap_foo);
	}
	if ((sap_sdp - buffer) >= buf_length)
	{
		log_warn("[SAP] package without content");
		return;
	}

	/* Parsing sdp announce */
	p_sdp = sdp_parse (sap_sdp);
	if (p_sdp == NULL)
	{
		return;
	}

	/* Parse connection information (c= & m= ) */
	if(sdp_connection_parse(p_sdp) != 0)
	{
		p_sdp->psz_uri = NULL;
	}

	/* Multi-media or no-parse -> pass to LIVE.COM */
	if(p_sdp->i_media > 1 || (p_sdp->i_media_type != 14 && p_sdp->i_media_type != 32 && p_sdp->i_media_type != 33))
	{
		log_warn("[SAP] unparsable SDP announce");
		sdp_free(p_sdp);
		return;
	}
	if (p_sdp->psz_uri == NULL)
		return;

	/* Ajout de l'annonce à la liste */
	for (i = 0; i < sdp_announces_size; i++)
	{
		if (sdp_same_session(p_sdp, sdp_announces[i]))
		{
			REMOVE_ELEM(sdp_announces, sdp_announces_size, i);
			if (sap_delete)
			{
				sdp_free(p_sdp);
				return;
			}
		}
	}

	if (!sap_delete)
	{
		TAB_APPEND(sdp_announces_size, sdp_announces, p_sdp);
	}
}

sdp_t* sdp_parse(char* psz_sdp)
{
	sdp_t *p_sdp;
	int b_invalid = 0;
	int b_end = 0;

	if(psz_sdp == NULL)
	{
		return NULL;
	}

	if(psz_sdp[0] != 'v' || psz_sdp[1] != '=')
	{
		log_warn("[SAP] bad packet");
		return NULL;
	}

	p_sdp = (sdp_t *) malloc(sizeof(sdp_t));
	if(p_sdp == NULL)
		return NULL;

	p_sdp->psz_sdp = strdup(psz_sdp);
	if(p_sdp->psz_sdp == NULL)
	{
		free(p_sdp);
		return NULL;
	}

	p_sdp->psz_sessionname = NULL;
	p_sdp->psz_media       = NULL;
	p_sdp->psz_connection  = NULL;
	p_sdp->psz_uri         = NULL;
	p_sdp->psz_address     = NULL;
	p_sdp->psz_address_type= NULL;

	p_sdp->i_media         = 0;
	p_sdp->i_attributes    = 0;
	p_sdp->pp_attributes   = NULL;

	while(*psz_sdp != '\0' && b_end == 0)
	{
		char *psz_eol = NULL;
		char *psz_eof = NULL;
		char *psz_parse = NULL;
		char *psz_sess_id = NULL;

		while(*psz_sdp == '\r' || *psz_sdp == '\n' || *psz_sdp == ' ' || *psz_sdp == '\t')
		{
			psz_sdp++;
		}

		if((psz_eol = strchr(psz_sdp, '\n')) == NULL)
		{
			psz_eol = psz_sdp + strlen( psz_sdp );
			b_end = 1;
		}
		if(psz_eol > psz_sdp && *(psz_eol - 1) == '\r')
		{
			psz_eol--;
		}

		if(psz_eol <= psz_sdp)
		{
			break;
		}
		*psz_eol++ = '\0';

		/* no space allowed between fields */
		if( psz_sdp[1] != '=' )
		{
			log_warn("[SAP] invalid packet");
			sdp_free( p_sdp );
			return NULL;
		}

		/* Now parse each line */
		switch( psz_sdp[0] )
		{
			case 'v':
				break;
			case 's':
				p_sdp->psz_sessionname = strdup( &psz_sdp[2] );
				break;
			case 'o':
			{
				int i_field = 0;

				/* o field is <username> <session id> <version> <network type> <address type> <address> */
				psz_parse = &psz_sdp[2];
				GET_FIELD( p_sdp->psz_username );
				GET_FIELD( psz_sess_id );

				p_sdp->i_session_id = atoll(psz_sess_id);

				FREE(psz_sess_id);

				GET_FIELD(psz_sess_id);
				FREE(psz_sess_id);

				GET_FIELD( p_sdp->psz_network_type );
				GET_FIELD( p_sdp->psz_address_type );
				GET_FIELD( p_sdp->psz_address );

				break;
			}
			case 'i':
			case 'u':
			case 'e':
			case 'p':
			case 't':
			case 'r':
				break;
			case 'a': /* attribute */
			{
				char *psz_eon = strchr(&psz_sdp[2], ':');
				attribute_t *p_attr = malloc(sizeof( attribute_t));

				/* Attribute with value */
				if(psz_eon)
				{
					*psz_eon++ = '\0';

					p_attr->psz_field = strdup(&psz_sdp[2]);
					p_attr->psz_value = strdup(psz_eon );
				}
				else /* Attribute without value */
				{
					p_attr->psz_field = strdup(&psz_sdp[2]);
					p_attr->psz_value = NULL;
				}

				TAB_APPEND(p_sdp->i_attributes, p_sdp->pp_attributes, p_attr);
				break;
			}

			case 'm': /* Media announcement */
			{
				p_sdp->i_media++;
				if( p_sdp->i_media == 1 )
				{
					p_sdp->psz_media = strdup(&psz_sdp[2]);
				}
				break;
			}

			case 'c':
			{
				if( p_sdp->i_media > 1 )
					break;

				p_sdp->psz_connection = strdup(&psz_sdp[2]);
				break;
			}

			default:
				break;
		}

		if(b_invalid)
		{
			sdp_free(p_sdp);
			return NULL;
		}

		psz_sdp = psz_eol;
	}

	return p_sdp;
}
int sdp_connection_parse(sdp_t *p_sdp)
{
	char *psz_eof;
	char *psz_parse;
	char *psz_uri = NULL;
	char *psz_proto = NULL;
	char psz_source[256];
	int i_port = 0;

	/* Parse c= field */
	if(p_sdp->psz_connection)
	{
		psz_parse = p_sdp->psz_connection;

		psz_eof = strchr(psz_parse, ' ');

		if(psz_eof)
		{
			*psz_eof = '\0';
			psz_parse = psz_eof + 1;
		}
		else
		{
			log_warn("[SAP] unable to parse c field (1)");
			return -1;
		}

		psz_eof = strchr(psz_parse, ' ');

		if(psz_eof)
		{
			*psz_eof = '\0';
			if(!strncmp(psz_parse, "IP4", 3))
			{
				p_sdp->i_in = 4;
			}
			else if(!strncmp(psz_parse, "IP6", 3))
			{
				p_sdp->i_in = 6;
			}
			else
			{
				p_sdp->i_in = 0;
			}
			psz_parse = psz_eof + 1;
		}
		else
		{
			log_warn("[SAP] unable to parse c field (2)");
			return -1;
		}

		psz_eof = strchr(psz_parse, '/');

		if(psz_eof)
		{
			*psz_eof = '\0';
		}
		else
		{
			log_warn("[SAP] incorrect c field, `%s'", p_sdp->psz_connection);
		}
		if(p_sdp->i_in == 6 && (isxdigit(*psz_parse) || *psz_parse == ':'))
		{
			asprintf(&psz_uri, "[%s]", psz_parse);
		}
		else
		{
			psz_uri = strdup(psz_parse);
		}
	}

	/* Parse m= field */
	if( p_sdp->psz_media )
	{
		psz_parse = p_sdp->psz_media;
		psz_eof = strchr( psz_parse, ' ' );
		if( psz_eof )
		{
			*psz_eof = '\0';
			if( strncmp( psz_parse, "audio", 5 )  &&
						 strncmp( psz_parse, "video", 5 ) )
			{
				log_warn("[SAP] unhandled media type -%s-", psz_parse);
				FREE( psz_uri );
				return -1;
			}
			psz_parse = psz_eof + 1;
		}
		else
		{
			log_warn("[SAP] unable to parse m field (1)");
			FREE( psz_uri );
			return -1;
		}

		psz_eof = strchr(psz_parse, ' ');
		if(psz_eof)
		{
			*psz_eof = '\0';

			/* FIXME : multiple port ! */
			i_port = atoi(psz_parse);

			if(i_port <= 0 || i_port >= 65536)
			{
				log_warn("[SAP] invalid transport port %i", i_port);
			}
			psz_parse = psz_eof + 1;
		}
		else
		{
			log_warn("[SAP] unable to parse m field (2)");
			FREE( psz_uri );
			return -1;
		}

		psz_eof = strchr(psz_parse, ' ');
		if(psz_eof)
		{
			*psz_eof = '\0';
			psz_proto = strdup(psz_parse);

			psz_parse = psz_eof + 1;
			p_sdp->i_media_type = atoi(psz_parse);
		}
		else
		{
			log_warn("[SAP] incorrect m field `%s'", p_sdp->psz_media);
			p_sdp->i_media_type = 33;
			psz_proto = strdup(psz_parse);
		}
	}

	if(psz_proto && !strncmp(psz_proto, "RTP/AVP", 7))
	{
		free(psz_proto);
		psz_proto = strdup("rtp");
	}
	if(psz_proto && !strncasecmp(psz_proto, "UDP", 3))
	{
		free(psz_proto);
		psz_proto = strdup("udp");
	}

	if(i_port == 0)
	{
		i_port = 1234;
	}

	/* handle SSM case */
	psz_parse = get_attribute( p_sdp, "source-filter" );
	psz_source[0] = '\0';

	if(psz_parse)
	{
		sscanf(psz_parse, " incl IN IP%*s %*s %255s ", psz_source);
	}

	asprintf(&p_sdp->psz_uri, "%s://%s@%s:%i", psz_proto, psz_source, psz_uri, i_port);

	log_info("[SAP] parsed uri: %s", p_sdp->psz_uri);

	FREE( psz_uri );
	FREE( psz_proto );
	return 0;
}

/**
 * SDP/SAP Helper functions
 */
void sdp_free(sdp_t *p_sdp)
{
	int i;
	FREE( p_sdp->psz_sdp );
	FREE( p_sdp->psz_sessionname );
	FREE( p_sdp->psz_connection );
	FREE( p_sdp->psz_media );
	FREE( p_sdp->psz_uri );
	FREE( p_sdp->psz_username );
	FREE( p_sdp->psz_network_type );

	FREE( p_sdp->psz_address );
	FREE( p_sdp->psz_address_type );

	for( i= p_sdp->i_attributes - 1; i >= 0 ; i-- )
	{
		struct attribute_t *p_attr = p_sdp->pp_attributes[i];
		FREE( p_sdp->pp_attributes[i]->psz_field );
		FREE( p_sdp->pp_attributes[i]->psz_value );
		REMOVE_ELEM( p_sdp->pp_attributes, p_sdp->i_attributes, i);
		FREE( p_attr );
	}
	free( p_sdp );
}
char *get_attribute(sdp_t *p_sdp, const char *psz_search)
{
	int i;

	for(i = 0 ; i< p_sdp->i_attributes; i++)
	{
		if(!strncmp(p_sdp->pp_attributes[i]->psz_field, psz_search, strlen(p_sdp->pp_attributes[i]->psz_field)))
		{
			return p_sdp->pp_attributes[i]->psz_value;
		}
	}
	return NULL;
}
int sdp_same_session(sdp_t *p_sdp1, sdp_t *p_sdp2)
{
	/* A session is identified by username, session_id, network type, address type and address */
	if( p_sdp1->psz_username && p_sdp2->psz_username &&
		   p_sdp1->psz_network_type && p_sdp2->psz_network_type &&
		   p_sdp1->psz_address_type && p_sdp2->psz_address_type &&
		   p_sdp1->psz_address &&  p_sdp2->psz_address &&
		   p_sdp1->psz_uri && p_sdp2->psz_uri )
	{
		if(!strcmp( p_sdp1->psz_username , p_sdp2->psz_username ) &&
				  !strcmp( p_sdp1->psz_network_type , p_sdp2->psz_network_type ) &&
				  !strcmp( p_sdp1->psz_address_type , p_sdp2->psz_address_type ) &&
				  !strcmp( p_sdp1->psz_address , p_sdp2->psz_address ) &&
				  !strcmp( p_sdp1->psz_uri , p_sdp2->psz_uri ) )
		{
			return 1;
		}
		else
		{
			return 0;
		}
	}
	else
	{
		return 0;
	}
}
int sap_inflate(unsigned char *psz_src, unsigned char **_dst, int i_len)
{
	int i_result, i_dstsize, n;
	unsigned char *psz_dst;
	z_stream d_stream;

	d_stream.zalloc = (alloc_func) 0;
	d_stream.zfree = (free_func) 0;
	d_stream.opaque = (voidpf) 0;

	i_result = inflateInit(&d_stream);
	if (i_result != Z_OK)
	{
		log_error("inflateInit() failed (%d)", i_result);
		return -1;
	}
	d_stream.next_in = (Bytef *)psz_src;
	d_stream.avail_in = i_len;
	n = 0;

	psz_dst = NULL;
	do
	{
		n++;
		psz_dst = (unsigned char *) realloc(psz_dst, n * 1000);
		d_stream.next_out = (Bytef *) &psz_dst[(n - 1) * 1000];
		d_stream.avail_out = 1000;

		i_result = inflate(&d_stream, Z_NO_FLUSH);
		if ((i_result != Z_OK) && (i_result != Z_STREAM_END))
		{
			log_error("Zlib decompression failed (%d)", i_result);
			return -1;
		}
	}
	while ((d_stream.avail_out == 0) && (d_stream.avail_in != 0) &&  (i_result != Z_STREAM_END));

	i_dstsize = d_stream.total_out;
	inflateEnd (&d_stream);

	*_dst = (unsigned char *) realloc(psz_dst, i_dstsize);

	return i_dstsize;
}

/**
 * Main functions
 */
void usage ()
{
	printf("Usage: dump_sap [-hvq] [-l <localaddr>] [-d <seconds>] [-n <packets>] [-m <dispmode>]\n");
	printf("   -h, --help            Display this help\n");
	printf("   -v, --verbose         Verbose output\n");
	printf("   -q, --quiet           Quiet output\n");
	printf("   -l, --laddr=ADDR      Use ADDR as local interface address\n");
	printf("   -d, --duration=SECS   Stop dumping after SECS seconds (default: 30 secs)\n");
	printf("   -n, --count=N         Stop dumping after N packets (default: no limit)\n");
	printf("   -m, --mode=MODE       Use MODE as output display mode\n");
	printf("             verbose       Verbose, human-readable mode (default)\n");
	printf("             csv           Comma separated values\n");
	printf("             zsv           Zero (\\0) separated values (binary safe)\n");
	printf("             php           PHP serialized array (binary safe)\n");
	printf("             xml           XML Output\n");
}
int main (int argc, char** argv)
{
	int sap_fd = -1;
	int sap_timeout = 30;
	int sap_packets = -1;
	char sap_buffer[SAP_BUFFER+1];
	int sap_read;
	in_addr_t laddr = INADDR_ANY;

	/* Parameters */
	struct option longopts[] = {
		{"help",		0, 0, 'h'},
		{"usage",		0, 0, 'h'},
		{"verbose",		0, 0, 'v'},
		{"quiet",		0, 0, 'q'},
		{"laddr",		1, 0, 'l'},
		{"duration",	1, 0, 'd'},
		{"count",		1, 0, 'n'},
		{"mode",		1, 0, 'm'},
		{0,			0, 0,  0 }
	};
	while(1)
	{
		char c = getopt_long(argc, argv, "hvql:d:n:m:", longopts, NULL);
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
					return 3;
				}
				break;
			case 'd':
				sap_timeout = atoi(optarg);
				break;
			case 'n':
				sap_packets = atoi(optarg);
				break;
			case 'm':
				if (strcasecmp(optarg, "verbose") == 0)
				{
					sap_display_mode = DISPLAY_NORMAL;
				}
				else if (strcasecmp(optarg, "csv") == 0)
				{
					sap_display_mode = DISPLAY_CSV;
				}
				else if (strcasecmp(optarg, "zsv") == 0)
				{
					sap_display_mode = DISPLAY_ZSV;
				}
				else if (strcasecmp(optarg, "php") == 0)
				{
					sap_display_mode = DISPLAY_PHPSERIALIZED;
				}
				else if (strcasecmp(optarg, "xml") == 0)
				{
					sap_display_mode = DISPLAY_XML;
				}
				else
				{
					log_error("invalid display mode `%s'", optarg);
					usage();
					return 4;
				}
				break;
			default:
				usage();
				return 5;
		}
	}

	/* Signal setup */
	signal(SIGINT, sigterm_handler);
	signal(SIGTERM, sigterm_handler);
	signal(SIGALRM, sigalarm_handler);
	sigalarm_block();

	/* Timeout setup */
	if (sap_timeout > 0)
	{
		log_info("SAP timeout set to %d seconds", sap_timeout);
		alarm(sap_timeout);
	}

	/* Socket */
	sap_fd = udpsocket_ropen(INADDR_ANY, INADDR_ANY, SAP_PORT);
	if (sap_fd < 0)
	{
		exit(0);
	}

	udpsocket_addmc(sap_fd, INADDR_ANY, inet_addr(SAP_V4_GLOBAL_ADDRESS));
	udpsocket_addmc(sap_fd, INADDR_ANY, inet_addr(SAP_V4_ORG_ADDRESS));
	udpsocket_addmc(sap_fd, INADDR_ANY, inet_addr(SAP_V4_LOCAL_ADDRESS));
	udpsocket_addmc(sap_fd, INADDR_ANY, inet_addr(SAP_V4_LINK_ADDRESS));

	/* Main loop (polling & parsing) */
	while (sap_fd > 0 && (sap_packets != 0))
	{
		struct sockaddr_in from;
		unsigned int fromlen = sizeof (from);

		/* Receiving message */
		sigalarm_unblock();
		sap_read = recvfrom(sap_fd, sap_buffer, SAP_BUFFER, 0, (struct sockaddr*) &from, &fromlen);
		sigalarm_block();

		if (sap_read < 0)
		{
			udpsocket_close(sap_fd);
			return 0;
		}
		log_info("got %d bytes from %s:%d", sap_read, inet_ntoa(from.sin_addr), from.sin_port);

		/* Parsing SAP message */
		if (sap_read <= 6)
			continue;
		sap_buffer[sap_read] = '\0';
		sap_parse(from.sin_addr.s_addr, sap_buffer, sap_read);

		if (sap_packets > 0)
			sap_packets --;
	}
	sap_output ();

	terminate();
	return 0;
}
