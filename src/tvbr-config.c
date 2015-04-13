/*****************************************************************************
 * tvbr-config.c :  Configuration parsing
 *****************************************************************************
 * Copyright (C) 2006 Binet Réseau
 * $Id: tvbr-config.c 957 2007-02-22 15:57:41Z vinz2 $
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

#include "tvbr.h"

/**
 *  Structures & PP
 */
#define CONFIG_BUFFER_SIZE 1024

struct config_transponder_t;
struct config_channel_t;
struct config_stream_t;

typedef struct config_transponder_t {
	enum {
		TRANSP_DVBT,
		TRANSP_DVBS
	} type;
	char *name;
	union {
		tvbr_card_dvbt dvbt;
		tvbr_card_dvbs dvbs;
	} u;

	struct config_transponder_t *next;
} config_transponder;
typedef struct config_channel_t {
	char *name;
	char *group;
	char *desc;
	char *transp;

	config_transponder *tptr;

	tvbr_media_type media;
	uint16_t pno;
	int npids;
	uint16_t *pids;

	uint16_t pmt_filter;
	uint16_t pmt_pcr_pid;

	enum {
		MANDATORYPIDS_NONE,
		MANDATORYPIDS_MINIMAL,
		MANDATORYPIDS_FULL
	} mandatory_pids;

	struct config_channel_t *next;
} config_channel;
typedef struct config_stream_t {
	char *channel;
	config_channel *cptr;

	in_addr_t dst_ip;
	unsigned short dst_port;
	unsigned int dst_ttl;

	struct config_stream_t *next;
} config_stream;

typedef struct {
	char *tok;
	char *next;
} config_token;

/**
 *  Global vars
 */
dvb_card_type card_type[DVB_MAX_DEVS];

config_transponder *transponders;
config_channel *channels;
config_stream *streams;

int map_cardtransponder[DVB_MAX_DEVS];
config_transponder *used_transponders[DVB_MAX_DEVS];
int nused_transponders;

/**
 *  Prototypes
 */
void config_cleanup_stream (config_stream *);
void config_cleanup_channel (config_channel *);
void config_cleanup_transponder (config_transponder *);

inline char *next_token (config_token *);
inline char *first_token (config_token *, char *);
inline int isvalidname (const char*)
		__attribute((unused));

/**
 *  Cleanup handler
 */
void config_cleanup_stream (config_stream *st)
{
	if (st == NULL)
		return;

	if (st->channel != NULL)
		free (st->channel);

	st->channel = NULL;

	free (st);
}
void config_cleanup_channel (config_channel *ch)
{
	config_stream **sptr;

	if (ch == NULL)
		return;

	/* Cleaning associated streams */
	sptr = &streams;
	while (*sptr != NULL)
	{
		if (strcmp((*sptr)->channel, ch->name) == 0)
		{
			config_stream *tmp = (*sptr)->next;

			(*sptr)->next = NULL;
			config_cleanup_stream (*sptr);
			*sptr = tmp;
		}
		else
			sptr = &((*sptr)->next);
	}

	/* Cleaning channel */
	if (ch->name != NULL)
		free (ch->name);
	if (ch->transp != NULL)
		free (ch->transp);
	if (ch->group != NULL)
		free (ch->group);
	if (ch->desc != NULL)
		free (ch->desc);
	if (ch->pids != NULL)
		free (ch->pids);

	ch->tptr = NULL;

	ch->name = ch->group = ch->desc = NULL;
	ch->pids = NULL;

	free (ch);
}
void config_cleanup_transponder (config_transponder *tr)
{
	config_channel **cptr;

	if (tr == NULL)
		return;

	/* Cleaning associated channels */
	cptr = &channels;
	while (*cptr != NULL)
	{
		if (strcmp((*cptr)->transp, tr->name) == 0)
		{
			config_channel *tmp = (*cptr)->next;

			(*cptr)->next = NULL;
			config_cleanup_channel (*cptr);
			*cptr = tmp;
		}
		else
			cptr = &((*cptr)->next);
	}

	/* Cleaning transponder */
	if (tr->name != NULL)
		free (tr->name);
	tr->name = NULL;

	free (tr);
}
void config_cleanup ()
{
	config_transponder *tptr, *ttmp;
	config_channel *cptr, *ctmp;
	config_stream *sptr, *stmp;

	log_debug("entering cleanup_config function");

	/* Cleaning transponders */
	tptr = transponders;
	transponders = NULL;
	while (tptr != NULL)
	{
		ttmp = tptr;
		tptr = tptr->next;
		config_cleanup_transponder (ttmp);
	}

	/* Cleaning channels left */
	cptr = channels;
	channels = NULL;
	while (cptr != NULL)
	{
		ctmp = cptr;
		cptr = cptr->next;
		config_cleanup_channel (ctmp);
	}

	/* Cleaning streams left */
	sptr = streams;
	streams = NULL;
	while (sptr != NULL)
	{
		stmp = sptr;
		sptr = sptr->next;
		config_cleanup_stream (stmp);
	}
}

/**
 *  Parse functions
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
inline int isvalidname (const char* ptr)
{
	while (*ptr)
	{
		if (isalnum(*ptr) && isascii(*ptr))
			ptr ++;
		else
			return 0;
	}
	return 1;
}

/**
 *  Card configuration
 */
int config_cards (const char *cards)
{
  int i;

	/* cardlist parsing */
	if (cards != NULL)
	{
		int n;
		const char *ptr = cards;

		for (i = 0; i < DVB_MAX_DEVS; i++)
			card_type[i] = 0;

		while (*ptr)
		{
			log_debug("*ptr = %c", *ptr);
			n = 0;
			i = 0;
			while (*ptr && isdigit(*ptr))
			{
				n ++;
				i = 10 * i + (*ptr - '0');
				ptr ++;
			}

			if (n > 0)
			{
				if (i >= 0 && i < DVB_MAX_DEVS)
				{
					card_type[i] = 1;
					log_debug("Adding card %i to allowed card list", i);
				}
				else
				{
					log_error("Invalid card number in card list (%d)", i);
					return -1;
				}
			}
			if (*ptr == ',')
			{
				ptr ++;
			}
			else if (*ptr)
			{
				log_error("Unknown character '%c' found in cardlist", *ptr);
				return -1;
			}
		}
	}
	else
	{
		for (i = 0; i < DVB_MAX_DEVS; i++)
			card_type[i] = 1;
	}

	/* DVB Cards type */
	for (i = 0; i < DVB_MAX_DEVS; i++)
	{
		if (card_type[i] != DVB_NONE)
		{
			card_type[i] = dvb_type (i);
		}
	}

	return 0;
}

/**
 *  Channel configuration
 */
int config_channels ()
{
	FILE *fd;
	config_token tok;
	char *ptr;
	char buffer[CONFIG_BUFFER_SIZE];
	int line = 0, i;

	/* Initializing */
	for (i = 0; i < DVB_MAX_DEVS; i++)
		map_cardtransponder[i] = -1;

	/* Opening config file */
	if ((fd = fopen ("channels.conf", "r")) == NULL)
	{
		pthread_mutex_lock (&log_strerror_buf_mutex);
		strerror_r(errno, log_strerror_buf, LOG_STRERROR_BUFLEN);
		log_error ("Unable to open 'channels.conf' (%s)", log_strerror_buf);
		pthread_mutex_unlock (&log_strerror_buf_mutex);
		return -1;
	}

	/* Parsing channels.conf file */
	while (!feof (fd))
	{
		line ++;
		if (fgets(buffer, CONFIG_BUFFER_SIZE, fd) == NULL)
		{
			if (!feof (fd))
			{
				pthread_mutex_lock (&log_strerror_buf_mutex);
				strerror_r(errno, log_strerror_buf, LOG_STRERROR_BUFLEN);
				log_error ("Error while reading 'channels.conf' (%s)", log_strerror_buf);
				pthread_mutex_unlock (&log_strerror_buf_mutex);
			}
			break;
		}
		if (strlen(buffer) >= CONFIG_BUFFER_SIZE - 1)
		{
			log_error ("Line length exceeded maximum (%zu > %d), aborting reload", strlen(buffer), CONFIG_BUFFER_SIZE - 2);
			fclose (fd);
			return -1;
		}

		ptr = first_token (&tok, buffer);
		if (*ptr == '#' || *ptr == '\n' || *ptr == '\0')
			continue;

		IFTOKEN("add")
		{
			NEXTOKEN;
			IFTOKEN("transponder")
			{
				config_transponder transp;
				config_transponder *newt;
				config_transponder **tptr;
				transp.next = NULL;
				transp.name = NULL;

				NEXTOKEN;
				IFTOKEN("dvbt")
				{
					transp.type = TRANSP_DVBT;
					transp.u.dvbt.frequency = 0;
					transp.u.dvbt.bandwidth = DVB_T_DEF_BANDWIDTH;
					transp.u.dvbt.hpcoderate = DVB_T_DEF_HPCODERATE;
					transp.u.dvbt.lpcoderate = DVB_T_DEF_LPCODERATE;
					transp.u.dvbt.modulation = DVB_T_DEF_CONSTELL;
					transp.u.dvbt.transmitmode = DVB_T_DEF_TRANSMODE;
					transp.u.dvbt.guardinterval = DVB_T_DEF_GUARD;

					while (*(NEXTOKEN))
					{
						IFTOKEN("freq")
						{
							NEXTOKEN;
							IFMISSTOK("freq");
							transp.u.dvbt.frequency = strtoul (ptr, NULL, 10) * 1000UL;
						}
						else IFTOKEN("name")
						{
							NEXTOKEN;
							IFMISSTOK("name");
							transp.name = ptr;
						}
						else IFTOKEN("bandwidth")
						{
							NEXTOKEN;
							IFMISSTOK("bandwidth");
							IFTOKEN("8MHz")
								transp.u.dvbt.bandwidth = BANDWIDTH_8_MHZ;
							else IFTOKEN("7MHz")
								transp.u.dvbt.bandwidth = BANDWIDTH_7_MHZ;
							else IFTOKEN("6MHz")
								transp.u.dvbt.bandwidth = BANDWIDTH_6_MHZ;
							else IFTOKEN("auto")
								transp.u.dvbt.bandwidth = BANDWIDTH_AUTO;
							else BADTOKEN;
						}
						else IFTOKEN("modulation")
						{
							NEXTOKEN;
							IFMISSTOK("modulation");
							IFTOKEN("qpsk")
								transp.u.dvbt.modulation = QPSK;
							else IFTOKEN("qam16")
								transp.u.dvbt.modulation = QAM_16;
							else IFTOKEN("qam32")
								transp.u.dvbt.modulation = QAM_32;
							else IFTOKEN("qam64")
								transp.u.dvbt.modulation = QAM_64;
							else IFTOKEN("qam128")
								transp.u.dvbt.modulation = QAM_128;
							else IFTOKEN("qam256")
								transp.u.dvbt.modulation = QAM_256;
							else IFTOKEN("auto")
								transp.u.dvbt.modulation = QAM_AUTO;
							else BADTOKEN;
						}
						else IFTOKEN("transmode")
						{
							NEXTOKEN;
							IFMISSTOK("transmode");
							IFTOKEN("2k")
								transp.u.dvbt.transmitmode = TRANSMISSION_MODE_2K;
							else IFTOKEN("8k")
								transp.u.dvbt.transmitmode = TRANSMISSION_MODE_8K;
							else IFTOKEN("auto")
								transp.u.dvbt.transmitmode = TRANSMISSION_MODE_AUTO;
							else BADTOKEN;
						}
						else IFTOKEN("guard")
						{
							NEXTOKEN;
							IFMISSTOK("guard");
							IFTOKEN("1/32")
								transp.u.dvbt.guardinterval = GUARD_INTERVAL_1_32;
							else IFTOKEN("1/16")
								transp.u.dvbt.guardinterval = GUARD_INTERVAL_1_16;
							else IFTOKEN("1/8")
								transp.u.dvbt.guardinterval = GUARD_INTERVAL_1_8;
							else IFTOKEN("1/4")
								transp.u.dvbt.guardinterval = GUARD_INTERVAL_1_4;
							else IFTOKEN("auto")
								transp.u.dvbt.guardinterval = GUARD_INTERVAL_AUTO;
							else BADTOKEN;
						}
						else IFTOKEN("coderate")
						{
							NEXTOKEN;
							IFMISSTOK("coderate");
							IFTOKEN("none")
								transp.u.dvbt.hpcoderate = transp.u.dvbt.lpcoderate = FEC_NONE;
							else IFTOKEN("1/2")
								transp.u.dvbt.hpcoderate = transp.u.dvbt.lpcoderate = FEC_1_2;
							else IFTOKEN("2/3")
								transp.u.dvbt.hpcoderate = transp.u.dvbt.lpcoderate = FEC_2_3;
							else IFTOKEN("3/4")
								transp.u.dvbt.hpcoderate = transp.u.dvbt.lpcoderate = FEC_3_4;
							else IFTOKEN("4/5")
								transp.u.dvbt.hpcoderate = transp.u.dvbt.lpcoderate = FEC_4_5;
							else IFTOKEN("5/6")
								transp.u.dvbt.hpcoderate = transp.u.dvbt.lpcoderate = FEC_5_6;
							else IFTOKEN("6/7")
								transp.u.dvbt.hpcoderate = transp.u.dvbt.lpcoderate = FEC_6_7;
							else IFTOKEN("7/8")
								transp.u.dvbt.hpcoderate = transp.u.dvbt.lpcoderate = FEC_7_8;
							else IFTOKEN("8/9")
								transp.u.dvbt.hpcoderate = transp.u.dvbt.lpcoderate = FEC_8_9;
							else IFTOKEN("auto")
								transp.u.dvbt.hpcoderate = transp.u.dvbt.lpcoderate = FEC_AUTO;
							else BADTOKEN;
						}
						else BADTOKEN;
					}

					/* Checking freq */
					if (transp.u.dvbt.frequency == 0)
					{
						log_error("New transponder at line %d must have a frequency", line);
						fclose (fd);
						return -1;
					}
				}
				else IFTOKEN("dvbs")
				{
					transp.type = TRANSP_DVBS;
					transp.u.dvbs.frequency = 0;
					transp.u.dvbs.symbolrate = 0;
					transp.u.dvbs.polarity = 2;

					while (*(NEXTOKEN))
					{
						IFTOKEN("freq")
						{
							NEXTOKEN;
							IFMISSTOK("freq");
							transp.u.dvbs.frequency = strtoul (ptr, NULL, 10) * 1000UL;
						}
						else IFTOKEN("symbolrate")
						{
							NEXTOKEN;
							IFMISSTOK("symbolrate");
							transp.u.dvbs.symbolrate = strtoul (ptr, NULL, 10) * 1000UL;
						}
						else IFTOKEN("polarity")
						{
							NEXTOKEN;
							IFMISSTOK("polarity");
							IFTOKEN("v")
								transp.u.dvbs.polarity = DVB_S_POLARITY_V;
							else IFTOKEN("h")
								transp.u.dvbs.polarity = DVB_S_POLARITY_H;
							else BADTOKEN;
						}
						else IFTOKEN("name")
						{
							NEXTOKEN;
							IFMISSTOK("name");
							transp.name = ptr;
						} else BADTOKEN;
					}

					/* Checking freq */
					if (transp.u.dvbs.frequency == 0)
					{
						log_error("New transponder at line %d must have a frequency", line);
						fclose (fd);
						return -1;
					}

					/* Checking freq */
					if (transp.u.dvbs.symbolrate == 0)
					{
						log_error("New transponder at line %d must have a symbol rate", line);
						fclose (fd);
						return -1;
					}

					/* Checking polarity */
					if (transp.u.dvbs.polarity > 1)
					{
						log_error("New transponder at line %d must have a polarity", line);
						fclose (fd);
						return -1;
					}
				}
				else BADTOKEN;

				/* Checking transponder name */
				if (transp.name == NULL)
				{
					log_error("New transponder at line %d must have a name", line);
					fclose (fd);
					return -1;
				}

				/* Allocating new structure */
				newt = malloc (sizeof(config_transponder));
				if (newt == NULL)
				{
					log_error("Unable to malloc a new transponder structure");
					fclose (fd);
					return -1;
				}

				memcpy (newt, &transp, sizeof(config_transponder));
				newt->name = strdup (transp.name);

				/* Finding place to insert transponder */
				tptr = &transponders;
				while (*tptr != NULL)
				{
					if (strcmp ((*tptr)->name, newt->name) == 0)
					{
						log_info("Replacing transponder '%s'", newt->name);
						newt->next = (*tptr)->next;
						(*tptr)->next = NULL;
						config_cleanup_transponder (*tptr);
						*tptr = newt;
						break;
					}
					tptr = &((*tptr)->next);
				}
				if (*tptr == NULL)
				{
					log_info("Adding transponder '%s'", newt->name);
					*tptr = newt;
				}
			}
			else IFTOKEN("channel")
			{
				config_channel chan;
				config_channel *newc;
				config_channel **cptr;
				config_transponder *tptr;
				int pids[DVB_MAX_PIDS];
				memset (&chan, 0, sizeof(config_channel));
				memset (pids, 0, sizeof(pids));

				chan.media = TVBR_MEDIA_VIDEO;
				chan.mandatory_pids = MANDATORYPIDS_FULL;
				chan.pmt_filter = 0;
				chan.pmt_pcr_pid = 0;

				/* Looping trough args */
				while (*(NEXTOKEN))
				{
					IFTOKEN("transponder")
					{
						NEXTOKEN;
						IFMISSTOK("transponder");
						chan.transp = ptr;
					}
					else IFTOKEN("name")
					{
						NEXTOKEN;
						IFMISSTOK("name");
						chan.name = ptr;
					}
					else IFTOKEN("group")
					{
						NEXTOKEN;
						IFMISSTOK("group");
						chan.group = ptr;
					}
					else IFTOKEN("desc")
					{
						NEXTOKEN;
						IFMISSTOK("desc");
						chan.desc = ptr;
					}
					else IFTOKEN("media")
					{
						NEXTOKEN;
						IFMISSTOK("media");
						IFTOKEN("audio")
							chan.media = TVBR_MEDIA_AUDIO;
						else IFTOKEN("video")
							chan.media = TVBR_MEDIA_VIDEO;
						else BADTOKEN;
					}
					else IFTOKEN("pno")
					{
						NEXTOKEN;
						IFMISSTOK("pno");
						chan.pno = strtoul (ptr, NULL, 10);
					}
					else IFTOKEN("pids")
					{
						int n;

						NEXTOKEN;
						IFMISSTOK("pids");

						memset (pids, 0, sizeof(pids));

						while (*ptr)
						{
							n = 0;
							i = 0;
							while (*ptr && isdigit(*ptr))
							{
								n ++;
								i = 10 * i + (*ptr - '0');
								ptr ++;
							}

							if (n > 0)
							{
								if (i >= 0 && i < DVB_MAX_PIDS)
								{
									pids[i] = 1;
									chan.npids ++;
								}
								else
								{
									log_error("Invalid pid %d in new channel at line %d", i, line);
									fclose (fd);
									return -1;
								}
							}
							if (*ptr == ',')
							{
								ptr ++;
							}
							else if (*ptr)
							{
								log_error("Unknown character '%c' found in pid list at line %d", *ptr, line);
								fclose (fd);
								return -1;
							}
						}
					}
					else IFTOKEN("pmt-filter")
					{
						NEXTOKEN;
						IFMISSTOK("pmt-filter");
						chan.pmt_filter = strtoul(ptr, NULL, 10);
						if (chan.pmt_filter >= DVB_MAX_PIDS || chan.pmt_filter == 0)
						{
							log_error("Invalid pid %d for pmt-filter in new channel at line %d", chan.pmt_filter, line);
							fclose (fd);
							return -1;
						}
					}
					else IFTOKEN("pmt-pcr-pid")
					{
						NEXTOKEN;
						IFMISSTOK("pmt-pcr-pid");
						chan.pmt_pcr_pid = strtoul(ptr, NULL, 10);
						if (chan.pmt_pcr_pid >= DVB_MAX_PIDS || chan.pmt_pcr_pid == 0)
						{
							log_error("Invalid pid %d for pmt-pcr-pid in new channel at line %d", chan.pmt_pcr_pid, line);
							fclose (fd);
							return -1;
						}
					}
					else IFTOKEN("no-mandatory-pids")
					{
						chan.mandatory_pids = MANDATORYPIDS_NONE;
					}
					else IFTOKEN("minimal-mandatory-pids")
					{
						chan.mandatory_pids = MANDATORYPIDS_MINIMAL;
					}
					else IFTOKEN("all-mandatory-pids")
					{
						chan.mandatory_pids = MANDATORYPIDS_FULL;
					}
					else BADTOKEN;
				}

				/* Checking mandatory args */
				if (chan.name == NULL)
				{
					log_error("New channel at line %d must have a name", line);
					fclose (fd);
					return -1;
				}
				if (chan.transp == NULL)
				{
					log_error("New channel at line %d must have a transponder", line);
					fclose (fd);
					return -1;
				}
				if (chan.npids == 0)
				{
					log_error("New channel at line %d must have pids", line);
					fclose (fd);
					return -1;
				}
				if (chan.pno == 0)
				{
					log_error("New channel at line %d must have a program number", line);
					fclose (fd);
					return -1;
				}

				/* Checking transponder validity */
				tptr = transponders;
				while (tptr != NULL)
				{
					if (strcmp(tptr->name, chan.transp) == 0)
					{
						chan.tptr = tptr;
						break;
					}
					tptr = tptr->next;
				}
				if (chan.tptr == NULL)
				{
					log_error("New channel at line %d must have a valid transponder name", line);
					fclose (fd);
					return -1;
				}

				/* Adding mandatory pids */
				if (chan.mandatory_pids == MANDATORYPIDS_FULL)
				{
					/* PAT - Program Association Table (Table program <-> pmt pid) */
					pids[0] = 1;
					chan.npids ++;
					/* NIT - Network Information Table (transponder list) */
					pids[16] = 1;
					chan.npids ++;
					/* SDT - Service Description Table (service list) */
					pids[17] = 1;
					chan.npids ++;
					/* EIT - Event Information Table (list of current and future programs) */
					pids[18] = 1;
					chan.npids ++;
					/* TDT - Time and Date Table */
					pids[20] = 1;
					chan.npids ++;
				}
				else if (chan.mandatory_pids == MANDATORYPIDS_MINIMAL)
				{
					/* PAT - Program Association Table (Table program <-> pmt pid) */
					pids[0] = 1;
					chan.npids ++;
					/* EIT - Event Information Table (list of current and future programs) */
					pids[18] = 1;
					chan.npids ++;
					/* TDT - Time and Date Table */
					pids[20] = 1;
					chan.npids ++;
				}
				else
				{
					/* PAT - Program Association Table (Table program <-> pmt pid) */
					pids[0] = 1;
					chan.npids ++;
				}

				/* Allocating new structure */
				newc = malloc (sizeof(config_channel));
				if (newc == NULL)
				{
					log_error("Unable to malloc a new channel structure");
					fclose (fd);
					return -1;
				}

				memcpy (newc, &chan, sizeof(config_channel));
				newc->name = strdup (chan.name);
				newc->transp = strdup (chan.transp);
				if (chan.group != NULL)
					newc->group = strdup (chan.group);
				if (chan.desc != NULL)
					newc->desc = strdup (chan.desc);

				/* Preparing pids */
				newc->pids = malloc (sizeof(*(newc->pids)) * chan.npids);
				newc->npids = 0;
				if (newc->pids == NULL)
				{
					log_error("Unable to malloc a new pid list");
					config_cleanup_channel (newc);
					fclose (fd);
					return -1;
				}

				i = 0;
				while (newc->npids < chan.npids && i < DVB_MAX_PIDS)
				{
					if (pids[i] > 0)
					{
						newc->pids[newc->npids++] = i;
					}
					i++;
				}

				log_debug("Added %d pids for channel '%s'", newc->npids, newc->name);

				/* Inserting at the right place */
				cptr = &channels;
				while (*cptr != NULL)
				{
					if (strcmp ((*cptr)->name, newc->name) == 0)
					{
						log_info("Replacing channel '%s'", newc->name);
						newc->next = (*cptr)->next;
						(*cptr)->next = NULL;
						config_cleanup_channel (*cptr);
						*cptr = newc;
						break;
					}
					cptr = &((*cptr)->next);
				}
				if (*cptr == NULL)
				{
					log_info("Adding channel '%s'", newc->name);
					*cptr = newc;
				}
			}
			else BADTOKEN;
		}
		else BADTOKEN;
	}


	fclose (fd);
	return 0;
}

/**
 *  Streaming configuration
 */
int config_streams (const char *host)
{
	FILE *fd;
	config_token tok;
	char *ptr;
	char buffer[CONFIG_BUFFER_SIZE];
	int line = 0, i, j;

	config_stream *sptr;
	int ndvbt, ndvbs;

	if (host == NULL)
		return -1;

	/* Cleaning old streams */
	sptr = streams;
	while (sptr)
	{
		config_stream *tmp = sptr->next;
		config_cleanup_stream (sptr);
		sptr = tmp;
	}
	sptr = NULL;

	/* Opening config file */
	if ((fd = fopen ("streams.conf", "r")) == NULL)
	{
		pthread_mutex_lock (&log_strerror_buf_mutex);
		strerror_r(errno, log_strerror_buf, LOG_STRERROR_BUFLEN);
		log_error ("Unable to open 'streams.conf' (%s)", log_strerror_buf);
		pthread_mutex_unlock (&log_strerror_buf_mutex);
		return -1;
	}

	/* Parsing channels.conf file */
	while (!feof (fd))
	{
		line ++;
		if (fgets(buffer, CONFIG_BUFFER_SIZE, fd) == NULL)
		{
			if (!feof (fd))
			{
				pthread_mutex_lock (&log_strerror_buf_mutex);
				strerror_r(errno, log_strerror_buf, LOG_STRERROR_BUFLEN);
				log_error ("Error while reading 'streams.conf' (%s)", log_strerror_buf);
				pthread_mutex_unlock (&log_strerror_buf_mutex);
			}
			break;
		}
		if (strlen(buffer) >= CONFIG_BUFFER_SIZE - 1)
		{
			log_error ("Line length exceeded maximum (%zu > %d), aborting reload", strlen(buffer), CONFIG_BUFFER_SIZE - 2);
			fclose (fd);
			return -1;
		}

		ptr = first_token (&tok, buffer);
		if (*ptr == '#' || *ptr == '\n' || *ptr == '\0')
			continue;

		IFTOKEN("add")
		{
			NEXTOKEN;
			IFTOKEN("stream")
			{
				config_channel *cptr;
				config_stream stream;
				config_stream *news;
				config_stream **sptrptr;
				char *hostname = NULL;
				memset (&stream, 0, sizeof(stream));

				stream.dst_port = CONFIG_DEFAULT_PORT;
				stream.dst_ttl = CONFIG_DEFAULT_TTL;
				stream.dst_ip = INADDR_ANY;

				while (*(NEXTOKEN))
				{
					IFTOKEN("host")
					{
						NEXTOKEN;
						IFMISSTOK("host");
						hostname = ptr;
					}
					else IFTOKEN("channel")
					{
						NEXTOKEN;
						IFMISSTOK("channel");
						stream.channel = ptr;
					}
					else IFTOKEN("dst")
					{
						NEXTOKEN;
						IFMISSTOK("dst");
						if (inet_aton (ptr, (struct in_addr *) &(stream.dst_ip)) == 0)
						{
							log_error ("Invalid IP address in new stream at line %d", line);
							fclose (fd);
							return -1;
						}
					}
					else IFTOKEN("port")
					{
						NEXTOKEN;
						IFMISSTOK("port");
						stream.dst_port = strtoul (ptr, NULL, 10);
					}
					else IFTOKEN("ttl")
					{
						NEXTOKEN;
						IFMISSTOK("ttl");
						stream.dst_ttl = strtoul (ptr, NULL, 10);
						if (stream.dst_ttl < 1 || stream.dst_ttl > 255)
						{
							log_error ("Bad TTL in new stream at line %d", line);
							fclose (fd);
							return -1;
						}
					}
					else BADTOKEN;
				}

				/* Checking channel & host name */
				if (hostname == NULL)
				{
					log_error("New streaming at line %d must have an hostname", line);
					fclose (fd);
					return -1;
				}
				if (stream.channel == NULL)
				{
					log_error("New streaming at line %d must have a channel name", line);
					fclose (fd);
					return -1;
				}

				/* Checking IP */
				if (stream.dst_ip == INADDR_ANY)
				{
					log_error("New streaming at line %d must have a destination IP address", line);
					fclose (fd);
					return -1;
				}

				/* Checking channelname validity */
				cptr = channels;
				while (cptr != NULL)
				{
					if (strcmp(cptr->name, stream.channel) == 0)
					{
						stream.cptr = cptr;
						break;
					}
					cptr = cptr->next;
				}
				if (stream.cptr == NULL)
				{
					log_error("New streaming at line %d must have a valid channel name", line);
					fclose (fd);
					return -1;
				}

				/* Checking hostname validity */
				if (strcmp(host, hostname) != 0)
				{
					log_info("Ignoring streaming of '%s' on host '%s' (local host: '%s')", stream.channel, hostname, host);
					continue;
				}

				/* Allocating stream structure */
				news = malloc (sizeof(config_stream));
				if (news == NULL)
				{
					log_error("Unable to malloc a new stream structure");
					fclose (fd);
					return -1;
				}

				memcpy (news, &stream, sizeof(config_stream));
				news->channel = strdup (stream.channel);

				/* Finding place to insert transponder */
				sptrptr = &streams;
				while (*sptrptr != NULL)
				{
					if (strcmp ((*sptrptr)->channel, news->channel) == 0)
					{
						log_info("Replacing stream '%s'", news->channel);
						news->next = (*sptrptr)->next;
						(*sptrptr)->next = NULL;
						config_cleanup_stream (*sptrptr);
						*sptrptr = news;
						break;
					}
					sptrptr = &((*sptrptr)->next);
				}
				if (*sptrptr == NULL)
				{
					log_info("Adding stream '%s'", news->channel);
					*sptrptr = news;
				}
			}
			else BADTOKEN;
		}
		else BADTOKEN;
	}

	/* Validity of transponder set */
	memset (used_transponders, 0, sizeof (used_transponders));
	nused_transponders = 0;
	ndvbt = ndvbs = 0;

	sptr = streams;
	while (sptr != NULL)
	{
		for (i = 0; i < nused_transponders; i++)
		{
			if (used_transponders[i] == sptr->cptr->tptr)
				break;
		}
		if (i == nused_transponders)
		{
			if (nused_transponders == DVB_MAX_DEVS)
			{
				log_error ("Transponders of configured streams are more numerous than DVB cards");
				fclose (fd);
				return -1;
			}
			used_transponders[nused_transponders++] = sptr->cptr->tptr;

			if (sptr->cptr->tptr->type == TRANSP_DVBT)
				ndvbt ++;
			else
				ndvbs ++;
		}
		sptr = sptr->next;
	}

	for (i = 0; i < DVB_MAX_DEVS; i++)
	{
		switch (card_type[i])
		{
			case DVB_DVB_T:
				ndvbt --;
				break;
			case DVB_DVB_S:
				ndvbs --;
				break;
			default:
				break;
		}
	}

	if (ndvbt > 0)
	{
		log_error ("DVB-T transponders are more numerous than DVB-T cards (%d card(s) missing)", ndvbt);
		fclose (fd);
		return -1;
	}
	if (ndvbs > 0)
	{
		log_error ("DVB-S transponders are more numerous than DVB-S cards (%d card(s) missing)", ndvbs);
		fclose (fd);
		return -1;
	}

	/* Map transponders to cards (in order to reduce changes) */
	for (i = 0; i < DVB_MAX_DEVS; i++)
		map_cardtransponder[i] = -1;

	for (i = 0; i < DVB_MAX_DEVS; i++)
	{
		if (card_type[i] != DVB_DVB_T && card_type[i] != DVB_DVB_S)
		{
			map_cardtransponder[i] = -2;
			continue;
		}

		if (tvbr_running_config[i].card_type != card_type[i])
			continue;

		for (j = 0; j < nused_transponders; j++)
		{
			if (card_type[i] == DVB_DVB_T && used_transponders[j]->type == TRANSP_DVBT)
			{
				if (memcmp (&(tvbr_running_config[i].u.dvbt), &(used_transponders[j]->u.dvbt), sizeof (tvbr_card_dvbt)) == 0)
				{
					map_cardtransponder[i] = j;
					break;
				}
			}
			else if (card_type[i] == DVB_DVB_S && used_transponders[j]->type == TRANSP_DVBS)
			{
				if (memcmp (&(tvbr_running_config[i].u.dvbs), &(used_transponders[j]->u.dvbs), sizeof (tvbr_card_dvbs)) == 0)
				{
					map_cardtransponder[i] = j;
					break;
				}
			}
		}
	}

	for (j = 0; j < nused_transponders; j++)
	{
		for (i = 0; i < DVB_MAX_DEVS; i++)
		{
			if (map_cardtransponder[i] == j)
				break;
		}
		if (i != DVB_MAX_DEVS)
			continue;

		for (i = 0; i < DVB_MAX_DEVS; i++)
		{
			if (map_cardtransponder[i] != -1)
				continue;

			if (card_type[i] == DVB_DVB_T && used_transponders[j]->type == TRANSP_DVBT)
			{
				map_cardtransponder[i] = j;
				break;
			}
			if (card_type[i] == DVB_DVB_S && used_transponders[j]->type == TRANSP_DVBS)
			{
				map_cardtransponder[i] = j;
				break;
			}
		}
		if (i == DVB_MAX_DEVS)
		{
			log_error ("Unable to map transponder '%s' to a card (probably an internal error ...)", used_transponders[j]->name);
			fclose (fd);
			return -1;
		}
	}

	fclose (fd);
	return 0;
}
int config_apply ()
{
	unsigned int i,j,c;
	config_stream *sptr;

	memset (tvbr_standard_config, 0, sizeof(tvbr_standard_config));
	for (i = 0; i < DVB_MAX_DEVS; i++)
	{
		config_transponder *transp;
		if (map_cardtransponder[i] < 0 || map_cardtransponder[i] > nused_transponders)
			continue;

		/* General configuration */
		transp = used_transponders[map_cardtransponder[i]];
		if (transp == NULL)
		{
			log_warn ("Bad transponder for card %d, ignoring", i);
			continue;
		}

		if (transp->type == TRANSP_DVBT)
		{
			tvbr_standard_config[i].card_type = DVB_DVB_T;
			memcpy (&(tvbr_standard_config[i].u.dvbt), &(transp->u.dvbt), sizeof (tvbr_card_dvbt));
		}
		else
		{
			tvbr_standard_config[i].card_type = DVB_DVB_S;
			memcpy (&(tvbr_standard_config[i].u.dvbs), &(transp->u.dvbs), sizeof (tvbr_card_dvbs));
		}

		tvbr_standard_config[i].card = i;

		/* Channels */
		tvbr_standard_config[i].nchannels = 0;
		sptr = streams;
		while (sptr != NULL)
		{
			if (strcmp (sptr->cptr->transp, transp->name) == 0)
				tvbr_standard_config[i].nchannels ++;
			sptr = sptr->next;
		}

		tvbr_standard_config[i].channels = malloc (tvbr_standard_config[i].nchannels * sizeof (tvbr_channel));
		if (tvbr_standard_config[i].channels == NULL)
		{
			pthread_mutex_lock (&log_strerror_buf_mutex);
			strerror_r(errno, log_strerror_buf, LOG_STRERROR_BUFLEN);
			log_error ("Unable malloc channel list for transponder '%s' (%s)", transp->name, log_strerror_buf);
			pthread_mutex_unlock (&log_strerror_buf_mutex);
			return -1;
		}
		memset (tvbr_standard_config[i].channels, 0, tvbr_standard_config[i].nchannels * sizeof (tvbr_channel));

		sptr = streams;
		c = 0;
		while (sptr != NULL)
		{
			if (strcmp (sptr->cptr->transp, transp->name) == 0)
			{
				tvbr_standard_config[i].channels[c].group_name = (sptr->cptr->group ? strdup (sptr->cptr->group) : NULL);
				tvbr_standard_config[i].channels[c].channel_name = (sptr->cptr->desc ? strdup (sptr->cptr->desc) : strdup (sptr->cptr->name));

				tvbr_standard_config[i].channels[c].media_type = sptr->cptr->media;
				tvbr_standard_config[i].channels[c].dst_ip = sptr->dst_ip;
				tvbr_standard_config[i].channels[c].dst_port = sptr->dst_port;
				tvbr_standard_config[i].channels[c].dst_ttl = sptr->dst_ttl;

				tvbr_standard_config[i].channels[c].npids = sptr->cptr->npids;
				tvbr_standard_config[i].channels[c].pids = malloc (sptr->cptr->npids * sizeof (uint16_t));
				if (tvbr_standard_config[i].channels[c].pids == NULL)
				{
					pthread_mutex_lock (&log_strerror_buf_mutex);
					strerror_r(errno, log_strerror_buf, LOG_STRERROR_BUFLEN);
					log_error ("Unable malloc pid list for channel '%s' (%s)", sptr->cptr->name, log_strerror_buf);
					pthread_mutex_unlock (&log_strerror_buf_mutex);
					return -1;
				}
				for (j = 0; j < tvbr_standard_config[i].channels[c].npids; j++)
					tvbr_standard_config[i].channels[c].pids[j] = sptr->cptr->pids[j];
				tvbr_standard_config[i].channels[c].pmt_filter = sptr->cptr->pmt_filter;
				tvbr_standard_config[i].channels[c].pmt_pcr_pid = sptr->cptr->pmt_pcr_pid;

				c++;
			}
			sptr = sptr->next;
		}


	}

	return 0;
}
