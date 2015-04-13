/*****************************************************************************
 * tvbr.c :  Main threads & common functions
 *****************************************************************************
 * Copyright (C) 2006 Binet Réseau
 * $Id: tvbr.c 957 2007-02-22 15:57:41Z vinz2 $
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
 *  Initialization of global variables
 */
pthread_mutex_t log_fd_mutex = PTHREAD_MUTEX_INITIALIZER;
int log_fd = -1;
pthread_mutex_t log_strerror_buf_mutex = PTHREAD_MUTEX_INITIALIZER;
char log_strerror_buf[LOG_STRERROR_BUFLEN];

pthread_mutex_t tvbr_card_status_mutex = PTHREAD_MUTEX_INITIALIZER;
tvbr_status tvbr_card_status[DVB_MAX_DEVS];
pthread_key_t tvbr_card_key;

pthread_mutex_t tvbr_running_config_mutex = PTHREAD_MUTEX_INITIALIZER;
tvbr_card tvbr_running_config[DVB_MAX_DEVS];
tvbr_card tvbr_standard_config[DVB_MAX_DEVS];

int verbosity = 0;
tvbr_mainstatus main_thread_status = TVBR_HUP;

/**
 * Prototypes
 */
inline void log_do (const int, const char *, const char *, va_list)
		__attribute__((format(printf,3,0)));

void tvbr_cleanup_channel (void *);
void tvbr_cleanup_card (void *);
void tvbr_signal_handler (int);

int tvbr_config_copy (unsigned int);
int tvbr_config_diff (unsigned int);

void usage (void);

/**
 *  Logging functions
 */
inline void log_do (const int minverb, const char *prefix, const char *format, va_list ap)
{
	int card;
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

	/* Thread specific prefix */
	card = * (int *) (pthread_getspecific (tvbr_card_key));
	if (card >= 0)
		fprintf(stderr, "%s card%d: %s: ", timebuf, card, prefix);
	else
		fprintf(stderr, "%s main : %s: ", timebuf, prefix);

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
 *  Cleanup handlers
 */
void tvbr_cleanup_channel (void *data)
{
	tvbr_channel *channel = (tvbr_channel *) data;

	if (channel->group_name != NULL)
		free (channel->group_name);
	if (channel->channel_name != NULL)
		free (channel->channel_name);
	if (channel->pids != NULL)
		free (channel->pids);

	channel->npids = 0;
	channel->pids = NULL;
	channel->channel_name = channel->group_name = NULL;
}
void tvbr_cleanup_card (void *data)
{
	unsigned int i;
	tvbr_card *card = (tvbr_card *)data;

	if (card->channels == NULL)
		return;

	for (i = 0; i < card->nchannels; i++)
	{
		tvbr_cleanup_channel ((void *)&(card->channels[i]));
	}
	free (card->channels);
	card->channels = NULL;
}

/**
 *  Signal handler
 */
void tvbr_signal_handler (int sig)
{
	if (sig == SIGHUP)
	{
		main_thread_status |= TVBR_HUP;
	}
	else
	{
		main_thread_status |= TVBR_TERM;
		signal (SIGINT, SIG_DFL);
		signal (SIGTERM, SIG_DFL);
		signal (SIGQUIT, SIG_DFL);
	}
}

/**
 *  Config helpers
 */
int tvbr_config_copy (unsigned int card)
{
	unsigned int i;
	assert(card < DVB_MAX_DEVS);

	/* Mutex lock */
	pthread_mutex_lock (&tvbr_running_config_mutex);

	if (tvbr_standard_config[card].card_type == DVB_NONE)
	{
		tvbr_running_config[card].card_type = DVB_NONE;
		pthread_mutex_unlock (&tvbr_running_config_mutex);
		return 0;
	}

	memcpy (&tvbr_running_config[card], &tvbr_standard_config[card], sizeof(tvbr_card));
	tvbr_running_config[card].channels = malloc (sizeof (tvbr_channel) * tvbr_standard_config[card].nchannels);
	if (tvbr_running_config[card].channels == NULL)
	{
		pthread_mutex_unlock (&tvbr_running_config_mutex);

		pthread_mutex_lock (&log_strerror_buf_mutex);
		strerror_r(errno, log_strerror_buf, LOG_STRERROR_BUFLEN);
		log_error("Unable to copy channels configuration for card %d (%s)", card, log_strerror_buf);
		pthread_mutex_unlock (&log_strerror_buf_mutex);
		return -1;
	}

	memcpy (tvbr_running_config[card].channels, tvbr_standard_config[card].channels, sizeof (tvbr_channel) * tvbr_standard_config[card].nchannels);
	for (i = 0; i < tvbr_standard_config[card].nchannels; i++)
	{
		if (tvbr_standard_config[card].channels[i].group_name != NULL)
			tvbr_running_config[card].channels[i].group_name = strdup (tvbr_standard_config[card].channels[i].group_name);
		if (tvbr_standard_config[card].channels[i].channel_name != NULL)
			tvbr_running_config[card].channels[i].channel_name = strdup (tvbr_standard_config[card].channels[i].channel_name);

		tvbr_running_config[card].channels[i].pids = malloc (sizeof(uint16_t) * tvbr_standard_config[card].channels[i].npids);
		if (tvbr_running_config[card].channels[i].pids == NULL)
		{
			pthread_mutex_unlock (&tvbr_running_config_mutex);

			pthread_mutex_lock (&log_strerror_buf_mutex);
			strerror_r(errno, log_strerror_buf, LOG_STRERROR_BUFLEN);
			log_error("Unable to copy channels configuration for card %d, channel %d (%s)", card, i, log_strerror_buf);
			pthread_mutex_unlock (&log_strerror_buf_mutex);
			return -1;
		}

		memcpy (tvbr_running_config[card].channels[i].pids, tvbr_standard_config[card].channels[i].pids, sizeof(uint16_t) * tvbr_standard_config[card].channels[i].npids);
	}

	pthread_mutex_unlock (&tvbr_running_config_mutex);
	return 0;
}
int tvbr_config_diff (unsigned int card)
{
	unsigned int i, j;
	assert(card < DVB_MAX_DEVS);

	if (tvbr_running_config[card].card_type != tvbr_standard_config[card].card_type)
		return 1;

	if (tvbr_running_config[card].card != tvbr_standard_config[card].card)
	{
		if (tvbr_running_config[card].card_type != DVB_NONE)
			log_warn("Running config or standard config is not consistent (rconf.card = %d, sconf.card = %d, card = %d)",
				   tvbr_running_config[card].card, tvbr_standard_config[card].card, card);
		return 1;
	}

	switch (tvbr_running_config[card].card_type)
	{
		case DVB_DVB_T:
			if ((tvbr_running_config[card].u.dvbt.frequency != tvbr_standard_config[card].u.dvbt.frequency) ||
						  (tvbr_running_config[card].u.dvbt.bandwidth != tvbr_standard_config[card].u.dvbt.bandwidth) ||
						  (tvbr_running_config[card].u.dvbt.hpcoderate != tvbr_standard_config[card].u.dvbt.hpcoderate) ||
						  (tvbr_running_config[card].u.dvbt.lpcoderate != tvbr_standard_config[card].u.dvbt.lpcoderate) ||
						  (tvbr_running_config[card].u.dvbt.modulation != tvbr_standard_config[card].u.dvbt.modulation) ||
						  (tvbr_running_config[card].u.dvbt.transmitmode != tvbr_standard_config[card].u.dvbt.transmitmode) ||
						  (tvbr_running_config[card].u.dvbt.guardinterval != tvbr_standard_config[card].u.dvbt.guardinterval))
				return 1;
			break;
		case DVB_DVB_S:
			if ((tvbr_running_config[card].u.dvbs.frequency != tvbr_standard_config[card].u.dvbs.frequency) ||
						  (tvbr_running_config[card].u.dvbs.polarity != tvbr_standard_config[card].u.dvbs.polarity) ||
						  (tvbr_running_config[card].u.dvbs.symbolrate != tvbr_standard_config[card].u.dvbs.symbolrate))
				return 1;
			break;
		case DVB_DVB_C:
			if ((tvbr_running_config[card].u.dvbc.frequency != tvbr_standard_config[card].u.dvbc.frequency) ||
						  (tvbr_running_config[card].u.dvbc.symbolrate != tvbr_standard_config[card].u.dvbc.symbolrate) ||
						  (tvbr_running_config[card].u.dvbc.modulation != tvbr_standard_config[card].u.dvbc.modulation))
				return 1;
			break;
		default:
			break;
	}

	if (tvbr_running_config[card].nchannels != tvbr_standard_config[card].nchannels)
		return 1;

	for (i = 0; i < tvbr_running_config[card].nchannels; i++)
	{
		if (strcmp(tvbr_running_config[card].channels[i].channel_name, tvbr_standard_config[card].channels[i].channel_name) != 0)
			return 1;
		if (strcmp(tvbr_running_config[card].channels[i].channel_name, tvbr_standard_config[card].channels[i].channel_name) != 0)
			return 1;

		if (tvbr_running_config[card].channels[i].media_type != tvbr_standard_config[card].channels[i].media_type)
			return 1;

		if (tvbr_running_config[card].channels[i].dst_ip != tvbr_standard_config[card].channels[i].dst_ip)
			return 1;
		if (tvbr_running_config[card].channels[i].dst_port != tvbr_standard_config[card].channels[i].dst_port)
			return 1;
		if (tvbr_running_config[card].channels[i].dst_ttl != tvbr_standard_config[card].channels[i].dst_ttl)
			return 1;

		if (tvbr_running_config[card].channels[i].npids != tvbr_standard_config[card].channels[i].npids)
			return 1;

		for (j = 0; j < tvbr_running_config[card].channels[i].npids; j++)
		{
			if (tvbr_running_config[card].channels[i].pids[j] != tvbr_standard_config[card].channels[i].pids[j])
				return 1;
		}

		if (tvbr_running_config[card].channels[i].pmt_filter != tvbr_standard_config[card].channels[i].pmt_filter)
			return 1;
		if (tvbr_running_config[card].channels[i].pmt_pcr_pid != tvbr_standard_config[card].channels[i].pmt_pcr_pid)
			return 1;
	}

	return 0;
}

/**
 *  Usage
 */
void usage ()
{
	printf("Usage: tvbr [-hvq] [-d <path/to/etc>] [-c <card>[,<card>[...]]] <hostname>\n");
	printf("   -h, --help            Display this help\n");
	printf("   -v, --verbose         Verbose output\n");
	printf("   -q, --quiet           Quiet output\n");
	printf("   -d, --confdir=PATH    Configuration directory\n");
	printf("   -c, --cards=CARDLIST  Only cards in CARDLIST are capable DVB cards (comma-separated list of int)\n");
	printf("   <hostname>            Local hostname (related to streams.conf)\n");
}

/**
 *  Main function
 */
int main (int argc, char **argv)
{
	tvbr_restart restart[DVB_MAX_DEVS];
	pthread_t tid;
	int i, cardno;

	const char *confdir = NULL;
	const char *hostname = NULL;
	const char *cardlist = NULL;

	struct option longopts[] = {
		{"help",	0, 0, 'h'},
		{"usage",	0, 0, 'h'},
		{"verbose",	0, 0, 'v'},
		{"quiet",	0, 0, 'q'},
		{"confdir",	1, 0, 'd'},
		{"cards",	1, 0, 'c'},
		{0,		0, 0,  0 }
	};

	/* Initialisation */
	cardno = -1;
	pthread_key_create (&tvbr_card_key, NULL);
	pthread_setspecific (tvbr_card_key, (void *) &cardno);

	for (i = 0; i < DVB_MAX_DEVS; i++)
		tvbr_card_status[i] = TVBR_STATUS_NOTSTARTED;

	verbosity = 0;
	memset (log_strerror_buf, 0, LOG_STRERROR_BUFLEN);
	memset (tvbr_running_config, 0, sizeof (tvbr_running_config));
	memset (tvbr_standard_config, 0, sizeof (tvbr_standard_config));
	memset (restart, 0, sizeof (restart));

	/* Parameters */
	while(1)
	{
		char c = getopt_long(argc, argv, "hvqd:c:", longopts, NULL);
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
			case 'd':
				confdir = optarg;
				break;
			case 'c':
				cardlist = optarg;
				break;
			case '?':
				usage();
				return 1;
			case '0':
			default:
				break;
		}
	}
	if (optind >= argc)
	{
		usage ();
		return 1;
	}
	hostname = argv[optind];

	if (confdir == NULL)
		confdir = "/etc/tvbr/";

	if (chdir (confdir) < 0)
	{
		pthread_mutex_lock (&log_strerror_buf_mutex);
		strerror_r(errno, log_strerror_buf, LOG_STRERROR_BUFLEN);
		log_error("Unable chdir to confdir (%s)", log_strerror_buf);
		pthread_mutex_unlock (&log_strerror_buf_mutex);
		return 1;
	}

	/* Card type configuration */
	if (config_cards (cardlist) < 0)
		return 1;

	/* Signals */
	signal (SIGHUP, &tvbr_signal_handler);
	signal (SIGINT, &tvbr_signal_handler);
	signal (SIGTERM, &tvbr_signal_handler);
	signal (SIGQUIT, &tvbr_signal_handler);

	/* Starting sap thread */
	sap_status = TVBR_OK;
	log_info("Starting SAP thread");
	pthread_create (&tid, NULL, &sap_main, NULL);
	pthread_detach (tid);

	/* Main loop */
	for (;;)
	{
		/* Special case: party is over */
		if (main_thread_status & TVBR_TERM)
		{
			pthread_mutex_lock (&tvbr_card_status_mutex);
			for (i = 0; i < DVB_MAX_DEVS; i++)
			{
				if (tvbr_card_status[i] != TVBR_STATUS_NOTSTARTED)
				{
					log_debug("(status) card %d status set to TVBR_STATUS_MUSTSTOP", i);
					tvbr_card_status[i] = TVBR_STATUS_MUSTSTOP;
					log_info("Stopping card %d's thread", i);
				}
			}
			pthread_mutex_unlock (&tvbr_card_status_mutex);

			pthread_mutex_lock (&sap_status_mutex);
			sap_status = TVBR_TERM;
			log_info("Stopping SAP thread");
			pthread_mutex_unlock (&sap_status_mutex);

			usleep (TVBR_SLEEP_GRACE);
			break;
		}
		/* Computing standard_config from external sources */
		if (main_thread_status & TVBR_HUP)
		{
			log_info("Reloading configuration");

			if (config_channels () < 0)
			{
				log_warn("Aborting configuration reload (channels.conf error)");
			}
			else if (config_streams (hostname) < 0)
			{
				log_warn("Aborting configuration reload (streams.conf error)");
			}
			else
			{
				for (i = 0; i < DVB_MAX_DEVS; i++)
					tvbr_cleanup_card (&(tvbr_standard_config[i]));
				if (config_apply () < 0)
				{
					log_error ("It was not possible to apply new configuration; possibly garbaged config -> exiting");
					main_thread_status |= TVBR_TERM;
					continue;
				}

				/* Determining threads that should be restarted */
				for (i = 0; i < DVB_MAX_DEVS; i++)
				{
					if (tvbr_config_diff (i) != 0)
						restart[i] = TVBR_START | TVBR_STOP;
					else
						restart[i] = 0;

					pthread_mutex_lock (&tvbr_card_status_mutex);
					if (tvbr_card_status[i] == TVBR_STATUS_NOTSTARTED)
					{
						restart[i] = TVBR_START;
					}
					pthread_mutex_unlock (&tvbr_card_status_mutex);

					if (tvbr_standard_config[i].card_type == DVB_NONE)
					{
						if (restart[i] & TVBR_START)
							restart[i] ^= TVBR_START;
					}

					if (restart[i] & TVBR_START && restart[i] & TVBR_STOP)
						log_info("Restarting card %d's thread", i);
					else if (restart[i] & TVBR_START)
						log_info("Starting card %d's thread", i);
					else if (restart[i] & TVBR_STOP)
						log_info("Stopping card %d's thread", i);
				}
			}
			main_thread_status ^= TVBR_HUP;
		}

		/* Checking if some threads died unexpectedly */
		pthread_mutex_lock (&tvbr_card_status_mutex);
		for (i = 0; i < DVB_MAX_DEVS; i++)
		{
			if (tvbr_running_config[i].card_type != DVB_NONE && tvbr_card_status[i] == TVBR_STATUS_NOTSTARTED && restart[i] == 0)
			{
				restart[i] = TVBR_START;
				log_info("Restarting card %d's thread (which died unexpectedly)", i);
			}
		}
		pthread_mutex_unlock (&tvbr_card_status_mutex);

		/* Restarting threads */
		for (i = 0; i < DVB_MAX_DEVS; i++)
		{
			if (restart[i] & TVBR_STOP || restart[i] & TVBR_START)
			{
				pthread_mutex_lock (&tvbr_card_status_mutex);
				if (tvbr_card_status[i] != TVBR_STATUS_NOTSTARTED)
				{
					log_debug("(status) card %d status set to TVBR_STATUS_MUSTSTOP 2", i);
					tvbr_card_status[i] = TVBR_STATUS_MUSTSTOP;
					pthread_mutex_unlock (&tvbr_card_status_mutex);

					restart[i] &= ~TVBR_STOP;
					continue;
				}
				pthread_mutex_unlock (&tvbr_card_status_mutex);
			}
			if (restart[i] & TVBR_START && tvbr_standard_config[i].card_type != DVB_NONE)
			{
				tvbr_cleanup_card (&tvbr_running_config[i]);
				tvbr_config_copy (i);

				pthread_mutex_lock (&tvbr_card_status_mutex);
				tvbr_card_status[i] = TVBR_STATUS_STARTED;
				log_debug("(status) card %d status set to TVBR_STATUS_STARTED", i);
				pthread_mutex_unlock (&tvbr_card_status_mutex);

				pthread_create (&tid, NULL, &stream_main, (void *) &(tvbr_running_config[i]));
				pthread_detach (tid);
				restart[i] ^= TVBR_START;
				continue;
			}
		}

		/* Sleeping */
		usleep (TVBR_SLEEP_MAINLOOP);
	}

	/* Cleaning up */
	config_cleanup ();
	for (i = 0; i < DVB_MAX_DEVS; i++)
	{
		tvbr_cleanup_card (&tvbr_standard_config[i]);
		tvbr_cleanup_card (&tvbr_running_config[i]);
	}
	pthread_key_delete (tvbr_card_key);
	return 0;
}
