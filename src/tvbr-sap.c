/*****************************************************************************
 * tvbr-sap.c :  SAPserver thread
 *****************************************************************************
 * Copyright (C) 2006 Binet Réseau
 * $Id: tvbr-sap.c 827 2006-11-07 23:10:23Z vinz2 $
 *
 * Authors: Vincent Zanotti <vincent.zanotti@m4x.org>
 * Inspired from:
 *	(VLC 0.9.0-svn-r16633)/src/stream_output/sap.c
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
 *  Initialisation of global vars & locks
 */
pthread_mutex_t sap_status_mutex = PTHREAD_MUTEX_INITIALIZER;
tvbr_mainstatus sap_status = TVBR_OK;

pthread_mutex_t sap_messages_mutex = PTHREAD_MUTEX_INITIALIZER;
sap_message *sap_messages[DVB_MAX_DEVS];
sap_message *sap_oldmessages[DVB_MAX_DEVS];
unsigned int sap_message_count = 0;

/**
 *  Registering SAP messages
 */
int sap_register (int card, sap_channel *channel)
{
	sap_message *message;
	int written;
	unsigned int header_size;
	char src_ip[TVBR_IPSTR_SIZE], dst_ip[TVBR_IPSTR_SIZE];
	char *media_type;

	assert (card >= 0);
	assert (card < DVB_MAX_DEVS);
	assert (channel != NULL);

	/* Allocating message */
	message = malloc (sizeof(sap_message));
	if (message == NULL)
	{
		pthread_mutex_lock (&log_strerror_buf_mutex);
		strerror_r(errno, log_strerror_buf, LOG_STRERROR_BUFLEN);
		log_error("Unable to alloc new SAP/SDP message (%s)", log_strerror_buf);
		pthread_mutex_unlock (&log_strerror_buf_mutex);
		return -1;
	}
	memset (message, 0, sizeof(sap_message));

	/* SAP Header */
	message->message[0] = 0x20;
	message->message[1] = 0x00;
	message->message[2] = (0x42 + card);
	message->message[3] = (((channel->sdp_version & 0xff) + (channel->sdp_sid & 0xff)) & 0xff);
	header_size = 4;

	memcpy (message->message + header_size, &(channel->src_ip), 4);
	header_size += 4;
	memcpy (message->message + header_size, "application/sdp", 16);
	header_size += 16;

	/* SDP Message */
	switch (channel->media_type)
	{
		case TVBR_MEDIA_VIDEO:
			media_type = "video";
			break;
		case TVBR_MEDIA_AUDIO:
			media_type = "audio";
			break;
		default:
			media_type = "unknown";
			break;
	}
	snprintf(src_ip, TVBR_IPSTR_SIZE, "%d.%d.%d.%d",
		   ((int)channel->src_ip.s_addr & 0xff),
		   ((int)channel->src_ip.s_addr >> 8) & 0xff,
		   ((int)channel->src_ip.s_addr >> 16) & 0xff,
		   ((int)channel->src_ip.s_addr >> 24) & 0xff);
	snprintf(dst_ip, TVBR_IPSTR_SIZE, "%d.%d.%d.%d",
		   ((int)channel->dst_ip.s_addr & 0xff),
		   ((int)channel->dst_ip.s_addr >> 8) & 0xff,
		   ((int)channel->dst_ip.s_addr >> 16) & 0xff,
		   ((int)channel->dst_ip.s_addr >> 24) & 0xff);
	written = snprintf ((char *) message->message + header_size, SAP_MESSAGE_LENGTH - header_size,
			"v=0\r\n"
			"o=%s %" PRIu64 " %d IN IP4 %s\r\n"
			"s=%s\r\n"
			"c=IN IP4 %s/%d\r\n"
			"t=0 0\r\n"
			"u=%s\r\n"
			"a=tool:%s\r\n"
			"a=recvonly\r\n"
			"a=type:broadcast\r\n"
			"a=source-filter: incl IN IP4 * %s\r\n"
			"%s%s%s"
			"m=%s %u udp 33\r\n",
			SAP_SDP_OWNER, channel->sdp_sid, channel->sdp_version, src_ip,
			channel->sdp_name,
			dst_ip, channel->dst_ttl,
			SAP_SDP_URL,
			SAP_SDP_TOOL,
			src_ip,
			(channel->sdp_group ? "a=x-plgroup:" : ""), (channel->sdp_group ? channel->sdp_group : ""), (channel->sdp_group ? "\r\n" : ""),
			media_type, channel->dst_port);

	if (written	<= 0)
	{
		pthread_mutex_lock (&log_strerror_buf_mutex);
		strerror_r(errno, log_strerror_buf, LOG_STRERROR_BUFLEN);
		log_error("Unable sprintf SAP/SDP message (%s)", log_strerror_buf);
		pthread_mutex_unlock (&log_strerror_buf_mutex);
		free (message);
		return -1;
	}
	if (written >= (SAP_MESSAGE_LENGTH - header_size))
	{
		log_error("SAP/SDP message is too long (%d bytes)", written + header_size);
		free (message);
		return -1;
	}

	message->msglen = header_size + written;
	log_info ("Adding SAP announcement for %s:%u, on card %d (from %s)", dst_ip, channel->dst_port, card, src_ip);

	/* Adding to message queue */
	pthread_mutex_lock (&sap_messages_mutex);
	message->next = sap_messages[card];
	sap_messages[card] = message;
	sap_message_count ++;
	log_debug ("New SAP announcements count: %d", sap_message_count);
	pthread_mutex_unlock (&sap_messages_mutex);

	return 0;
}

/**
 *  Unregistering cards
 */
int sap_unregister (int card)
{
	sap_message *ptr;
	assert (card >= 0);
	assert (card < DVB_MAX_DEVS);

	pthread_mutex_lock (&sap_messages_mutex);

	if (sap_oldmessages[card] != NULL)
	{
		ptr = sap_oldmessages[card];
		while (ptr->next != NULL)
		{
			ptr = ptr->next;
		}
		ptr->next = sap_messages[card];
	}
	else
	{
		sap_oldmessages[card] = sap_messages[card];
	}
	sap_messages[card] = NULL;

	pthread_mutex_unlock (&sap_messages_mutex);

	log_info ("Removing SAP announcements for card %d", card);

	return 0;
}

/**
 *  SAP Thread main function
 */
void *sap_main (void *d)
{
	int i, fd_sap;
	struct sockaddr_in sout;
	struct in_addr addr;
	unsigned int sap_diff_sleep;
	unsigned int sap_ext_sleep;
	sap_message *ptr, *tmp;

	/* Initializing */
	pthread_mutex_lock (&sap_messages_mutex);
	memset (sap_messages, 0, sizeof (sap_messages));
	memset (sap_oldmessages, 0, sizeof (sap_oldmessages));
	pthread_mutex_unlock (&sap_messages_mutex);

	/* Opening SAP socket */
	inet_aton (SAP_UDP_IP, &addr);
	fd_sap = udpsocket_connect (addr.s_addr, SAP_UDP_PORT);
	if (fd_sap < 0)
	{
		pthread_mutex_lock (&log_strerror_buf_mutex);
		strerror_r(errno, log_strerror_buf, LOG_STRERROR_BUFLEN);
		log_error("Unable to open SAP UDP fd for %s:%d (%s)", SAP_UDP_IP, SAP_UDP_PORT, log_strerror_buf);
		pthread_mutex_unlock (&log_strerror_buf_mutex);
		pthread_exit (NULL);
	}

	udpsocket_setttl (fd_sap, SAP_UDP_TTL);

	sout.sin_family = AF_INET;
	sout.sin_port = htons (SAP_UDP_PORT);
	sout.sin_addr = addr;

	/* Main loop */
	while (1)
	{
		/* sleep time */
		pthread_mutex_lock (&sap_messages_mutex);
		if (sap_message_count > 0)
		{
			sap_diff_sleep = SAP_CYCLE_TIME / sap_message_count;
			sap_ext_sleep = 0;
		}
		else
		{
			sap_diff_sleep = 0;
			sap_ext_sleep = SAP_CYCLE_TIME;
		}
		pthread_mutex_unlock (&sap_messages_mutex);

		/* Sending sessions */
		for (i = 0; i < DVB_MAX_DEVS; i++)
		{
			pthread_mutex_lock (&sap_messages_mutex);
			ptr = sap_messages[i];
			pthread_mutex_unlock (&sap_messages_mutex);

			while (ptr != NULL)
			{
				/* Sending message */
				send(fd_sap, ptr->message, ptr->msglen, 0);

				/* Next message */
				ptr = ptr->next;

				/* Sleeping */
				usleep (sap_diff_sleep);
			}

			pthread_mutex_lock (&sap_messages_mutex);
			ptr = sap_oldmessages[i];
			sap_oldmessages[i] = NULL;
			pthread_mutex_unlock (&sap_messages_mutex);

			while (ptr != NULL)
			{
				/* Modifying old message */
				ptr->message[0] |= 0x4;

				/* Sending message */
				send(fd_sap, ptr->message, ptr->msglen, 0);

				/* Removing message & nextmessage */
				tmp = ptr;
				ptr = ptr->next;
				free (tmp);

				pthread_mutex_lock (&sap_messages_mutex);
				sap_message_count --;
				log_debug ("Freeing deleted announcement, new SAP count: %d", sap_message_count);
				pthread_mutex_unlock (&sap_messages_mutex);

				/* Sleeping */
				usleep (sap_diff_sleep);
			}
		}

		/* Checking new status */
		pthread_mutex_lock (&sap_status_mutex);
		if (sap_status != TVBR_OK)
		{
			if (sap_message_count == 0)
				break;

			pthread_mutex_lock (&sap_messages_mutex);

			for (i = 0; i < DVB_MAX_DEVS; i++)
			{
				if (sap_oldmessages[i] != NULL)
				{
					ptr = sap_oldmessages[i];
					while (ptr->next != NULL)
					{
						ptr = ptr->next;
					}
					ptr->next = sap_messages[i];
				}
				else
				{
					sap_oldmessages[i] = sap_messages[i];
				}
				sap_messages[i] = NULL;
			}

			pthread_mutex_unlock (&sap_messages_mutex);
		}
		pthread_mutex_unlock (&sap_status_mutex);

		/* Sleeping */
		if (sap_ext_sleep > 0)
			usleep (sap_ext_sleep);
	}

	return NULL;
}
