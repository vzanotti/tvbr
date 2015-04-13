/*****************************************************************************
 * tvbr-stream.c :  Streaming threads
 *****************************************************************************
 * Copyright (C) 2006 Binet Réseau
 * $Id: tvbr-stream.c 957 2007-02-22 15:57:41Z vinz2 $
 *
 * Authors: Vincent Zanotti <vincent.zanotti@m4x.org>
 * Inspired from:
 *	(MumuDVB 1.2-17)/src/
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
dvb_tune stream_dvb_params[DVB_MAX_DEVS];
dvb_mode stream_dvb_mode[DVB_MAX_DEVS];

/**
 *  Private prototypes
 */
void stream_cleanup_channel (void *);
void stream_cleanup_channels (void *);
void stream_cleanup_status (void *data);

int stream_pmt_filter (uint16_t *, const unsigned char *);
inline int stream_pmt_check (const uint16_t *, int, const uint16_t *);
inline void stream_pmt_rewrite (unsigned char *, stream_channel *);

/**
 *  CRC
 */
static uint32_t stream_crc32_table[256] =
{
	0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9,
	0x130476dc, 0x17c56b6b, 0x1a864db2, 0x1e475005,
	0x2608edb8, 0x22c9f00f, 0x2f8ad6d6, 0x2b4bcb61,
	0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd,
	0x4c11db70, 0x48d0c6c7, 0x4593e01e, 0x4152fda9,
	0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75,
	0x6a1936c8, 0x6ed82b7f, 0x639b0da6, 0x675a1011,
	0x791d4014, 0x7ddc5da3, 0x709f7b7a, 0x745e66cd,
	0x9823b6e0, 0x9ce2ab57, 0x91a18d8e, 0x95609039,
	0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5,
	0xbe2b5b58, 0xbaea46ef, 0xb7a96036, 0xb3687d81,
	0xad2f2d84, 0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d,
	0xd4326d90, 0xd0f37027, 0xddb056fe, 0xd9714b49,
	0xc7361b4c, 0xc3f706fb, 0xceb42022, 0xca753d95,
	0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1,
	0xe13ef6f4, 0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d,
	0x34867077, 0x30476dc0, 0x3d044b19, 0x39c556ae,
	0x278206ab, 0x23431b1c, 0x2e003dc5, 0x2ac12072,
	0x128e9dcf, 0x164f8078, 0x1b0ca6a1, 0x1fcdbb16,
	0x018aeb13, 0x054bf6a4, 0x0808d07d, 0x0cc9cdca,
	0x7897ab07, 0x7c56b6b0, 0x71159069, 0x75d48dde,
	0x6b93dddb, 0x6f52c06c, 0x6211e6b5, 0x66d0fb02,
	0x5e9f46bf, 0x5a5e5b08, 0x571d7dd1, 0x53dc6066,
	0x4d9b3063, 0x495a2dd4, 0x44190b0d, 0x40d816ba,
	0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e,
	0xbfa1b04b, 0xbb60adfc, 0xb6238b25, 0xb2e29692,
	0x8aad2b2f, 0x8e6c3698, 0x832f1041, 0x87ee0df6,
	0x99a95df3, 0x9d684044, 0x902b669d, 0x94ea7b2a,
	0xe0b41de7, 0xe4750050, 0xe9362689, 0xedf73b3e,
	0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2,
	0xc6bcf05f, 0xc27dede8, 0xcf3ecb31, 0xcbffd686,
	0xd5b88683, 0xd1799b34, 0xdc3abded, 0xd8fba05a,
	0x690ce0ee, 0x6dcdfd59, 0x608edb80, 0x644fc637,
	0x7a089632, 0x7ec98b85, 0x738aad5c, 0x774bb0eb,
	0x4f040d56, 0x4bc510e1, 0x46863638, 0x42472b8f,
	0x5c007b8a, 0x58c1663d, 0x558240e4, 0x51435d53,
	0x251d3b9e, 0x21dc2629, 0x2c9f00f0, 0x285e1d47,
	0x36194d42, 0x32d850f5, 0x3f9b762c, 0x3b5a6b9b,
	0x0315d626, 0x07d4cb91, 0x0a97ed48, 0x0e56f0ff,
	0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623,
	0xf12f560e, 0xf5ee4bb9, 0xf8ad6d60, 0xfc6c70d7,
	0xe22b20d2, 0xe6ea3d65, 0xeba91bbc, 0xef68060b,
	0xd727bbb6, 0xd3e6a601, 0xdea580d8, 0xda649d6f,
	0xc423cd6a, 0xc0e2d0dd, 0xcda1f604, 0xc960ebb3,
	0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7,
	0xae3afba2, 0xaafbe615, 0xa7b8c0cc, 0xa379dd7b,
	0x9b3660c6, 0x9ff77d71, 0x92b45ba8, 0x9675461f,
	0x8832161a, 0x8cf30bad, 0x81b02d74, 0x857130c3,
	0x5d8a9099, 0x594b8d2e, 0x5408abf7, 0x50c9b640,
	0x4e8ee645, 0x4a4ffbf2, 0x470cdd2b, 0x43cdc09c,
	0x7b827d21, 0x7f436096, 0x7200464f, 0x76c15bf8,
	0x68860bfd, 0x6c47164a, 0x61043093, 0x65c52d24,
	0x119b4be9, 0x155a565e, 0x18197087, 0x1cd86d30,
	0x029f3d35, 0x065e2082, 0x0b1d065b, 0x0fdc1bec,
	0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088,
	0x2497d08d, 0x2056cd3a, 0x2d15ebe3, 0x29d4f654,
	0xc5a92679, 0xc1683bce, 0xcc2b1d17, 0xc8ea00a0,
	0xd6ad50a5, 0xd26c4d12, 0xdf2f6bcb, 0xdbee767c,
	0xe3a1cbc1, 0xe760d676, 0xea23f0af, 0xeee2ed18,
	0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4,
	0x89b8fd09, 0x8d79e0be, 0x803ac667, 0x84fbdbd0,
	0x9abc8bd5, 0x9e7d9662, 0x933eb0bb, 0x97ffad0c,
	0xafb010b1, 0xab710d06, 0xa6322bdf, 0xa2f33668,
	0xbcb4666d, 0xb8757bda, 0xb5365d03, 0xb1f740b4
};

/**
 *  Cleanup handlers
 */
void stream_cleanup_channel (void *data)
{
	stream_channel *channel = (stream_channel *) data;

	if (data == NULL)
		return;

	if (channel->fd_udp >= 0)
		close (channel->fd_udp);
}
void stream_cleanup_channels (void *data)
{
	unsigned int i;
	stream_channels *channels = (stream_channels *) data;

	log_debug("entering cleanup_channels function");

	if (data == NULL)
		return;

	for (i = 0; i < channels->nchannels; i++)
		stream_cleanup_channel ((void *)&(channels->channels[i]));
	free (channels->channels);
}
void stream_cleanup_status (void *data)
{
	log_debug("entering cleanup_status function");

	pthread_mutex_lock (&tvbr_card_status_mutex);
	log_debug("(status) card %zu status set to TVBR_STATUS_NOTSTARTED", (size_t) data);
	tvbr_card_status[(size_t) data] = TVBR_STATUS_NOTSTARTED;
	pthread_mutex_unlock (&tvbr_card_status_mutex);
}

/**
 *  PMT Filtering
 */
int stream_pmt_filter (uint16_t *pmtpids, const unsigned char *dvbbuf)
{
	const unsigned char *payload_begin, *payload_end, *p_begin, *p_ptr, *p_end;
	uint16_t psilen;
	int pmtpidscount = 0;

	/* TS start code */
	if (dvbbuf[0] != 0x47)
		return 0;

	/* No payload */
	if (!(dvbbuf[3] & 0x10))
		return 0;

	/* Skip the adaptation_field if present */
	if (dvbbuf[3] & 0x20)
		payload_begin = dvbbuf + 5 + dvbbuf[4];
	else
		payload_begin = dvbbuf + 4;

	/* skip the pointer_field and a new section begins */
	if(dvbbuf[1] & 0x40)
		payload_begin += 1;

	/* Check table_id value */
	if (payload_begin[0] != 0x02)
		return 0;

	/* Real payload start */
	if (payload_begin[1] & 0x80)
		p_begin = payload_begin + 8;
	else
		p_begin = payload_begin + 3;

	/* Payload end + CRC */
	psilen = 3 + (((uint16_t)(payload_begin[1] & 0xf)) << 8 | payload_begin[2]);
	payload_end = payload_begin + psilen;
	if (payload_begin[1] & 0x80)
		payload_end -= 4;

	/* PMT Descriptors */
	p_ptr = p_begin + 4;
	p_end = p_ptr + (((uint16_t)(p_begin[2] & 0x0f) << 8) | p_begin[3]);
	while (p_ptr + 2 <= p_end)
		p_ptr += 2 + p_ptr[1];

	/* Elementary streams */
	for (p_ptr = p_end; p_ptr + 4 <= payload_end;)
	{
		uint16_t pid = ((uint16_t)(p_ptr[1] & 0x1f) << 8) | p_ptr[2];
		uint16_t len = ((uint16_t)(p_ptr[3] & 0x0f) << 8) | p_ptr[4];

		pmtpids[pmtpidscount++] = pid;
		if (pmtpidscount >= DVB_MAX_PMT_PIDS)
			return pmtpidscount;

		p_ptr += 5;
		p_end = p_ptr + len;
		if (p_end > payload_end)
			p_end = payload_end;

		while (p_ptr + 2 <= p_end)
			p_ptr += 2 + p_ptr[1];
	}

	return pmtpidscount;
}
inline int stream_pmt_check (const uint16_t *pmtpids, int pmtpidscount, const uint16_t *pids)
{
	int i;
	for (i = 0; i < pmtpidscount; i++)
	{
		if (pids[pmtpids[i]] != 0)
			return 1;
	}
	return 0;
}
inline void stream_pmt_rewrite (unsigned char *buffer, stream_channel *channel)
{
	/* TS Discontinuity rewrite */
	buffer[3] = (buffer[3] & 0xf0) | (channel->ts_continuity & 0x0f);
	channel->ts_continuity = (channel->ts_continuity + 1) & 0xf;

	/* PCR_PID Rewrite */
	if (channel->channel->pmt_pcr_pid > 0)
	{
		unsigned char *p_ptr = buffer;
		unsigned char *p_crc;

		/* Skip the adaptation_field if present */
		if (buffer[3] & 0x20)
			p_ptr = buffer + 5 + buffer[4];
		else
			p_ptr = buffer + 4;

		/* skip the pointer_field and a new section begins */
		if(buffer[1] & 0x40)
			p_ptr += 1;

		/* Update PCR ID */
		p_ptr[8] = (p_ptr[8] & 0xe0) | ((channel->channel->pmt_pcr_pid >> 8) & 0x1f);
		p_ptr[9] = (channel->channel->pmt_pcr_pid & 0xff);

		/* Payload end + CRC */
		if (p_ptr[1] & 0x80)
		{
			uint32_t crc = 0xffffffff;

			p_crc = p_ptr + 3 + (((uint16_t)(p_ptr[1] & 0xf)) << 8 | p_ptr[2]) - 4;

			while(p_ptr < p_crc)
			{
				crc = (crc << 8) ^ stream_crc32_table[(crc >> 24) ^ (*p_ptr)];
				p_ptr ++;
			}

			p_crc[0] = (crc >> 24) & 0xff;
			p_crc[1] = (crc >> 16) & 0xff;
			p_crc[2] = (crc >> 8) & 0xff;
			p_crc[3] = crc & 0xff;
		}
	}
}

/**
 *  Streaming
 */
void *stream_main (void *data)
{
	unsigned int i, j, npids;
	uint16_t *pids;
	uint16_t pidstab[DVB_MAX_PIDS];

	uint16_t pmtpids[DVB_MAX_PMT_PIDS];
	int pmtpidscount = 0;
	int pmtprocessed = 0;

	stream_channels channels;
	tvbr_card *card = (tvbr_card *) data;
	dvb_tune tune;
	dvb_fd fd;

	unsigned int pidsfreq[DVB_MAX_PIDS];
	unsigned int count_loops, count_packets, count_timeouts;
	uint16_t pid;
	struct pollfd pollfd;
	int bytes_read;
	unsigned char *dvbptr;
	unsigned char dvbbuf[DVB_TS_PACKETSIZE*DVB_TS_PACKETSATONCE];

	pthread_cleanup_push (stream_cleanup_status, (void *)card->card);

	if (card->card_type == DVB_NONE)
	{
		log_error("Trying to start an empty config (%s)", log_strerror_buf);
		return NULL;
	}

	pthread_setspecific (tvbr_card_key, (void *) &(card->card));

	/* Initialisation of data structure channels */
	memset(pidstab, 0, sizeof(unsigned short) * DVB_MAX_PIDS);
	memset(pidsfreq, 0, sizeof(int) * DVB_MAX_PIDS);

	channels.nchannels = card->nchannels;
	channels.channels = malloc (sizeof(stream_channel) * card->nchannels);
	if (channels.channels == NULL)
	{
		pthread_mutex_lock (&log_strerror_buf_mutex);
		strerror_r(errno, log_strerror_buf, LOG_STRERROR_BUFLEN);
		log_error("Unable to alloc channel array (%s)", log_strerror_buf);
		pthread_mutex_unlock (&log_strerror_buf_mutex);
		pthread_exit (NULL);
	}
	pthread_cleanup_push (stream_cleanup_channels, &channels);

	for (i = 0; i < card->nchannels; i++)
	{
		channels.channels[i].channel = &(card->channels[i]);
		memset(channels.channels[i].udpbuffer, 0, sizeof(unsigned char) * STREAM_UDP_PACKETSIZE);
		memset(channels.channels[i].pids, 0, sizeof(unsigned short) * DVB_MAX_PIDS);
		channels.channels[i].fd_udp = -1;
		channels.channels[i].buffered = 0;
		channels.channels[i].ts_continuity = 31;

		for (j = 0; j < card->channels[i].npids; j++)
		{
			channels.channels[i].pids[ card->channels[i].pids[j] ] = 1;
			pidstab[ card->channels[i].pids[j] ] = 1;
		}
	}

	/* Peparing dvb-tune parameters */
	switch (card->card_type)
	{
		case DVB_DVB_T:
			tune.frequency = card->u.dvbt.frequency;
			tune.symbolrate = 0;
			tune.polarity = DVB_S_POLARITY_H;
			tune.modulation = card->u.dvbt.modulation;
			tune.hpcoderate = card->u.dvbt.hpcoderate;
			tune.lpcoderate = card->u.dvbt.lpcoderate;
			tune.transmitmode = card->u.dvbt.transmitmode;
			tune.guardinterval = card->u.dvbt.guardinterval;
			tune.bandwidth = card->u.dvbt.bandwidth;
			tune.tunetimeout = DVB_TUNE_TIMEOUT;
			break;
		case DVB_DVB_S:
			tune.frequency = card->u.dvbs.frequency;
			tune.symbolrate = card->u.dvbs.symbolrate;
			tune.polarity = card->u.dvbs.polarity;
			tune.modulation = DVB_T_DEF_CONSTELL;
			tune.hpcoderate = DVB_T_DEF_HPCODERATE;
			tune.lpcoderate = DVB_T_DEF_LPCODERATE;
			tune.transmitmode = DVB_T_DEF_TRANSMODE;
			tune.guardinterval = DVB_T_DEF_GUARD;
			tune.bandwidth = DVB_T_DEF_BANDWIDTH;
			tune.tunetimeout = DVB_TUNE_TIMEOUT;
			break;
		case DVB_DVB_C:
			tune.frequency = card->u.dvbc.frequency;
			tune.symbolrate = card->u.dvbc.symbolrate;
			tune.polarity = DVB_S_POLARITY_H;
			tune.modulation = card->u.dvbc.modulation;
			tune.hpcoderate = DVB_T_DEF_HPCODERATE;
			tune.lpcoderate = DVB_T_DEF_LPCODERATE;
			tune.transmitmode = DVB_T_DEF_TRANSMODE;
			tune.guardinterval = DVB_T_DEF_GUARD;
			tune.bandwidth = DVB_T_DEF_BANDWIDTH;
			tune.tunetimeout = DVB_TUNE_TIMEOUT;
			break;
		case DVB_NONE:
			break;
	}

	/* pid list */
	npids = 0;
	for (i = 0; i < DVB_MAX_PIDS; i++)
		if (pidstab[i] > 0)
			npids ++;

	pids = malloc (sizeof(int) * npids);
	pthread_cleanup_push (&free, pids);
	if (pids == NULL)
	{
		pthread_mutex_lock (&log_strerror_buf_mutex);
		strerror_r(errno, log_strerror_buf, LOG_STRERROR_BUFLEN);
		log_error("Unable to alloc pids array (%s)", log_strerror_buf);
		pthread_mutex_unlock (&log_strerror_buf_mutex);
		pthread_exit (NULL);
	}

	j = 0;
	npids = 0;
	for (i = 0; i < DVB_MAX_PIDS; i++) {
		if (pidstab[i] > 0) {
			pids[j++] = i;
			npids ++;
		}
	}

	/* Tuning & opening dvb fds */
	pthread_cleanup_push (dvb_cleanup_fd, &fd);
	if (dvb_fd_init(&fd, &tune, card->card, npids, pids) < 0)
	{
		log_error("Unable to tune & open dvb fds");
		pthread_exit (NULL);
	}

	/* Opening udp fds */
	for (i = 0; i < channels.nchannels; i++)
	{
		struct in_addr addr;
		addr.s_addr = card->channels[i].dst_ip ;

		channels.channels[i].fd_udp = udpsocket_connect (card->channels[i].dst_ip, card->channels[i].dst_port);
		if (channels.channels[i].fd_udp < 0)
		{
			pthread_mutex_lock (&log_strerror_buf_mutex);
			strerror_r(errno, log_strerror_buf, LOG_STRERROR_BUFLEN);
			log_error("Unable to open UDP fd for %s:%d (%s)", inet_ntoa(addr), (int) card->channels[i].dst_port, log_strerror_buf);
			pthread_mutex_unlock (&log_strerror_buf_mutex);
			pthread_exit (NULL);
		}

		udpsocket_setttl (channels.channels[i].fd_udp, (int) card->channels[i].dst_ttl);

		channels.channels[i].sout.sin_family = AF_INET;
		channels.channels[i].sout.sin_port = htons (card->channels[i].dst_port);
		channels.channels[i].sout.sin_addr = addr;
	}

	/* Registering SAP announcements */
	for (i = 0; i < channels.nchannels; i++)
	{
		sap_channel sap;
		struct timeval tv;
		struct sockaddr_in sin;
		socklen_t socklen = sizeof(sin);

		/* Initialization */
		memset (&sap, 0, sizeof (sap_channel));
		gettimeofday (&tv, NULL);

		/* Obtaining local ip address */
		if (getsockname (channels.channels[i].fd_udp, (struct sockaddr *) &sin, &socklen) < 0)
		{
			pthread_mutex_lock (&log_strerror_buf_mutex);
			strerror_r(errno, log_strerror_buf, LOG_STRERROR_BUFLEN);
			log_warn("Unable to obtain local ip address for channel %d (%s)", i, log_strerror_buf);
			pthread_mutex_unlock (&log_strerror_buf_mutex);
			continue;
		}

		/* Filling sap_channel struct */
		sap.sdp_sid = (uint64_t) tv.tv_sec * 1000000 + (uint64_t) tv.tv_usec;
		sap.sdp_version = 0x100 * (card->card) + i;
		sap.sdp_name = card->channels[i].channel_name;
		sap.sdp_group = card->channels[i].group_name;
		sap.media_type = card->channels[i].media_type;
		sap.src_ip.s_addr = sin.sin_addr.s_addr;
		sap.dst_ip.s_addr = card->channels[i].dst_ip;
		sap.dst_port = card->channels[i].dst_port;
		sap.dst_ttl = card->channels[i].dst_ttl;

		/* Registering ... */
		sap_register (card->card, &sap);
	}

	/* Main loop */
	count_loops = count_packets = count_timeouts = 0;

	pollfd.fd = fd.fd_dvr;
	pollfd.events = POLLIN | POLLPRI;

	for (;;)
	{
		count_loops ++;

		if (poll (&pollfd, 1, STREAM_LOOP_POLLTIMEOUT) == 0)
		{
			count_timeouts ++;
			count_loops += STREAM_LOOPCHECK_TIMEOUT;
		}

		if ((bytes_read = read (fd.fd_dvr, dvbbuf, DVB_TS_PACKETSIZE*DVB_TS_PACKETSATONCE)) > 0)
		{
			dvbptr = dvbbuf;

			while (bytes_read >= DVB_TS_PACKETSIZE)
			{
				count_loops += STREAM_LOOPCHECK_PACKET;
				count_packets ++;
				count_timeouts = 0;

				pid = ((dvbptr[1] << 8) | (dvbptr[2] & 0xff)) & 0x1fff;
				pidsfreq[pid] ++;
				pmtprocessed = 0;

				for (i = 0; i < channels.nchannels; i++)
				{
					if (channels.channels[i].pids[pid] == 0)
						continue;

					/* PMT Filtering */
					if (pid > 0 && channels.channels[i].channel->pmt_filter == pid)
					{
						if (!pmtprocessed)
						{
							pmtpidscount = stream_pmt_filter (pmtpids, dvbptr);
							pmtprocessed = 1;
						}
						if (!stream_pmt_check (pmtpids, pmtpidscount, channels.channels[i].pids))
							continue;
					}

					memcpy (&(channels.channels[i].udpbuffer[channels.channels[i].buffered]), dvbptr, DVB_TS_PACKETSIZE);
					channels.channels[i].buffered += DVB_TS_PACKETSIZE;

					/* PMT Rewriting */
					if (pmtpidscount > 0 && pid > 0 && channels.channels[i].channel->pmt_filter == pid)
					{
						stream_pmt_rewrite(
							&(channels.channels[i].udpbuffer[channels.channels[i].buffered - DVB_TS_PACKETSIZE]),
							&(channels.channels[i])
						);
					}

					if (channels.channels[i].buffered + DVB_TS_PACKETSIZE > STREAM_UDP_PACKETSIZE)
					{
						send (channels.channels[i].fd_udp,
								channels.channels[i].udpbuffer,
								channels.channels[i].buffered,
								0);
						channels.channels[i].buffered = 0;
					}
				}
				dvbptr += DVB_TS_PACKETSIZE;
				bytes_read -= DVB_TS_PACKETSIZE;
			}
			if (bytes_read < DVB_TS_PACKETSIZE && bytes_read > 0)
			{
				log_warn("Did read an inconsistent number of bytes (%d bytes left); respawning", bytes_read);
				break;
			}
		}

		/* end_of_loop checking */
		if (count_loops > STREAM_LOOPCHECK_COUNT)
		{
			pthread_mutex_lock (&tvbr_card_status_mutex);
			if (tvbr_card_status[card->card] != TVBR_STATUS_STARTED)
			{
				pthread_mutex_unlock (&tvbr_card_status_mutex);
				log_info("Interrupting thread on behalf main thread");
				break;
			}
			pthread_mutex_unlock (&tvbr_card_status_mutex);
			log_debug("Checking for interruption status ... OK");

			count_loops = 0;
		}

		/* stats */
		if (count_packets > STREAM_STATS_COUNT)
		{
			for (i = 0; i < DVB_MAX_PIDS; i++)
			{
				if (pidsfreq[i] > 0)
				{
					log_debug("Stats pid %d -> %d packets", i, pidsfreq[i]);
					pidsfreq[i] = 0;
				}
			}
			count_packets = 0;
		}

		/* Aborting */
		if (count_timeouts > STREAM_TIMEOUT_COUNT)
		{
			log_error("No incoming packets during the last %d seconds, aborting thread", count_timeouts * STREAM_LOOP_POLLTIMEOUT / 1000);
			break;
		}
	}

	/* Cleaning up */
	sap_unregister (card->card);
	pthread_cleanup_pop (1);
	pthread_cleanup_pop (1);
	pthread_cleanup_pop (1);
	pthread_cleanup_pop (1);

	return NULL;
}
