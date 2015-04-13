/*****************************************************************************
 * tvbr-dvb.c :  DVB functions
 *****************************************************************************
 * Copyright (C) 2006 Binet Réseau
 * $Id: tvbr-dvb.c 824 2006-11-04 17:29:47Z vinz2 $
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
pthread_mutex_t dvb_tuned_card_mutex = PTHREAD_MUTEX_INITIALIZER;
int dvb_tuned_card = -1;
pthread_t dvb_tuned_card_thread;

/**
 * DVB Devices
 */
char *dvb_frontenddev[DVB_MAX_DEVS] = {
	"/dev/dvb/adapter0/frontend0",
	"/dev/dvb/adapter1/frontend0",
	"/dev/dvb/adapter2/frontend0",
	"/dev/dvb/adapter3/frontend0",
	"/dev/dvb/adapter4/frontend0",
	"/dev/dvb/adapter5/frontend0"
};

char *dvb_demuxdev[DVB_MAX_DEVS] = {
	"/dev/dvb/adapter0/demux0",
	"/dev/dvb/adapter1/demux0",
	"/dev/dvb/adapter2/demux0",
	"/dev/dvb/adapter3/demux0",
	"/dev/dvb/adapter4/demux0",
	"/dev/dvb/adapter5/demux0"
};

char *dvb_dvrdev[DVB_MAX_DEVS] = {
	"/dev/dvb/adapter0/dvr0",
	"/dev/dvb/adapter1/dvr0",
	"/dev/dvb/adapter2/dvr0",
	"/dev/dvb/adapter3/dvr0",
	"/dev/dvb/adapter4/dvr0",
	"/dev/dvb/adapter5/dvr0"
};

/**
 * Cleanup handler
 */
void dvb_cleanup_fd (void *data)
{
	dvb_fd *fd = (dvb_fd *) data;

	if (data == NULL)
		return;

	dvb_fd_destroy (fd);
}


/**
 * DVB fd manipulator
 */
int dvb_fd_init (dvb_fd *fd, dvb_tune *tune, int card, int npids, uint16_t *pids)
{
	int dvbs_band = DVB_S_FREQ_L;
	int timeleft, i;
	struct dvb_frontend_info fe_info;
	struct dvb_frontend_parameters fe_params;
	struct dvb_frontend_event fe_event;
	struct dmx_pes_filter_params pes_filter_params;
	struct pollfd pollfd;

	assert(card >= 0);
	assert(card < DVB_MAX_DEVS);

	/* Initializing dvb_fd struct */
	fd->card = card;
	fd->fd_frontend = fd->fd_dvr = -1;
	for (i = 0; i < DVB_MAX_PIDS; i++)
		fd->fd_pids[i] = -1;

	/* Opening frontend fd */
	fd->fd_frontend = open(dvb_frontenddev[card], O_RDWR | O_NONBLOCK);
	if (fd->fd_frontend < 0)
	{
		pthread_mutex_lock (&log_strerror_buf_mutex);
		strerror_r(errno, log_strerror_buf, LOG_STRERROR_BUFLEN);
		log_error("Unable to open frontend device (%s)", log_strerror_buf);
		pthread_mutex_unlock (&log_strerror_buf_mutex);
		dvb_fd_destroy (fd);
		return -1;
	}

	/* Obtaining card type */
	if (ioctl(fd->fd_frontend, FE_GET_INFO, &fe_info) < 0)
	{
		pthread_mutex_lock (&log_strerror_buf_mutex);
		strerror_r(errno, log_strerror_buf, LOG_STRERROR_BUFLEN);
		log_error("Unable to get frontend infos (%s)", log_strerror_buf);
		pthread_mutex_unlock (&log_strerror_buf_mutex);
		dvb_fd_destroy (fd);
		return -1;
	}

	/* Preparing tuning parameters */
	log_debug("DVB card name is '%s'", fe_info.name);
	switch (fe_info.type)
	{
		case FE_OFDM:
			fe_params.frequency = tune->frequency;
			fe_params.inversion = INVERSION_AUTO;
			fe_params.u.ofdm.bandwidth = tune->bandwidth;
			fe_params.u.ofdm.code_rate_HP = tune->hpcoderate;
			fe_params.u.ofdm.code_rate_LP = tune->lpcoderate;
			fe_params.u.ofdm.constellation = tune->modulation;
			fe_params.u.ofdm.transmission_mode = tune->transmitmode;
			fe_params.u.ofdm.guard_interval = tune->guardinterval;
			fe_params.u.ofdm.hierarchy_information = DVB_T_DEF_HIERARCHY;

			log_debug("Tuning to DVB-T, freq = %d Hz, bandwidth = %s MHz", tune->frequency,
				    (tune->bandwidth == BANDWIDTH_8_MHZ ? "8" : (tune->bandwidth == BANDWIDTH_7_MHZ ? "7" :
						    (tune->bandwidth == BANDWIDTH_6_MHZ ? "6" : "auto"))));
			break;

		case FE_QPSK:
			dvbs_band = (tune->frequency < DVB_S_BORDERFREQ ? DVB_S_FREQ_L : DVB_S_FREQ_H);

			fe_params.frequency = tune->frequency - (dvbs_band == DVB_S_FREQ_L ? DVB_S_LOWERFREQ : DVB_S_UPPERFREQ);
			fe_params.inversion = INVERSION_AUTO;
			fe_params.u.qpsk.symbol_rate = tune->symbolrate;
			fe_params.u.qpsk.fec_inner = FEC_AUTO;

			log_debug("Tuning to DVB-S, freq = %d Hz, polarity = %s, frequency band = %s, symbol rate = %d", fe_params.frequency,
				    (tune->polarity == DVB_S_POLARITY_H ? "H" : "V"), (dvbs_band == DVB_S_FREQ_L ? "low" : "high"), tune->symbolrate);

			/* Sending diseqc message */
			if (ioctl(fd->fd_frontend, FE_SET_VOLTAGE, (tune->polarity == DVB_S_POLARITY_V ? SEC_VOLTAGE_13 : SEC_VOLTAGE_18)) < 0)
			{
				pthread_mutex_lock (&log_strerror_buf_mutex);
				strerror_r(errno, log_strerror_buf, LOG_STRERROR_BUFLEN);
				log_error("Unable to set polarity (%s)", log_strerror_buf);
				pthread_mutex_unlock (&log_strerror_buf_mutex);
				dvb_fd_destroy (fd);
				return -1;
			}

			if (ioctl(fd->fd_frontend, FE_SET_TONE, (dvbs_band == DVB_S_FREQ_H ? SEC_TONE_ON : SEC_TONE_OFF)) < 0)
			{
				pthread_mutex_lock (&log_strerror_buf_mutex);
				strerror_r(errno, log_strerror_buf, LOG_STRERROR_BUFLEN);
				log_error("Unable to set frequency band (%s)", log_strerror_buf);
				pthread_mutex_unlock (&log_strerror_buf_mutex);
				dvb_fd_destroy (fd);
				return -1;
			}

			usleep(15 * 1000);
			break;

		case FE_QAM:
			fe_params.frequency = tune->frequency;
			fe_params.inversion=INVERSION_OFF;
			fe_params.u.qam.symbol_rate = tune->symbolrate;
			fe_params.u.qam.fec_inner = FEC_AUTO;
			fe_params.u.qam.modulation = tune->modulation;

			log_debug("Tuning to DVB-C, freq = %d Hz, symbol rate = %d", tune->frequency, tune->symbolrate);
			break;
		default:
			log_error("Unknown frontend type");
			dvb_fd_destroy (fd);
			return -1;
	}

	/* Preparing tuning timeframe */
	usleep(100 * 1000);

	timeleft = (tune->tunetimeout > 0 ? tune->tunetimeout : DVB_TUNE_TIMEOUT);

	/* Emptying event queue */
	while (1)
	{
		if (ioctl(fd->fd_frontend, FE_GET_EVENT, &fe_event) < 0)
			break;
	}

	/* Tuning */
	if (ioctl(fd->fd_frontend, FE_SET_FRONTEND, &fe_params) < 0)
	{
		pthread_mutex_lock (&log_strerror_buf_mutex);
		strerror_r(errno, log_strerror_buf, LOG_STRERROR_BUFLEN);
		log_error("Unable to tune the card (%s)", log_strerror_buf);
		pthread_mutex_unlock (&log_strerror_buf_mutex);
		dvb_fd_destroy (fd);
		return -1;
	}

	/* Polling status of the acquisition of signal */
	pollfd.fd = fd->fd_frontend;
	pollfd.events = POLLPRI;

	memset (&fe_event, 0, sizeof (fe_event));
	while (((fe_event.status & FE_TIMEDOUT) == 0) && ((fe_event.status & FE_HAS_LOCK) == 0) && timeleft > 0)
	{
		timeleft -= 10;
		if (poll(&pollfd, 1, 10 * 1000) > 0)
		{
			if (pollfd.revents & POLLPRI)
			{
				if (ioctl(fd->fd_frontend, FE_GET_EVENT, &fe_event) < 0 && errno != EOVERFLOW)
				{
					pthread_mutex_lock (&log_strerror_buf_mutex);
					strerror_r(errno, log_strerror_buf, LOG_STRERROR_BUFLEN);
					log_error("Unable to get event while tuning the card (%s)", log_strerror_buf);
					pthread_mutex_unlock (&log_strerror_buf_mutex);
					dvb_fd_destroy (fd);
					return -1;
				}
			}
		}
	}

	/* Checking tuning result */
	if (fe_event.status & FE_HAS_LOCK)
	{
		int16_t strength = 0;
		int16_t snr = 0;
		uint32_t ber = 0xFFFFFFFF;
		fe_status_t fe_status = 0;

		switch (fe_info.type)
		{
			case FE_OFDM:
				log_info("Got tuning event: frequency = %d Hz", fe_event.parameters.frequency);
				break;
			case FE_QPSK:
				log_info("Got tuning event: frequency = %d Hz, symbol_rate = %d, inner fec = %d",
					    fe_event.parameters.frequency + (dvbs_band == DVB_S_FREQ_L ? DVB_S_LOWERFREQ : DVB_S_UPPERFREQ),
					    fe_event.parameters.u.qpsk.symbol_rate, fe_event.parameters.u.qpsk.fec_inner);
				break;
			case FE_QAM:
				log_info("Got tuning event: frequency = %d Hz, symbol_rate = %d, inner fec = %d",
					    fe_event.parameters.frequency, fe_event.parameters.u.qpsk.symbol_rate, fe_event.parameters.u.qpsk.fec_inner);
				break;
			default:
				break;
		}

		ioctl(fd->fd_frontend, FE_READ_BER, &ber);
		ioctl(fd->fd_frontend, FE_READ_SIGNAL_STRENGTH, &strength);
		ioctl(fd->fd_frontend, FE_READ_SNR, &snr);
		ioctl(fd->fd_frontend, FE_READ_STATUS, &fe_status);

		log_info("Tuning result: BER = %lu, Sig strength = %u, SNR = %u, status =%s%s%s%s%s%s", ber, strength & 0xFFFFL, snr & 0xFFFFL,
			    (fe_status & FE_HAS_SIGNAL ? " FE_HAS_SIGNAL" : ""),
			    (fe_status & FE_TIMEDOUT ? " FE_TIMEDOUT" : ""),
			    (fe_status & FE_HAS_LOCK ? " FE_HAS_LOCK" : ""),
			    (fe_status & FE_HAS_CARRIER ? " FE_HAS_CARRIER" : ""),
			    (fe_status & FE_HAS_VITERBI ? " FE_HAS_VITERBI" : ""),
			    (fe_status & FE_HAS_SYNC ? " FE_HAS_SYNC" : ""));

	}
	else
	{
		log_error("Unable to lock to the signal on the given frequency");
		dvb_fd_destroy (fd);
		return -1;
	}

	/* Creating fds and setting filters */
	assert(npids >= 0);

	pes_filter_params.input = DMX_IN_FRONTEND;
	pes_filter_params.output = DMX_OUT_TS_TAP;
	pes_filter_params.pes_type = DMX_PES_OTHER;
	pes_filter_params.flags = DMX_IMMEDIATE_START;

	for (i = 0; i < npids; i++)
	{
		assert(pids[i] < DVB_MAX_PIDS);

		if ((fd->fd_pids[pids[i]] = open (dvb_demuxdev[card], O_RDWR)) < 0)
		{
			pthread_mutex_lock (&log_strerror_buf_mutex);
			strerror_r(errno, log_strerror_buf, LOG_STRERROR_BUFLEN);
			log_error("Unable to open demux device for pid %d (%s)", pids[i], log_strerror_buf);
			pthread_mutex_unlock (&log_strerror_buf_mutex);
			dvb_fd_destroy (fd);
			return -1;
		}

		pes_filter_params.pid = pids[i];
		if (ioctl (fd->fd_pids[pids[i]], DMX_SET_PES_FILTER, &pes_filter_params) < 0)
		{
			pthread_mutex_lock (&log_strerror_buf_mutex);
			strerror_r(errno, log_strerror_buf, LOG_STRERROR_BUFLEN);
			log_error("Unable set pes filter for pid %d (%s)", pids[i], log_strerror_buf);
			pthread_mutex_unlock (&log_strerror_buf_mutex);
			dvb_fd_destroy (fd);
			return -1;
		}

		log_debug("Opened fd for pid %" PRIu16, pids[i]);
	}

	if ((fd->fd_dvr = open (dvb_dvrdev[card], O_RDONLY | O_NONBLOCK)) < 0)
	{
		pthread_mutex_lock (&log_strerror_buf_mutex);
		strerror_r(errno, log_strerror_buf, LOG_STRERROR_BUFLEN);
		log_error("Unable to open DVR device (%s)", log_strerror_buf);
		pthread_mutex_unlock (&log_strerror_buf_mutex);
		dvb_fd_destroy (fd);
		return -1;
	}

	return 0;
}

void dvb_fd_destroy (dvb_fd *fd)
{
	int i;

	if (fd == NULL)
		return;

	if (fd->fd_frontend >= 0)
	{
		close (fd->fd_frontend);
		fd->fd_frontend = -1;
	}
	if (fd->fd_dvr >= 0)
	{
		close (fd->fd_dvr);
		fd->fd_dvr = -1;
	}

	for (i = 0; i < DVB_MAX_PIDS; i++)
	{
		if (fd->fd_pids[i] >= 0)
		{
			close (fd->fd_pids[i]);
			fd->fd_pids[i] = -1;
		}
	}
}

dvb_card_type dvb_type (int card)
{
	int fd_frontend;
	struct dvb_frontend_info fe_info;

	assert(card >= 0);
	assert(card < DVB_MAX_DEVS);

	fd_frontend = open(dvb_frontenddev[card], O_RDWR | O_NONBLOCK);
	if (fd_frontend < 0)
	{
		log_debug("Card %d does not exist", card);
		return DVB_NONE;
	}

	if (ioctl(fd_frontend, FE_GET_INFO, &fe_info) < 0)
	{
		pthread_mutex_lock (&log_strerror_buf_mutex);
		strerror_r(errno, log_strerror_buf, LOG_STRERROR_BUFLEN);
		log_error("Unable to get frontend infos for card %d (%s)", card, log_strerror_buf);
		pthread_mutex_unlock (&log_strerror_buf_mutex);
		close (fd_frontend);
		return DVB_NONE;
	}

	switch (fe_info.type)
	{
		case FE_OFDM:
			log_debug("Card %d is a DVB-T card (name: %s)", card, fe_info.name);
			close (fd_frontend);
			return DVB_DVB_T;

		case FE_QPSK:
			log_debug("Card %d is a DVB-S card (name: %s)", card, fe_info.name);
			close (fd_frontend);
			return DVB_DVB_S;

		case FE_QAM:
			log_debug("Card %d is a DVB-C card (name: %s)", card, fe_info.name);
			close (fd_frontend);
			return DVB_DVB_C;

		default:
			log_debug("Card %d is of unknown type", card);
			close (fd_frontend);
			return DVB_NONE;
	}
}
