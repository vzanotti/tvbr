/*****************************************************************************
 * tvbr.h :  TVBR headers
 *****************************************************************************
 * Copyright (C) 2006 Binet Réseau
 * $Id: tvbr.h 887 2006-12-14 02:28:24Z vinz2 $
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

#ifndef _TVBR_H
#define _TVBR_H

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/time.h>

#include <pthread.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <ctype.h>

#include "log.h"
#include "udpsocket.h"

/**
 *  Logging headers
 */
#define LOG_STRERROR_BUFLEN 256
void log_debug (const char *format, ...);
void log_info (const char *format, ...);
void log_warn (const char *format, ...);
void log_error (const char *format, ...);

/**
 *  Logging global vars & locks
 */
extern pthread_mutex_t log_fd_mutex;
extern int log_fd;
extern pthread_mutex_t log_strerror_buf_mutex;
extern char log_strerror_buf[LOG_STRERROR_BUFLEN];

/**
 *  DVB Headers
 */
#include <linux/dvb/dmx.h>
#include <linux/dvb/frontend.h>

#define DVB_S_BORDERFREQ	(11700*1000UL)
#define DVB_S_LOWERFREQ		(9750*1000UL)
#define DVB_S_UPPERFREQ		(10600*1000UL)
#define DVB_S_FREQ_L		0
#define DVB_S_FREQ_H		1
#define DVB_S_POLARITY_H	0
#define DVB_S_POLARITY_V	1

#define DVB_T_DEF_BANDWIDTH	BANDWIDTH_8_MHZ
#define DVB_T_DEF_HPCODERATE	FEC_AUTO
#define DVB_T_DEF_LPCODERATE	FEC_AUTO
#define DVB_T_DEF_CONSTELL	QAM_AUTO
#define DVB_T_DEF_TRANSMODE	TRANSMISSION_MODE_AUTO
#define DVB_T_DEF_GUARD		GUARD_INTERVAL_AUTO
#define DVB_T_DEF_HIERARCHY	HIERARCHY_NONE

#define DVB_TUNE_TIMEOUT	21

#define DVB_TS_PACKETSIZE	188
#define DVB_TS_PACKETSATONCE	20

#define DVB_MAX_DEVS		6
#define DVB_MAX_PIDS		8192
#define DVB_MAX_PMT_PIDS	16

typedef enum {
	DVB_MODE_NOTTUNED,
	DVB_MODE_TUNING,
	DVB_MODE_TUNED
} dvb_mode;
typedef struct {
	int card;
	int fd_dvr;
	int fd_frontend;
	int fd_pids[DVB_MAX_PIDS];
} dvb_fd;
typedef struct {
	unsigned int frequency;
	unsigned int symbolrate;
	unsigned int polarity;
	fe_modulation_t modulation;
	fe_code_rate_t hpcoderate;
	fe_code_rate_t lpcoderate;
	fe_transmit_mode_t transmitmode;
	fe_guard_interval_t guardinterval;
	fe_bandwidth_t bandwidth;
	unsigned int tunetimeout;
} dvb_tune;
typedef enum {
	DVB_NONE = 0,
	DVB_DVB_T,
	DVB_DVB_S,
	DVB_DVB_C
} dvb_card_type;

int dvb_fd_init (dvb_fd *fd, dvb_tune *tune, int card, int npids, uint16_t *pids);
void dvb_fd_destroy (dvb_fd *fd);
void dvb_cleanup_fd (void *data);
dvb_card_type dvb_type (int card);

/**
 *  Main headers
 */
typedef enum {
	TVBR_MEDIA_VIDEO,
	TVBR_MEDIA_AUDIO
} tvbr_media_type;

typedef struct {
	char *group_name;
	char *channel_name;
	tvbr_media_type media_type;

	in_addr_t dst_ip;
	unsigned short dst_port;
	unsigned int dst_ttl;

	unsigned int npids;
	uint16_t *pids;
	uint16_t pmt_filter;
	uint16_t pmt_pcr_pid;
} tvbr_channel;

typedef struct {
	unsigned int frequency;
	fe_bandwidth_t bandwidth;
	fe_code_rate_t hpcoderate;
	fe_code_rate_t lpcoderate;
	fe_modulation_t modulation;
	fe_transmit_mode_t transmitmode;
	fe_transmit_mode_t guardinterval;
} tvbr_card_dvbt;
typedef struct {
	unsigned int frequency;
	unsigned int polarity;
	unsigned int symbolrate;
} tvbr_card_dvbs;
typedef struct {
	unsigned int frequency;
	unsigned int symbolrate;
	unsigned int modulation;
} tvbr_card_dvbc;
typedef struct {
	dvb_card_type card_type;
	int card;

	union {
		tvbr_card_dvbt dvbt;
		tvbr_card_dvbs dvbs;
		tvbr_card_dvbc dvbc;
	} u;

	unsigned int nchannels;
	tvbr_channel *channels;
} tvbr_card;

typedef enum {
	TVBR_STATUS_NOTSTARTED,
	TVBR_STATUS_STARTED,
	TVBR_STATUS_MUSTSTOP
} tvbr_status;

typedef enum {
	TVBR_START = 0x01,
	TVBR_STOP  = 0x02
} tvbr_restart;

typedef enum {
	TVBR_OK   = 0x00,
	TVBR_HUP  = 0x01,
	TVBR_TERM = 0x02
} tvbr_mainstatus;

/**
 *  Main global vars & locks
 */
#define TVBR_SLEEP_MAINLOOP		800000
#define TVBR_SLEEP_GRACE		2000000
#define TVBR_IPSTR_SIZE			20

extern pthread_mutex_t tvbr_card_status_mutex;
extern tvbr_status tvbr_card_status[DVB_MAX_DEVS];
extern pthread_key_t tvbr_card_key;

/**
 *  Stream threads global vars & locks
 */
extern pthread_mutex_t dvb_tuned_card_mutex;
extern int dvb_tuned_card;
extern pthread_t dvb_tuned_card_thread;

extern pthread_mutex_t tvbr_running_config_mutex;
extern tvbr_card tvbr_running_config[DVB_MAX_DEVS];
extern tvbr_card tvbr_standard_config[DVB_MAX_DEVS];

/**
 *  Stream threads headers
 */
#define STREAM_UDP_PACKETSIZE		1468
#define STREAM_LOOP_POLLTIMEOUT	100
#define STREAM_STATS_COUNT		50000
#define STREAM_TIMEOUT_COUNT		200
#define STREAM_LOOPCHECK_COUNT	10000
#define STREAM_LOOPCHECK_TIMEOUT	(STREAM_LOOPCHECK_COUNT/STREAM_LOOP_POLLTIMEOUT*STREAM_LOOPCHECK_PACKET)
#define STREAM_LOOPCHECK_PACKET	1

typedef struct {
	tvbr_channel *channel;

	unsigned int buffered;
	unsigned char udpbuffer[STREAM_UDP_PACKETSIZE];
	uint16_t pids[DVB_MAX_PIDS];
	
	uint8_t ts_continuity;

	int fd_udp;
	struct sockaddr_in sout;
} stream_channel;

typedef struct {
	unsigned int nchannels;
	stream_channel *channels;
} stream_channels;

void *stream_main (void *);

/**
 *  SAP threads headers
 */
#define SAP_UDP_PORT		9875
#define SAP_UDP_IP		"239.255.255.255"
#define SAP_UDP_TTL		10
#define SAP_MESSAGE_LENGTH	1000
#define SAP_SDP_OWNER		"BinetReseau"
#define SAP_SDP_TOOL		"TVBR"
#define SAP_SDP_URL		"http://tv.eleves.polytechnique.fr/"
#define SAP_CYCLE_TIME		5000000

typedef struct {
	uint64_t sdp_sid;
	int sdp_version;

	char *sdp_name;
	char *sdp_group;
	tvbr_media_type media_type;

	struct in_addr src_ip;
	struct in_addr dst_ip;
	unsigned short dst_port;
	unsigned short dst_ttl;
} sap_channel;

struct sap_message_t;
typedef struct sap_message_t {
	unsigned char message[SAP_MESSAGE_LENGTH];
	unsigned int msglen;
	struct sap_message_t *next;
} sap_message;

extern pthread_mutex_t sap_status_mutex;
extern tvbr_mainstatus sap_status;

void *sap_main (void *);
int sap_register (int card, sap_channel *channel);
int sap_unregister (int card);

/**
 *  Config headers
 */
#define CONFIG_DEFAULT_PORT	1234
#define CONFIG_DEFAULT_TTL	10
int config_cards (const char *cards);
int config_channels ();
int config_streams (const char *host);
int config_apply ();
void config_cleanup ();

#endif
