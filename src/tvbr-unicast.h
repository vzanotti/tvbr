/*****************************************************************************
 * tvbr-unicast.h :  TV-Unicaster headers
 *****************************************************************************
 * Copyright (C) 2006 Binet Réseau
 * $Id: tvbr-unicast.h 913 2007-01-14 18:44:57Z vinz2 $
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

#ifndef _TVBR_UNICAST_H
#define _TVBR_UNICAST_H

#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "log.h"
#include "udpsocket.h"

#define IPC_SOCKET	"/tmp/tvbr.sock"
#define IPC_BUFFER	4096

/* IPC Header */
#define IPC_MAGIC			0x76545242
#define IPC_VERSION		0x04
#define IPC_TEXT_LENGTH		2048
#define IPC_URL_LENGTH		32
#define IPC_GROUP_LENGTH	16
#define IPC_MAX_PACKET_SIZE	3200
#define IPC_IP_LENGTH		20
typedef enum {
	IPC_NOOP = 0,		// Prevent the TCP connection from terminating
	IPC_ACCESS_REQUEST,	// Ask for an authorization for given url
	IPC_ACCESS_ACCEPT,	// Accept access
	IPC_ACCESS_DENY,		// Deny access
	IPC_URLLIST_GET,		// Ask for list of allowed URL
	IPC_URLLIST,		// Send back list of allowed URL
	IPC_BWGROUP_GET,		// Ask for list of BW Groups
	IPC_BWGROUP_LIST,		// Send back list of BW Groups
	IPC_CONNECTION_GET,	// Ask for list of connected people
	IPC_CONNECTION_LIST	// Get list of connected people
} ipc_packet_type;

typedef struct {
	unsigned int magic  : 32;
	unsigned int version: 8;
	unsigned int length : 16;
	unsigned int type   : 8;
} ipc_header;

/* IPC Commands */
typedef struct {
	unsigned int host_ip : 32;
	unsigned char url[IPC_URL_LENGTH];
} ipc_access_request;
typedef struct {
	unsigned int query_port : 16;
	unsigned char query_ip[IPC_IP_LENGTH];
} ipc_access_accept;
typedef struct {
	unsigned int status : 16;
	unsigned char answer[IPC_TEXT_LENGTH];
} ipc_access_deny;

typedef struct {
	unsigned int host_ip : 32;
} ipc_request_list;
typedef struct {
	unsigned int host_ip    : 32;
	unsigned int number     : 8;
	unsigned int _reserved1 : 24;
} ipc_answer_list;

typedef struct {
	unsigned char url[IPC_URL_LENGTH];
	unsigned char ip[IPC_IP_LENGTH];
	unsigned int port       : 16;
	unsigned int _reserved1 : 16;
} ipc_url;

typedef struct {
	unsigned char name[IPC_GROUP_LENGTH];
	unsigned int max_bw : 32;
	unsigned int allocated_bw : 32;
	unsigned int max_channels : 32;
	unsigned int allocated_channels : 32;
} ipc_bwgroup;

typedef struct {
	unsigned char url[IPC_URL_LENGTH];
	unsigned int host_ip : 32;
	unsigned int start_time : 32;
} ipc_connection;


typedef struct {
	unsigned int packet_length;
	ipc_header headers;
	union {
		ipc_access_request access_request;
		ipc_access_deny access_deny;
		ipc_access_accept access_accept;
		ipc_request_list request_list;
		ipc_answer_list answer_list;
	} payload;
	unsigned int list_length;
	unsigned char list[IPC_MAX_PACKET_SIZE];
} ipc_packet;

/* IPC Encode & Decode */
int ipc_recv(int, unsigned char*, int, int);
int ipc_decode (const unsigned char *, const int, ipc_packet *);
int ipc_encode_headers (ipc_packet *, ipc_packet_type);
int ipc_encode_packet (ipc_packet *, unsigned char *);
int ipc_encode_noop (ipc_packet *, unsigned char *);
int ipc_encode_access_request (ipc_packet *, unsigned char *, uint32_t, char *);
int ipc_encode_access_accept (ipc_packet *, unsigned char *, char *, unsigned int);
int ipc_encode_access_deny (ipc_packet *, unsigned char *, char *, int);
int ipc_encode_connection_get (ipc_packet *, unsigned char *);
int ipc_encode_urllist_get (ipc_packet *, unsigned char *, uint32_t);
int ipc_encode_bwlist_get (ipc_packet *, unsigned char *, uint32_t);
int ipc_encode_list_answer_url (ipc_packet *);
int ipc_encode_list_answer_bw (ipc_packet *);
int ipc_encode_list_answer_conn (ipc_packet *);
int ipc_encode_answer (ipc_packet *packet, unsigned char *, uint32_t);
int ipc_encode_urllist_add (ipc_packet *, unsigned char *, char *, char *, unsigned int);
int ipc_encode_bwlist_add (ipc_packet *, unsigned char *, char *, unsigned int, unsigned int, unsigned int, unsigned int);
int ipc_encode_connlist_add (ipc_packet *, unsigned char *, unsigned int, char *, unsigned int);

#endif
