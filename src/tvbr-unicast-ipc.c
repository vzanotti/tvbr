/*****************************************************************************
 * tvbr-unicast-ipc.c :  TV-Unicaster Client-Server communications
 *****************************************************************************
 * Copyright (C) 2006 Binet Réseau
 * $Id: tvbr-unicast-ipc.c 957 2007-02-22 15:57:41Z vinz2 $
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

/* Reading socket */
int ipc_recv(int socket, unsigned char *buffer, int buffer_length, int recv_flags)
{
	int read, read2, len;

	read = recv(socket, buffer, sizeof(ipc_header), recv_flags);
	if (read <= 0)
	{
		return read;
	}

	len = ((ipc_header *)buffer) -> length;
	if (len > buffer_length - (int)sizeof(ipc_header))
		len = buffer_length - sizeof(ipc_header);
	if (len < 0)
		len = 0;

	read2 = recv(socket, buffer + sizeof(ipc_header), len, recv_flags);
	if (read2 <= 0)
		return read2;
	else
		return read2 + sizeof(ipc_header);
}

/* Decoding IPC */
int ipc_decode (const unsigned char *buffer, const int length, ipc_packet *packet)
{
	int element_size;

	packet->packet_length = 0;
	packet->list_length = 0;

	if (buffer == NULL || packet == NULL)
	{
		return 0;
	}

	/* Verifying packet size */
	if (length < (int)sizeof (ipc_header))
	{
		log_debug ("ignoring too short message (missing headers)");
		return 0;
	}
	packet->packet_length = length;

	/* Preparing packet headers & verifying magics */
	memcpy (&(packet->headers), buffer, sizeof(ipc_header));

	if (packet->headers.magic != IPC_MAGIC)
	{
		log_warn ("ignoring packet with bad magic (expected: %08x, found: %08x)", IPC_MAGIC, *((uint32_t *)buffer));
		return 0;
	}
	if (packet->headers.version != IPC_VERSION)
	{
		log_warn("ignoring packet with bad version (expected: %d, found: %d)", IPC_VERSION, packet->headers.version);
		return 0;
	}
	if (packet->headers.length + sizeof (ipc_header) != packet->packet_length)
	{
		log_warn("ignoring packet with different packet length (real: %d, found in headers: %d)", packet->packet_length, packet->headers.length);
		return 0;
	}

	/* Packet payload */
	switch (packet->headers.type)
	{
		case IPC_NOOP:
		case IPC_CONNECTION_GET:
			if (packet->headers.length != 0)
			{
				log_info("found %d garbage bytes at end of packet", packet->headers.length);
			}
			break;

		case IPC_ACCESS_REQUEST:
			if (packet->headers.length > sizeof (ipc_access_request))
			{
				log_info("found %zu garbage bytes at end of packet", packet->headers.length - sizeof (ipc_access_request));
			}
			else if (packet->headers.length < sizeof (ipc_access_request))
			{
				log_warn("ignoring too short message (incomplete payload)");
				return 0;
			}
			memcpy (&(packet->payload.access_request), buffer + sizeof(ipc_header), sizeof (ipc_access_request));
			break;

		case IPC_ACCESS_ACCEPT:
			if (packet->headers.length > sizeof (ipc_access_accept))
			{
				log_info("found %zu garbage bytes at end of packet", packet->headers.length - sizeof (ipc_access_accept));
			}
			else if (packet->headers.length < sizeof (ipc_access_accept))
			{
				log_warn("ignoring too short message (incomplete payload)");
				return 0;
			}
			memcpy (&(packet->payload.access_accept), buffer + sizeof(ipc_header), sizeof (ipc_access_accept));
			break;

		case IPC_ACCESS_DENY:
			if (packet->headers.length > sizeof (ipc_access_deny))
			{
				log_info("found %zu garbage bytes at end of packet", packet->headers.length - sizeof (ipc_access_deny));
			}
			else if (packet->headers.length < sizeof (ipc_access_deny))
			{
				log_warn("ignoring too short message (incomplete payload)");
				return 0;
			}
			memcpy (&(packet->payload.access_deny), buffer + sizeof(ipc_header), sizeof (ipc_access_deny));
			break;

		case IPC_URLLIST_GET:
		case IPC_BWGROUP_GET:
			if (packet->headers.length > sizeof (ipc_request_list))
			{
				log_info("found %zu garbage bytes at end of packet", packet->headers.length - sizeof (ipc_request_list));
			}
			else if (packet->headers.length < sizeof (ipc_request_list))
			{
				log_warn("ignoring too short message (incomplete payload)");
				return 0;
			}
			memcpy (&(packet->payload.request_list), buffer + sizeof(ipc_header), sizeof (ipc_request_list));
			break;

		case IPC_URLLIST:
		case IPC_BWGROUP_LIST:
		case IPC_CONNECTION_LIST:
			/* Preparing payload header */
			switch (packet->headers.type)
			{
				case IPC_URLLIST:
					element_size = sizeof (ipc_url);
					break;
				case IPC_BWGROUP_LIST:
					element_size = sizeof (ipc_bwgroup);
					break;
				case IPC_CONNECTION_LIST:
					element_size = sizeof (ipc_connection);
					break;
				default:
					return 0;
			}

			if (packet->headers.length < sizeof (ipc_answer_list))
			{
				log_warn("ignoring too short message (incomplete payload)");
				return 0;
			}

			memcpy (&(packet->payload.answer_list), buffer + sizeof(ipc_header), sizeof (ipc_answer_list));

			if (packet->headers.length > sizeof (ipc_answer_list) + (element_size * packet->payload.answer_list.number))
			{
				log_info("found %zu garbage bytes at end of packet", packet->headers.length - sizeof (ipc_answer_list) - (element_size * packet->payload.answer_list.number));
			}
			else if (packet->headers.length < sizeof (ipc_answer_list) + (element_size * packet->payload.answer_list.number))
			{
				log_warn("ignoring too short message (incomplete list)");
				return 0;
			}

			/* Preparing list */
			packet->list_length = packet->payload.answer_list.number;
			memcpy(packet->list, buffer + sizeof(ipc_header) + sizeof (ipc_answer_list), element_size * packet->payload.answer_list.number);
			break;

		default:
			log_warn("ignoring packet with unknown type (%d)", packet->headers.type);
			return 0;
	}

	return 1;
}

/* IPC Generic Encode */
int ipc_encode_headers (ipc_packet *packet, ipc_packet_type type)
{
	if (packet == NULL)
		return 0;

	packet->headers.magic = IPC_MAGIC;
	packet->headers.version = IPC_VERSION;
	packet->headers.length = 0;
	packet->headers.type = type;

	packet->packet_length = 0;
	packet->list_length = 0;

	return 1;
}
int ipc_encode_packet (ipc_packet *packet, unsigned char *buffer)
{
	int element_size = 0, payload_size = 0;

	if (packet == NULL || buffer == NULL)
		return 0;

	/* Copying payload */
	switch (packet->headers.type)
	{
		case IPC_NOOP:
		case IPC_CONNECTION_GET:
			payload_size = 0;
			break;

		case IPC_ACCESS_REQUEST:
			payload_size = sizeof (ipc_access_request);
			break;

		case IPC_ACCESS_ACCEPT:
			payload_size = sizeof (ipc_access_accept);
			break;

		case IPC_ACCESS_DENY:
			payload_size = sizeof (ipc_access_deny);
			break;

		case IPC_URLLIST_GET:
		case IPC_BWGROUP_GET:
			payload_size = sizeof (ipc_request_list);
			break;

		case IPC_URLLIST:
			payload_size = sizeof (ipc_answer_list);
			element_size = sizeof (ipc_url);
			break;
		case IPC_BWGROUP_LIST:
			payload_size = sizeof (ipc_answer_list);
			element_size = sizeof (ipc_bwgroup);
			break;
		case IPC_CONNECTION_LIST:
			payload_size = sizeof (ipc_answer_list);
			element_size = sizeof (ipc_connection);
			break;

		default:
			return 0;
	}
	memcpy (buffer + sizeof (ipc_header), &(packet->payload), payload_size);

	/* Copying list */
	if (packet->list_length > 0 && element_size > 0)
	{
		memcpy (buffer + sizeof (ipc_header) + payload_size, packet->list, element_size * packet->list_length);
	}

	/* Copying headers */
	packet->headers.length = element_size * packet->list_length + payload_size;
	packet->packet_length = packet->headers.length + sizeof (ipc_header);
	memcpy (buffer, &(packet->headers), sizeof (ipc_header));

	return 1;
}

/* IPC Encode: NOOP & co */
int ipc_encode_noop (ipc_packet *packet, unsigned char *buffer)
{
	if (ipc_encode_headers(packet, IPC_NOOP))
	{
		return ipc_encode_packet (packet, buffer);
	}
	return 0;
}
int ipc_encode_connection_get (ipc_packet *packet, unsigned char *buffer)
{
	if (ipc_encode_headers(packet, IPC_CONNECTION_GET))
	{
		return ipc_encode_packet (packet, buffer);
	}
	return 0;
}

/* IPC Encode: Deny & request */
int ipc_encode_access_request (ipc_packet *packet, unsigned char *buffer, uint32_t host_ip, const char *url)
{
	if (ipc_encode_headers(packet, IPC_ACCESS_REQUEST))
	{
		packet->payload.access_request.host_ip = host_ip;
		strncpy((char *)packet->payload.access_request.url, url, IPC_URL_LENGTH);
		packet->payload.access_request.url[IPC_URL_LENGTH-1] = '\0';
		return ipc_encode_packet (packet, buffer);
	}
	return 0;
}
int ipc_encode_access_deny (ipc_packet *packet, unsigned char *buffer, const char *denial, int status)
{
	if (ipc_encode_headers(packet, IPC_ACCESS_DENY))
	{
		strncpy((char *)packet->payload.access_deny.answer, denial, IPC_TEXT_LENGTH);
		packet->payload.access_deny.answer[IPC_TEXT_LENGTH-1] = '\0';
		packet->payload.access_deny.status = status;
		return ipc_encode_packet (packet, buffer);
	}
	return 0;
}
int ipc_encode_access_accept (ipc_packet *packet, unsigned char *buffer, const char *ip, unsigned int port)
{
	if (ipc_encode_headers(packet, IPC_ACCESS_ACCEPT))
	{
		strncpy((char *)packet->payload.access_accept.query_ip, ip, IPC_IP_LENGTH);
		packet->payload.access_accept.query_ip[IPC_IP_LENGTH-1] = '\0';
		packet->payload.access_accept.query_port = port;
		return ipc_encode_packet (packet, buffer);
	}
	return 0;
}

/* IPC Encode: Generic list manipulation */
int ipc_encode_urllist_get (ipc_packet *packet, unsigned char *buffer, uint32_t host_ip)
{
	if (ipc_encode_headers(packet, IPC_URLLIST_GET))
	{
		packet->payload.request_list.host_ip = host_ip;
		return ipc_encode_packet (packet, buffer);
	}
	return 0;
}
int ipc_encode_bwlist_get (ipc_packet *packet, unsigned char *buffer, uint32_t host_ip)
{
	if (ipc_encode_headers(packet, IPC_BWGROUP_GET))
	{
		packet->payload.request_list.host_ip = host_ip;
		return ipc_encode_packet (packet, buffer);
	}
	return 0;
}

int ipc_encode_list_answer_url (ipc_packet *packet)
{
	return ipc_encode_headers(packet, IPC_URLLIST);
}
int ipc_encode_list_answer_bw (ipc_packet *packet)
{
	return ipc_encode_headers(packet, IPC_BWGROUP_LIST);
}
int ipc_encode_list_answer_conn (ipc_packet *packet)
{
	return ipc_encode_headers(packet, IPC_CONNECTION_LIST);
}

int ipc_encode_answer (ipc_packet *packet, unsigned char *buffer, uint32_t ip)
{
	packet->payload.answer_list.host_ip = ip;
	packet->payload.answer_list.number = packet->list_length;
	packet->payload.answer_list._reserved1 = 0;
	return ipc_encode_packet (packet, buffer);
}

/* IPC Encode: Adding to lists */

int ipc_encode_urllist_add (ipc_packet *packet, unsigned char *buffer, const char *url, const char *ip, unsigned int port)
{
	ipc_url *ptr;

	if (sizeof(ipc_header) + sizeof(ipc_answer_list) + (packet->list_length + 1) * sizeof(ipc_url) > IPC_MAX_PACKET_SIZE)
		return 0;

	ptr = &(((ipc_url *)packet->list)[packet->list_length++]);
	strncpy((char *)ptr->url, url, IPC_URL_LENGTH);
	ptr->url[IPC_URL_LENGTH-1] = '\0';
	strncpy((char *)ptr->ip, ip, IPC_IP_LENGTH);
	ptr->ip[IPC_IP_LENGTH-1] = '\0';
	ptr->port = port;
	ptr->_reserved1 = 0;
	return 1;
}

int ipc_encode_bwlist_add (ipc_packet *packet, unsigned char *buffer, const char *name, unsigned int max_bw, unsigned int alloc_bw, unsigned int max_channels, unsigned int alloc_channels)
{
	ipc_bwgroup *ptr;

	if (sizeof(ipc_header) + sizeof(ipc_answer_list) + (packet->list_length + 1) * sizeof(ipc_bwgroup) > IPC_MAX_PACKET_SIZE)
		return 0;

	ptr = &(((ipc_bwgroup *)packet->list)[packet->list_length++]);
	strncpy((char *)ptr->name, name, IPC_GROUP_LENGTH);
	ptr->name[IPC_GROUP_LENGTH-1] = '\0';

	ptr->max_bw = max_bw;
	ptr->allocated_bw = alloc_bw;
	ptr->max_channels = max_channels;
	ptr->allocated_channels = alloc_channels;
	return 0;
}

int ipc_encode_connlist_add (ipc_packet *packet, unsigned char *buffer, unsigned int host_ip, const char *url, unsigned int start_time)
{
	ipc_connection *ptr;

	if (sizeof(ipc_header) + sizeof(ipc_answer_list) + (packet->list_length + 1) * sizeof(ipc_connection) > IPC_MAX_PACKET_SIZE)
		return 0;

	ptr = &(((ipc_connection *)packet->list)[packet->list_length++]);
	strncpy((char *)ptr->url, url, IPC_URL_LENGTH);
	ptr->url[IPC_URL_LENGTH-1] = '\0';

	ptr->host_ip = host_ip;
	ptr->start_time = start_time;
	return 0;
}
