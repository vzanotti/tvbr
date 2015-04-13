/*****************************************************************************
 * socket.c :  UDP/Multicast socket helper
 *****************************************************************************
 * Copyright (C) 2006 Binet Réseau
 * $Id: udpsocket.c 817 2006-11-01 23:33:08Z vinz2 $
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

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include "log.h"
#include "udpsocket.h"

extern int verbosity;

int udpsocket_open (in_addr_t laddr, in_addr_t raddr, unsigned short port)
{
	int sock;
	int sockopt;

	/* Socket creation */
	sock = socket (PF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
	{
		log_error("could not open socket (%s)", strerror(errno));
		return -1;
	}

	/* Socket options */
	sockopt = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt)) < 0)
	{
		log_error("could not set SO_REUSEADDR socket option (%s)", strerror(errno));
		return -1;
	}
	if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &sockopt, sizeof(sockopt)) < 0)
	{
		log_error("could not set SO_BROADCAST socket option (%s)", strerror(errno));
		return -1;
	}
	if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, &sockopt, sizeof(sockopt)) < 0)
	{
		log_error("could not set IP_MULTICAST_LOOP socket option (%s)", strerror(errno));
		return -1;
	}

	return sock;
}
int udpsocket_ropen (in_addr_t laddr, in_addr_t raddr, unsigned short port)
{
	int sock = udpsocket_open (laddr, raddr, port);
	struct sockaddr_in sin;

	/* Socket binding */
	sin.sin_family = AF_INET;
# ifdef HAVE_SA_LEN
	sin.sin_len = sizeof (sin);
# endif
	if (IN_MULTICAST(ntohl(raddr)))
	{
		sin.sin_addr.s_addr = raddr;
	}
	else
	{
		sin.sin_addr.s_addr = laddr;
	}
	sin.sin_port = htons(port);

	if (bind(sock, (struct sockaddr*) &sin, sizeof(sin)) < 0)
	{
		log_error("could not bind socket to ip `%s' (%s)", inet_ntoa(sin.sin_addr), strerror(errno));
		return -1;
	}

	/* IP Multicast membership request */
	udpsocket_addmc(sock, laddr, raddr);

	return sock;

}
int udpsocket_wopen (in_addr_t laddr, in_addr_t raddr, unsigned short port)
{
	int sock = udpsocket_open (laddr, raddr, port);
	struct sockaddr_in sin;

	/* Socket binding */
	sin.sin_family = AF_INET;
# ifdef HAVE_SA_LEN
	sin.sin_len = sizeof (sin);
# endif
	sin.sin_addr.s_addr = laddr;
	sin.sin_port = htons(port);
	if (bind(sock, (struct sockaddr*) &sin, sizeof(sin)) < 0)
	{
		log_error("could not bind socket to ip `%s' (%s)", inet_ntoa(sin.sin_addr), strerror(errno));
		return -1;
	}

	return sock;
}
int udpsocket_connect (in_addr_t raddr, unsigned short port)
{
	int sock = udpsocket_open (INADDR_ANY, raddr, port);
	struct sockaddr_in sin;

	/* Socket binding */
	sin.sin_family = AF_INET;
# ifdef HAVE_SA_LEN
	sin.sin_len = sizeof (sin);
# endif
	sin.sin_addr.s_addr = raddr;
	sin.sin_port = htons(port);
	if (connect(sock, (struct sockaddr*) &sin, sizeof(sin)) < 0)
	{
		log_error("could not connect udp-socket to ip `%s' (%s)", inet_ntoa(sin.sin_addr), strerror(errno));
		return -1;
	}

	return sock;
}

int udpsocket_close (int sock)
{
	close(sock);
	return 0;
}

int udpsocket_addmc (int sock, in_addr_t laddr, in_addr_t raddr)
{
	struct ip_mreq mreq;
	if (IN_MULTICAST(ntohl(raddr)))
	{
		mreq.imr_multiaddr.s_addr = raddr;
		mreq.imr_interface.s_addr = laddr;

		log_info("IP_ADD_MEMBERSHIP on %s (local %s)", inet_ntoa(mreq.imr_multiaddr), inet_ntoa(mreq.imr_interface));

		if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
		{

			log_error("failed to add membership to %s (%s)", inet_ntoa(mreq.imr_multiaddr), strerror(errno));
			return -1;
		}
		return 0;
	}
	return -2;
}

int udpsocket_setttl (int sock, int ttl)
{
	if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0)
	{
		log_error("could not set IP_MULTICAST_TTL socket option (%s)", strerror(errno));
		return -1;
	}
	return 0;
}
