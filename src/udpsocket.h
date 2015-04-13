/*****************************************************************************
 * socket.h :  UDP/Multicast socket helper
 *****************************************************************************
 * Copyright (C) 2006 Binet Réseau
 * $Id: udpsocket.h 817 2006-11-01 23:33:08Z vinz2 $
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

#ifndef _UDP_SOCKET_H
#define _UDP_SOCKET_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

int udpsocket_open  (in_addr_t, in_addr_t, unsigned short);
int udpsocket_ropen (in_addr_t, in_addr_t, unsigned short);
int udpsocket_wopen (in_addr_t, in_addr_t, unsigned short);
int udpsocket_connect (in_addr_t, unsigned short);
int udpsocket_close (int);
int udpsocket_addmc (int, in_addr_t, in_addr_t);
int udpsocket_setttl(int, int);

#endif  // _UDP_SOCKET_H
