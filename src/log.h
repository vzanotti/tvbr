/*****************************************************************************
 * log.h :  Logging helpers
 *****************************************************************************
 * Copyright (C) 2006 Binet Réseau
 * $Id: log.h 821 2006-11-04 01:19:02Z vinz2 $
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

#ifndef _LOG_H
#define _LOG_H

#include <stdarg.h>

void log_debug (const char *format, ...);
void log_info (const char *format, ...);
void log_warn (const char *format, ...);
void log_error (const char *format, ...);

#endif
