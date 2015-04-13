<?php
/*****************************************************************************
 * Site tele du Binet Reseau
 *****************************************************************************
 * Copyright (C) 2006 Binet RÃ©seau
 * $Id: ipc.php 914 2007-01-14 18:47:58Z vinz2 $
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

class IPC {
	var $socket = false;

	const IPC_BUFFER = 4096;
	const IPC_MAGIC = 0x76545242;
	const IPC_VERSION = 0x4;
	const IPC_TEXT_LENGTH = 2048;
	const IPC_URL_LENGTH = 32;
	const IPC_GROUP_LENGTH = 16;
	const IPC_MAX_PACKET_SIZE =3200;
	const IPC_IP_LENGTH = 20;

	const IPC_NOOP = 0;
	const IPC_URLLIST_GET = 4;
	const IPC_URLLIST = 5;
	const IPC_BWGROUP_GET = 6;
	const IPC_BWGROUP_LIST = 7;
	const IPC_CONNECTION_GET = 8;
	const IPC_CONNECTION_LIST = 9;

	function __construct ($file)
	{
		$this->socket = @socket_create(AF_UNIX, SOCK_STREAM, 0);
		if ($this->socket < 0)
		{
			$this->socket = false;
			return;
		}

		socket_set_nonblock ($this->socket);
		socket_set_option ($this->socket, SOL_SOCKET, SO_RCVBUF, self::IPC_BUFFER);
		socket_set_option ($this->socket, SOL_SOCKET, SO_RCVBUF, self::IPC_BUFFER);

		if (@socket_connect ($this->socket, $file) < 0)
		{
			socket_close ($this->socket);
			$this->socket = false;
			return;
		}
	}
	function close ()
	{
		if ($this->socket)
		{
			socket_close ($this->socket);
			$this->socket = false;
		}
	}

	function send_packet ($type, $payload)
	{
		if ($this->socket)
		{
			$header = pack("LCSC", self::IPC_MAGIC, self::IPC_VERSION, strlen($payload), $type);
			return @socket_send ($this->socket, $header . $payload, strlen($header) + strlen($payload), 0);
		}
		return false;
	}
	function get_packet ($timeout = 0)
	{
		$buffer = false;

		if (!$this->socket)
			return false;

		if (($result = socket_select($read = array($this->socket), $write = NULL, $except = NULL, $timeout)) > 0)
		{
			$read = socket_recv($this->socket, $buffer, 8, 0);

			if ($read > 0)
			{
				if (strlen($buffer) < 8)
	                        return false;

				$packet = unpack("Lmagic/Cversion/Slength/Ctype", $buffer);
				$read = socket_recv($this->socket, $buffer, $packet['length'], 0);
				if ($read > 0)
				{
					$packet['payload'] = $this->decode_payload($packet['type'], $buffer);
					return $packet;
				}
				socket_close ($this->socket);
				$this->socket = false;
			}
			else
			{
				socket_close ($this->socket);
				$this->socket = false;
			}
		}
		return false;
	}

	function decode_payload ($type, $payload)
	{
		switch ($type)
		{
			case self::IPC_NOOP:
				return false;
			case self::IPC_URLLIST_GET:
			case self::IPC_BWGROUP_GET:
			case self::IPC_CONNECTION_GET:
				return false;

			case self::IPC_URLLIST:
			case self::IPC_BWGROUP_LIST:
			case self::IPC_CONNECTION_LIST:
				switch ($type)
				{
					case self::IPC_URLLIST:
						$itemlen = 56;
						break;
					case self::IPC_BWGROUP_LIST:
						$itemlen = 32;
						break;
					case self::IPC_CONNECTION_LIST:
						$itemlen = 40;
						break;
				}

				if (strlen($payload) < 8)
					return false;

				$decoded = unpack("Lip/Clength", substr($payload, 0, 5));

				if (strlen($payload) != 8 + $decoded['length'] * $itemlen)
					return false;

				for ($i = 0; $i < $decoded['length']; $i ++)
				{
					$item = substr($payload, 8 + $itemlen * $i, $itemlen);
					switch ($type)
					{
						case self::IPC_URLLIST:
							$decoded[$i] = array_merge (
								array (
									'url'  => substr($item, 0, 32),
									'ip'   => substr($item, 32, 20),
								),
								unpack ("Sport", substr($item, 52, 2))
							);
							break;
						case self::IPC_BWGROUP_LIST:
							$decoded[$i] = unpack("Lmax_bw/Lalloc_bw/Lmax_channels/Lalloc_channels", substr($item, 16, 16));
							$decoded[$i]['name'] = substr($item, 0, 16);
							break;
						case self::IPC_CONNECTION_LIST:
							$decoded[$i] = array_merge (
								array (
									'url'  => substr($item, 0, 32),
								),
								unpack ("Nhost_ip/Lstart_time", substr($item, 32, 8))
							);
							break;
					}
				}
				return $decoded;
			default:
				return false;
		}
	}

	function encode_get_url ($ip)
	{
		$payload = pack("N", ip2long($ip));
		return $this->send_packet (self::IPC_URLLIST_GET, $payload);
	}
	function encode_get_bw ($ip)
	{
		$payload = pack("N", ip2long($ip));
		return $this->send_packet (self::IPC_BWGROUP_GET, $payload);
	}
	function encode_get_conn ()
	{
		$payload = pack("N", 0);
		return $this->send_packet (self::IPC_CONNECTION_GET, $payload);
	}


	function get_list_url ($ip)
	{
		if (!$this->encode_get_url($ip))
			return false;

		while (true)
		{
			$packet = $this->get_packet(1);
			if ($packet == false)
				return false;
			if ($packet['type'] != self::IPC_URLLIST)
				continue;

			$channels = array ();
			for ($i = 0; $i < $packet['payload']['length']; $i ++)
			{
				$channels[] = array (
					'url'  => self::dezeroize($packet['payload'][$i]['url']),
					'ip'   => self::dezeroize($packet['payload'][$i]['ip']),
					'port' => self::dezeroize($packet['payload'][$i]['port']),
				);
			}
			return $channels;
		}
		return false;
	}
	function get_list_bw ($ip)
	{
		if (!$this->encode_get_bw($ip))
			return false;

		while (true)
		{
			$packet = $this->get_packet(1);
			if ($packet == false)
				return false;
			if ($packet['type'] != self::IPC_BWGROUP_LIST)
				continue;

			$groups = array ();
			for ($i = 0; $i < $packet['payload']['length']; $i ++)
			{
				$groups[] = array (
					'name'           => self::dezeroize($packet['payload'][$i]['name']),
					'max_bw'         => $packet['payload'][$i]['max_bw'],
					'max_channels'   => $packet['payload'][$i]['max_channels'],
					'alloc_bw'       => $packet['payload'][$i]['alloc_bw'],
					'alloc_channels' => $packet['payload'][$i]['alloc_channels'],
				);
			}
			return $groups;
		}
		return false;
	}
	function get_list_conn ($ip)
	{
		if (!$this->encode_get_conn($ip))
			return false;

		while (true)
		{
			$packet = $this->get_packet(1);
			if ($packet == false)
				return false;
			if ($packet['type'] != self::IPC_CONNECTION_LIST)
				continue;

			$conns = array ();
			for ($i = 0; $i < $packet['payload']['length']; $i ++)
			{
				$conns[] = array (
					'url'        => self::dezeroize($packet['payload'][$i]['url']),
					'host_ip'    => long2ip($packet['payload'][$i]['host_ip']),
					'start_time' => $packet['payload'][$i]['start_time'],
				);
			}
			return $conns;
		}
		return false;
	}

	function dezeroize ($text)
	{
		$pos = strpos($text, "\0");
		if ($pos === false)
			return $text;
		else
			return substr($text, 0, $pos);
	}
}
