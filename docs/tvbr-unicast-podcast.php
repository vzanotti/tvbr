<?php
/*****************************************************************************
 * Site tele du Binet Reseau
 *****************************************************************************
 * Copyright (C) 2006 Binet Réseau
 * $Id: podcast.php 914 2007-01-14 18:47:58Z vinz2 $
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

/**
 *  Configuration
 */
include "../includes/config.php";

/**
 *  Allowed channels
 */
include "../includes/ipc.php";

$allowed_channels = array ();
if (isset($_SERVER['REMOTE_ADDR']))
{
	$ipc = new IPC ($ipc__socket);
	$channels = $ipc->get_list_url ($_SERVER['REMOTE_ADDR']);

	if (is_array($channels))
	{
		foreach ($channels as $c)
		{
			$allowed_channels[$c['ip'] . ':' . $c['port']] = $c['url'];
		}
	}

	unset($channels);
	$ipc->close ();
	unset ($ipc);
}

/**
 *  Channels
 */
include "../includes/sap.php";
$db = mysql_connect($mysql__host, $mysql__user, $mysql__pass);
if ($db && mysql_select_db ($mysql__base))
	$channels = sap::load_from_sql($db);
else
	$channels = sap::load_from_dump($config__sapdump);

/**
 *  Sorting
 */
usort($channels, create_function('$a, $b', 'return strnatcmp($a->get_name(), $b->get_name());'));

/**
 *  Output
 */
header("Content-Type: text/xml; charset=UTF-8");
echo '<?xml version="1.0" encoding="UTF-8" ?>' . "\n";
?>
<rss version="2.0" lang="fr">
	<channel>
		<title>La télé du BR</title>
		<link>http://tv.eleves.polytechnique.fr</link>
		<description>La télévision du Binet Réseau</description>
		<generator>tvbr-podcast</generator>
<?php
while (list(, $c) = each($channels))
{
	$ipport = $c->get_ip () . ':' . $c->get_port ();
	if (!isset($allowed_channels[$ipport]))
		continue;

	$uri = "http://129.104.201.54/stream/" . $allowed_channels[$ipport];
?>
		<item>
			<title><?php echo $c->get_name (); ?></title>
			<enclosure url="<?php echo $uri ?>" />
		</item>
<?php
}
?>
	</channel>
</rss>
