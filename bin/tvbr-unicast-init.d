#!/sbin/runscript

TVBR_UNICAST_LOGFILE_SERVER=/var/log/tvbr-unicast/server.log
TVBR_UNICAST_LOGFILE_CLIENT=/var/log/tvbr-unicast/client.log
TVBR_UNICAST_CONFIG_FILE=/home/tv/etc/unicast.conf

depend() {
	need net
}

checkconfig() {
	if [[ ! -f ${TVBR_UNICAST_CONFIG_FILE} ]] ; then
		eerror "Please create ${TVBR_UNICAST_CONFIG_FILE}."
		return 1
	fi
	return 0
}

start() {
	checkconfig || return 1
	ebegin "Starting tvbr-unicast"
	if [[ -f ${TVBR_UNICAST_LOGFILE_SERVER} ]] ; then
		/usr/sbin/savelog -p ${TVBR_UNICAST_LOGFILE_SERVER}
	fi
	if [[ -f ${TVBR_UNICAST_LOGFILE_CLIENT} ]] ; then
		/usr/sbin/savelog -p ${TVBR_UNICAST_LOGFILE_CLIENT}
	fi

	/sbin/logsave -s ${TVBR_UNICAST_LOGFILE_SERVER} /home/tv/bin/tvbr-unicast-server -v -d -c ${TVBR_UNICAST_CONFIG_FILE} >/dev/null &
	eend $?
}

stop() {
	ebegin "Stopping tvbr-unicast"
	start-stop-daemon --stop --quiet --retry 3 --exec /home/tv/bin/tvbr-unicast-server
	eend $?
}
