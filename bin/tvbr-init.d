#!/sbin/runscript

TVBR_LOGFILE=/var/log/tvbr.log
TVBR_CONFIG_DIR=/home/tv/etc

depend() {
	need net xorp
}

checkconfig() {
	if [[ ! -f ${TVBR_CONFIG_DIR}/channels.conf || ! -f ${TVBR_CONFIG_DIR}/streams.conf ]] ; then
		eerror "Please create ${TVBR_CONFIG_DIR}/channels.conf and ${TVBR_CONFIG_DIR}/streams.conf first."
		return 1
	fi
	return 0
}

start() {
	checkconfig || return 1
	ebegin "Starting tvbr"
	if [[ -f ${TVBR_LOGFILE} ]] ; then
		/usr/sbin/savelog -p ${TVBR_LOGFILE}
	fi

	/sbin/logsave -s ${TVBR_LOGFILE} /home/tv/bin/tvbr -v -d ${TVBR_CONFIG_DIR} `hostname` >/dev/null &
	eend $?
}

stop() {
	ebegin "Stopping tvbr"
	start-stop-daemon --stop --quiet --retry 10 --exec /home/tv/bin/tvbr
	eend $?
}
