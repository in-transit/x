#!/bin/bash

# x,v0.2

# http://github.com/in-transit/x

# This service runs in the background in conjuction with ossec. It will read
# alert messages that are pushed to a pipe from rsyslog and process them
# indivudally.

# Create the pipe to be used with this service
#
#		sudo mkdir /var/log/alerts/
#		sudo mkfifo /var/log/alerts/50-ossec-alert-messages.fifo
#		sudo chmod 600 /var/log/alerts/50-ossec-alert-messages.fifo
# (Kali)	sudo chown root:adm /var/log/alerts/50-ossec-alert-messages.fifo
# (Ubuntu)	sudo chown syslog:adm /var/log/alerts/50-ossec-alert-messages.fifo

# An exmaple of an /etc/rsyslog.conf that works with this is located at:
#	http://in-transit.me/x-rsyslog-conf

# To use this service direct a fifo pipe to x. Example:
#	user@server~$ x < /var/log/alerts/50-ossec-alert-messages.fifo

# Variables
# $Alert is the inputed line from the fifo pipe.
# $SrcIP is the src_ip key from $Alert.
# $DestIP is the dest_ip key from $Alert.
# $RuleID is the OSSEC rule key from $Alert.
# $ThreatID is a generated ID nubmer for the alert done in Unix time.
# $IsNet is the determination of it being a network related event.
# $line is the single line inputed from the fifo pipe.

# Functions
# fParseAlertString will gather $SrcIP, $DestIP, and $RuleID.
# fGenerateThreatID will generate $ThreatID.
# fIsNet will determine if the alert is network related by the presence of $SrcIP.


# START fParseAlertString function
function fParseAlertString {

SrcIP=$(echo $Alert | sed -e '/^.*src_ip\=\"//g' | sed -e '\"\,\ message//g')
DestIP=$(echo $Alert | sed -e '/^.*component.*\)\ //g' | sed -e '/\-\>.*//g')
RuleID=$(echo $Alert | sed -e '/^.*id\=//g' | sed -e '/\ description.*$//g')

# END fParseAlertString function
}

# START fGenerateThreatID function
function fGenerateThreatID {

ThreatID=$(date +%s)

# END fGenerateThreatID function
}

# START fIsNet function
function fIsNet {

while read line
do

  # Collect the alert message
  Alert=$(echo ${line})

  # BEGIN Test string for "src_ip"

  IsNet=$(echo $Alert | grep src_ip > /dev/null && echo 1 || echo 0)

  if [ $IsNet -eq 1 ]; then

    echo "It's Network."

  else

    echo "It's Not Network."

  fi

  # END Test string for "src_ip"

done

# END fGetInput function
}

GetInput

