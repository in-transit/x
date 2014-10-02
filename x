#!/bin/bash

# x,v0.2

# This service runs in the background in conjuction with ossec. It will read
# alert messages that are pushed to a pipe from rsyslog and process them
# indivudally.

# Create the pipe to be used with this service
#
#	sudo mkdir /var/log/alerts/
#	sudo mkfifo /var/log/alerts/50-ossec-alert-messages.log
#	sudo chmod 600 /var/log/alerts/50-ossec-alert-messages.log
#	sudo chown syslog:adm /var/log/alerts/50-ossec-alert-messages.log

# An exmaple of an /etc/rsyslog.conf that works with this is located at http://in-transit.me/x-rsyslog-conf

function GetInput {

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

}

GetInput

