#!/bin/bash

# x,v0.2.2

# http://github.com/in-transit/x

# This service runs in the background in conjuction with ossec. It will read
# alert messages that are pushed to a pipe from rsyslog and process them
# indivudally. OSSEC will need to push the log to the syslog server as type
# splunk.

# Example: You can prepend this following lines to the ossec.conf file.
#  <syslog_output>
#    <server>localhost</server>
#    <port>514</port>
#    <format>splunk</format>
#  </syslog_output>

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
# $IsInDataBase determines if the block has already happened by x.
# $SrcIsPublic will find if $SrcIP is private or public (RFC 1918)
# $DestIsPublic will find if $DestIP is private or public (RFC 1918)

# Functions
# fHOUSEKEEPING will reset all variables to prevent subsequent flase executions.
# fParseAlertString will gather $SrcIP, $DestIP, and $RuleID.
# fGenerateThreatID will generate $ThreatID.
# fIsNet will determine if the alert is network related by the presence of src_ip.
# fIsInDataBase determines if the block has already happened by x.
# fSrcIsPublic will find if $SrcIP is private or public (RFC 1918)
# fDestIsPublic will find if $DestIP is private or public (RFC 1918)

# TO BE DONE:
# 1. fAttackDetermination will call to a pending attack function which will
#    increment the log item then proceed with a determination to attack.

# START HOUSEKEEPING
function fHOUSEKEEPING {

  Alert=""
  SrcIP=""
  DestIP=""
  RuleID=""
  ThreatID=""
  IsNet=""
  line=""
  IsInDataBase=""
  SrcIsPublic=""
  DestIsPublic=""
  AttackLevel=""
  SrcZone=""
  DestZone=""
  AttackLevel=""

}

# END HOUSEKEEPING

# START fParseAlertString function
function fParseAlertString {

  SrcIP=$(echo $Alert | sed -e 's/^.*src_ip\=\"//g' | sed -e 's/\"\,\ message.*$//g')
  DestIP=$(echo $Alert | sed -e 's/^.*component.*)\ //g' | sed -e 's/->.*$//g')
  RuleID=$(echo $Alert | sed -e 's/^.*id=//g' | sed -e 's/\ description.*$//g')
  echo "SrcIP:" $SrcIP
  echo "DestIP:" $DestIP
  echo "RuleID:" $RuleID

# END fParseAlertString function
}

# START fIsInDataBase function
function fIsInDataBase {

  IsInDataBase=$(grep -e "$SrcIP,$DestIP," threat.db > /dev/null && echo 1 || echo 0)
  echo "IsInDataBase:" $IsInDataBase

# END fIsInDatabase function
}

# START fGenerateThreatID function
function fGenerateThreatID {

  ThreatID=$(date +%s)
  echo "ThreatID:" $ThreatID

# END fGenerateThreatID function
}

# START fIsNet function
function fIsNet {

  Alert=$(echo ${line})
  echo "Alert:" $Alert

  IsNet=$(echo $Alert | grep src_ip > /dev/null && echo 1 || echo 0)
  echo "IsNet:" $IsNet

# END fIsNet function
}

# START fSrcIsPublic function
function fSrcIsPublic {

  SrcIsPublic=$(echo $SrcIP | sed -e '/10\./d' | sed -e '/192\.168\./d' | sed -e '/172\.1[6-9]\./d' | sed -e '/172\.2[0-9]\./d' | sed -e '/172\.3[0-1]\./d' | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' > /dev/null && echo 1 || echo 0)
  echo "SrcIsPublic:" $SrcIsPublic

# END fSrcIsPublic function
}

# START fDestIsPublic function
function fDestIsPublic {

  DestIsPublic=$(echo $DestIP | sed -e '/10\./d' | sed -e '/192\.168\./d' | sed -e '/172\.1[6-9]\./d' | sed -e '/172\.2[0-9]\./d' | sed -e '/172\.3[0-1]\./d' | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' > /dev/null && echo 1 || echo 0)
  echo "DestIsPublic:" $DestIsPublic

# END fDestIsPublic function
}

# START fZone function
function fZone {

  if [ $SrcIsPublic -eq 1 ]; then

    SrcZone="Public"
    echo "SrcZone:" $SrcZone

  elif [ $SrcIsPublic -eq 0 ]; then

    SrcZone="Not Public"
    echo "SrcZone:" $SrcZone

  fi

  if [ $DestIsPublic -eq 1 ]; then

    DestZone="Public"
    echo "DestZone:" $DestZone

  elif [ $DestIsPublic -eq 0 ]; then

    DestZone="Not Public"
    echo "DestZone:" $DestZone

  fi
# END fZone function
}


# START fAttackLevel function
function fAttackLevel {

  if [ $SrcIsPublic -eq 1 -a $DestIsPublic -eq 0 ]; then

    AttackLevel=4
    echo "AttackLevel:" $AttackLevel

  elif [ $SrcIsPublic -eq 1 -a $DestIsPublic -eq 1 ]; then

    AttackLevel=3
    echo "AttackLevel:" $AttackLevel

  elif [ $SrcIsPublic -eq 0 -a $DestIsPublic -eq 1 ]; then

    AttackLevel=2
    echo "AttackLevel:" $AttackLevel

  elif [ $SrcIsPublic -eq 0 -a $DestIsPublic -eq 0 ]; then

    AttackLevel=1
    echo "AttackLevel:" $AttackLevel

  fi

# END fAttackLevel function
}

# START fPendingAttack function
function fPendingAttack {

# END fPendingAttack function
}

# START fAttackDetermination function
function fAttackDetermination {

  if [ $AttackLevel -eq 4 ]; then

    AttackNow=1

  elif [ $AttackLevel -eq 3 ]; then

    AttackNow=0

  elif [ $AttackLevel -eq 2 ]; then

    AttackNow=0

  elif [ $AttackLevel -eq 1 ]; then

    AttackNow=0

  fi

# END fAttackDetermination function
}

# START fAttack function
function fAttack {

  fGenerateThreatID

  # object network Threat-123456789-Src
  #  host 8.8.8.8
  #  description Generated at Wed Oct  8 11:49:29 EDT 2014 by x ThreatID: 123456789

  # object-group network ThreatObjects
  #  network-object object Threat-123456789-Src

# END fAttack function
}

# BEGIN RUN LIST

while read line

do

  fIsNet

  if [ $IsNet -eq 1 ]; then

    fParseAlertString
    fIsInDataBase

    if [ $IsInDataBase -eq 0 ]; then

      fSrcIsPublic
      fDestIsPublic
      fZone
      fAttackLevel
      fAttackDetermination

      if [ $AttackNow -eq 1 ]; then

        fAttack

      fi

    fi

  fi

  fHOUSEKEEPING

# END RUN LIST

done
