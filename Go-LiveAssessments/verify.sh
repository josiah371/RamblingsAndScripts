#!/bin/bash
#
# The MIT License (MIT)
# Copyright (c) 2016 Josiah371 (outofc0ntr0l), Scott Mountjoy
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and 
# associated documentation files (the "Software"), to deal in the Software without restriction, 
# including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
# and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, 
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
# LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# Version 0.4
# Written by: Josiah Inman, Scott Mountjoy
#
# Check to see if script is being ran as root
# Note: Using "old" method for detecting user, instead of EUID, for compatibility

# Tested on CentOS VM v. 6.7 and 7.2, Debian VM v 8, and Kali Rolling-Release

#ANSI Colors
CESC='\033[' #Escape Sequence

#Forecolor
BLACK="${CESC}0;30m"
RED="${CESC}0;31m"
GREEN="${CESC}0;32m"
ORANGE="${CESC}0;33m"
BLUE="${CESC}0;34m"
PURPLE="${CESC}0;35m"
CYAN="${CESC}0;36m"
LTGRAY="${CESC}0;37m"
GRAY="${CESC}1;30m"
PINK="${CESC}0;31m"
LTGREEN="${CESC}1;32m"
YELLOW="${CESC}1;33m"
LTBLUE="${CESC}1;34m"
LTPURPLE="${CESC}1;35m"
LTCYAN="${CESC}1;36m"
WHITE="${CESC}1;37m"

#No F/B color
NC="${CESC}0m"
BOLD="${CESC}1m"

#Background Color
BLACK_BACK="${CESC}0;40m"
RED_BACK="${CESC}0;41m"
GREEN_BACK="${CESC}0;42m"
ORANGE_BACK="${CESC}0;43m"
BLUE_BACK="${CESC}0;44m"
PURPLE_BACK="${CESC}0;45m"
CYAN_BACK="${CESC}0;46m"
LTGRAY_BACK="${CESC}0;47m"
GRAY_BACK="${CESC}1;40m"
PINK_BACK="${CESC}0;41m"
LTGREEN_BACK="${CESC}1;42m"
YELLOW_BACK="${CESC}1;43m"
LTBLUE_BACK="${CESC}1;44m"
LTPURPLE_BACK="${CESC}1;45m"
LTCYAN_BACK="${CESC}1;46m"
WHITE_BACK="${CESC}1;47m"

#\033 is the ANSI escape sequence
#[?7h sets auto-wrap mode on VT100/VT52
#[255D moves the cursor 255 spaces backward - essentially setting it fully to the left
RHEL="\033[?7h\033[255D|                                                                                       |
|${WHITE}          ++++++++                                    ${RED}###  ${WHITE}##${NC}                          |
|${WHITE}      ++${GRAY}*${RED}### ${GRAY}*${RED}###${WHITE}++++                                 ${RED}###  ${WHITE}##${NC}                          |
|${WHITE}    ++++${RED}#${GRAY}*${RED}####${GRAY}*${RED}###${WHITE}+++++                               ${RED}###  ${WHITE}##                    ##${NC}    |
|${WHITE}   ++++${RED}####${GRAY}*${RED}###${GRAY}*${RED}##${WHITE}++++++                              ${RED}###  ${WHITE}##                    ##${NC}    |
|${WHITE}  ++${RED}###${GRAY}*${RED}###########${WHITE}++++++   ${RED}### ###   ######     ########  ${WHITE}## ####     ######  ######${NC}  |
|${WHITE}  +${RED}####${GRAY}***${RED}#########${WHITE}++++++   ${RED}#######  ###  ###   ###  ####  ${WHITE}####  ##   ##    ##   ##${NC}    |
|${WHITE}  ++${RED}#####${GRAY}****${RED}####${GRAY}**${RED}##${WHITE}++++   ${RED}####    ###    ### ###    ###  ${WHITE}###    ##        ##   ##${NC}    |
|${WHITE}  +++${RED}########${GRAY}****${RED}#####${WHITE}+++   ${RED}###     ########## ###    ###  ${WHITE}##     ##   #######   ##${NC}    |
|${WHITE}   ++++${RED}###############${WHITE}++    ${RED}###     ###        ###    ###  ${WHITE}##     ##  ##    ##   ##${NC}    |
|${WHITE}    +++++${RED}############${WHITE}++     ${RED}###     ###        ###    ###  ${WHITE}##     ##  ##    ##   ##${NC}    |
|${WHITE}      ++++++${RED}########${WHITE}+       ${RED}###     ####   ### ####  ####  ${WHITE}##     ##  ##   ###   ##${NC}    |
|${WHITE}          ++++++++          ${RED}###      ########   ###### ##  ${WHITE}##     ##   ##### ##  ###${NC}   |
|                                                                                       |"

DEBL="\033[?7h\033[255D|                                                                                       |
|             ${RED}###                                           #                           ${NC}|
|          ${RED}#########              ${LTGRAY}###          ###         ${RED}###                          ${NC}|
|        ${RED}###### ######            ${LTGRAY}##            ##          ${RED}#                           ${NC}|
|       ${RED}####       ####           ${LTGRAY}##            ##                                      ${NC}|
|      ${RED}####   ###   ###      ${LTGRAY}#### ##   ######   ## #####  ####  ######  ### #####       ${NC}|
|      ${RED}###   ##  #  ###     ${LTGRAY}##   ###  ###  ###  ###   ###  ##  ##    ##  ####  ###      ${NC}|
|      ${RED}###   ###   ###     ${LTGRAY}##     ##  ##    ##  ##     ##  ##        ##  ###    ##      ${NC}|
|       ${RED}###   ######       ${LTGRAY}##     ##  ########  ##     ##  ##   #######  ##     ##      ${NC}|
|        ${RED}###               ${LTGRAY}##     ##  ##        ##     ##  ##  ##    ##  ##     ##      ${NC}|
|         ${RED}###              ${LTGRAY}##     ##  ##        ##     ##  ##  ##    ##  ##     ##      ${NC}|
|           ${RED}####           ${LTGRAY}##    ###  ###   ##  ###   ##   ##  ##   ###  ##     ##      ${NC}|
|              ${RED}###          ${LTGRAY}##### ###  ######    ######   ####  ##### ## ##     ##      ${NC}|
|                                                                                       |"

MOTD="This information system, its associated sub-systems, and the content contained within are CONFIDENTIAL and PROPRIETARY INFORMATION, and remain the sole and exclusive property of this company. This information system may be accessed and used by authorized personnel only. Authorized users may only perform authorized activities and may not exceed the limits of such authorization. Use and/or disclosure of information contained in this information system for any unauthorized use is *STRICTLY PROHIBITED*. All activities on this information system are subject to monitoring, recording, and review at any time. Users should assume no expectation of privacy. Intentional misuse of this information system may result in disciplinary or legal action taken by this company. Continued use of this information system represents that you are an authorized user and agree to the terms stated in this warning."

printPassed() {
	printf "${GREEN}PASSED${NC}\n" | tee -a $outFile
}

printPassedExplanation() {
	printf "${GREEN}PASSED${NC} (%s)\n" "$1" | tee -a $outFile
}

printFailed() {
	if [ $# -gt 0 ]; then
		printf "${RED}FAILED${NC} (Should be %s)\n" $1 | tee -a $outFile
	else
		printf "${RED}FAILED${NC}\n" | tee -a $outFile
	fi
}

printFailedExplanation() {
	printf "${RED}FAILED${NC} (%s)\n" "$1" | tee -a $outFile
}

printSecHead() {
	printf "\n${CYAN}${1}${NC}\n" | tee -a $outFile
}

printCFGFileHead() {
	printf "\n${PURPLE} ${1}${NC}\n" | tee -a $outFile
}

printPF() {
	# $1='=', $2=Title, $3=Tested value, $4=Desired Value
	# $1=Title, $2=Tested value, $3=Desired Value
	# if $4/$3 is blank or nonexistant, then Tested Value was empty.

	if [[ ${1} == '=' ]]; then
		[[ $# -lt 4 ]] && set -$- "${2}" "(unset}" "${3}" || shift
		printf "  ${1} == ${2} ... " | tee -a $outFile
	else
		[[ $# -lt 3 ]] && set -$- "${1}" "(unset)" "${2}"
		printf "  ${1} ${2} ... " | tee -a $outFile
	fi
	
	[[ ${2} != ${3} ]] && printFailed ${3} || printPassed
}

printPF_NotEmpty() {
	printf "  ${1} ... " | tee -a $outFile
	[[ ${#2} -gt 0 ]] && printPassed || printFailed
}

printPF_Empty() {
	printf "  ${1} ... " | tee -a $outFile
	[[ ${#2} -eq 0 ]] && printPassed || printFailed
}

checkPerms() {
	stat=$(stat -c "%a %n" $1 | awk -F' ' '{print$1}')
	local ret=$(printf "%04d" "${stat}")
	echo ${ret}
}

fileCheck() {
	printSecHead "Checking permissions on sensitive files:"

	printPF '=' "/etc/shadow" $(checkPerms /etc/shadow) "0000"
	printPF '=' "/etc/gshadow" $(checkPerms /etc/gshadow) "0000"
	printPF '=' "/etc/passwd" $(checkPerms /etc/passwd) "0644"
	printPF '=' "/etc/group" $(checkPerms /etc/group) "0644"
	
}

kernelChecks() {
	printSecHead "Checking Memory Protection:"
	
	printCFGFileHead "sysctl"
	printPF '=' "kernel.randomize_va_space (ASLR)" $(sysctl kernel.randomize_va_space | awk -F' ' '{print $NF}') "2"

	[[ ${OS_VER} -ge 7 ]] && \
		printf "  EXECShield is built in to RHE 7...${GREEN}PASSED${NC}\n"  | tee -a $outFile || \
		printPF "kernel.exec-shield (EXECShield)=" $(sysctl kernel.exec-shield 2>/dev/null | awk '{print $NF}') "1"


	printSecHead "Checking Kernel Network Config:"
	printCFGFileHead "sysctl"
	printPF '=' "net.ipv4.ip_forward" $(sysctl net.ipv4.ip_forward | awk -F' ' '{print $NF}') "0"
	printPF '=' "net.ipv4.conf.all.send_redirects" $(sysctl net.ipv4.conf.all.send_redirects | awk -F' ' '{print $NF}') "0"
	printPF '=' "net.ipv4.conf.default.send_redirects" $(sysctl net.ipv4.conf.default.send_redirects | awk -F' ' '{print $NF}') "0"
	printPF '=' "net.ipv4.conf.all.accept_redirects" $(sysctl net.ipv4.conf.all.accept_redirects | awk -F' ' '{print $NF}') "0"
	printPF '=' "net.ipv4.conf.default.accept_redirects" $(sysctl net.ipv4.conf.all.accept_redirects | awk -F' ' '{print $NF}') "0"
	printPF '=' "net.ipv4.icmp_echo_ignore_broadcasts" $(sysctl net.ipv4.icmp_echo_ignore_broadcasts | awk -F' ' '{print $NF}') "1"
	printPF '=' "net.ipv4.icmp_ignore_bogus_error_responses" $(sysctl net.ipv4.icmp_ignore_bogus_error_responses | awk -F' ' '{print $NF}') "1"
	printPF '=' "net.ipv4.tcp_syncookies" $(sysctl net.ipv4.tcp_syncookies | awk -F' ' '{print $NF}') "1"
	printPF '=' "net.ipv4.conf.all.log_martians" $(sysctl net.ipv4.conf.all.log_martians | awk -F' ' '{print $NF}') "1"
	printPF '=' "net.ipv4.conf.default.log_martians" $(sysctl net.ipv4.conf.default.log_martians | awk -F' ' '{print $NF}') "1"
	printPF '=' "net.ipv4.conf.all.accept_source_route" $(sysctl net.ipv4.conf.all.accept_source_route | awk -F' ' '{print $NF}') "0"
	printPF '=' "net.ipv4.conf.default.accept_source_route" $(sysctl net.ipv4.conf.default.accept_source_route | awk -F' ' '{print $NF}') "0"
	printPF '=' "net.ipv4.conf.all.rp_filter" $(sysctl net.ipv4.conf.all.rp_filter | awk -F' ' '{print $NF}') "1"
	printPF '=' "net.ipv4.conf.default.rp_filter" $(sysctl net.ipv4.conf.default.rp_filter | awk -F' ' '{print $NF}') "1"
	printPF '=' "net.ipv6.conf.default.accept_redirects" $(sysctl net.ipv6.conf.default.accept_redirects | awk -F' ' '{print $NF}') "0"
	printPF '=' "net.ipv4.conf.all.secure_redirects" $(sysctl net.ipv4.conf.all.secure_redirects | awk -F' ' '{print $NF}') "0"
	printPF '=' "net.ipv4.conf.default.secure_redirects" $(sysctl net.ipv4.conf.default.secure_redirects | awk -F' ' '{print $NF}') "0"
	printPF '=' "net.ipv6.conf.all.disable_ipv6" $(sysctl net.ipv6.conf.all.disable_ipv6 | awk -F' ' '{print $NF}') "1"
	printPF '=' "net.ipv6.conf.default.disable_ipv6" $(sysctl net.ipv6.conf.default.disable_ipv6 | awk -F' ' '{print $NF}') "1"


}

checkFW() {
	printSecHead "Checking Firewall:"
	
	if [[ ${OS_VER} -ge 7 && ${OS} = "RHE" ]]; then
		printPF "FirewallD status" $(getService "firewalld") "running"
		printCFGFileHead "firewall-cmd"
		printPF '=' "Default Zone" $(firewall-cmd --get-default-zone) "drop"
	else	
		printf "  IPTables " | tee -a $outFile
		#IPT is funky, and getService won't return correctly
		iptstat=$(service iptables status 2>/dev/null | grep -v "not running")
		[[ ${#iptstat} -gt 0 ]] && printf "(running)...${GREEN}PASSED${NC}\n"  | tee -a $outFile || printf "(dead)...${RED}FAILED${NC}\n" | tee -a $outFile
		
		printCFGFileHead "iptables -L INPUT"
		printPF '=' "Default INPUT policy" $(iptables -L INPUT | head -1 | awk -F'[ )]' '{print $4}') "DROP"
	fi
}

# Test for root access
testRoot() {
	if [ "$(id -u)" != "0" ]; then
		echo "This script must be run as root (with the use of sudo)" 1>&2
		exit 1
	fi
}

# 2.1.2.2.2 Syncing Network Time
checktime() {
	printSecHead "Checking Network Time Config (2.1.2.2.2):"
	
	printPF '=' "Time Zone" $(date | awk '{print $5}') "UTC"
	if [[ ${OS_VER} -ge 7 ]]; then
		which chronyc >/dev/null	
		if [ $? -eq 0 ]; then
			ntpstat=$( getService "chrony*" )			
			valChrony ${ntpstat}
		else
			ntpstat=$( getService "ntpd" )
			valNTP ${ntpstat}
		fi
	else
		ntpstat=$( getService "ntpd" )
		valNTP ${ntpstat}
	fi
}

valChrony() {
	chronstat=$1
	printf "  Using Chrony..." | tee -a $outFile
	[[ ${chronstat} == "running" ]] && printPassed || { printFailed; return 1; }
	
	
	printf "  Chrony using time.catholichealth.net..." | tee -a $outFile

	if [[ -f /etc/chrony.conf ]]; then	
		ser=$(grep -i catholichealth /etc/chrony.conf)
	elif [[ -f /etc/chrony/chrony.conf ]]; then
		ser=$(grep -i catholichealth /etc/chrony/chrony.conf)
	else
		printFailed;
		return 1;
	fi
	[[ ${#ser} > 0 ]] && printPassed || { printFailed; return 1; }
	
	ntphost=$(getent hosts time.catholichealth.net | sed 's/\([0-9\.]*\).*/\1/')
	chrsync=$(chronyc tracking | grep Reference | awk -F' ' '{print $4}')
	printf "  Checking if Chrony is communicating with time.catholichealth.net..." | tee -a $outFile
	[[ ${ntphost}=${chrsync} ]] && printPassed || printFailed
}

valNTP() {
	printPF '=' "NTP Stauts" $1 "running"
	
	ser=$(grep -i catholichealth /etc/ntp.conf)
	printf "  NTP using time.catholichealth.net..." | tee -a $outFile
	[[ ${#ser} > 0 ]] && printPassed || { printFailed; return 1; }

	ntphost=$(getent hosts time.catholichealth.net | sed 's/\([0-9\.]*\).*/\1/')
	ntpdRunning=$(ntpq -p 2>/dev/null | grep ${ntphost})
	printf "  Checking if NTPD is communicating with time.catholichealth.net..." | tee -a $outFile
	[[ ${#ntpdRunning} > 0 ]] && printPassed || printFailed
}

# Password complexity requirements
checkMinClass() {
		minclass=$(echo ${upper} | sed 's/.*\(minclass\=[0-9]\).*/\1/' | sed 's/[^0-9]//g')
	
		printf "  minclass == ${minclass}..." | tee -a $outFile
		if [[ ${minclass} -eq 3 ]]; then
			printPassed
		else
			printFailed 3
		fi
}

checkPW() {
	printSecHead "Checking Password rules (2.1.2.4.3):"
	
	printCFGFileHead "/etc/login.defs"
	printPF '=' "Password minimum length" $(grep ^PASS_MIN_LEN /etc/login.defs | sed 's/[^0-9]//g') 10	
	printPF '=' "Minimum days between changes" $(grep ^PASS_MIN_DAYS /etc/login.defs | sed 's/[^0-9]//g') 5
	printPF '=' "Maximum passwd age" $(grep ^PASS_MAX_DAYS /etc/login.defs | sed 's/[^0-9]//g') 90
	printPF '=' "Password change warning" $(grep ^PASS_WARN_AGE /etc/login.defs | sed 's/[^0-9]//g') 14
	
	login=$(grep 'ENCRYPT_METHOD SHA512' /etc/login.defs)
	printf "  login.defs contains 'ENCRYPT_METHOD SHA512' ... " | tee -a $outFile
	if [[ -z ${login} ]]; then
		printFailed "sha512"
	else
		printPassed
	fi

	[[ -f /etc/pam.d/common-password ]] && \
		printCFGFileHead "/etc/pam.d/common-password" || \
		printCFGFileHead "/etc/pam.d/[system|password]-auth{-ac|-local}"
		
	if [[ ${OS_ROOT} = "RHE" ]]; then
		if [[ ${OS_VER} -ge 7 ]]; then
			upper=$(authconfig --test | grep pam_pwquality)
			checkMinClass
		else		
			upper=$(authconfig --test | grep pam_cracklib)
		fi
	else
		upper=$(grep pwquality /etc/pam.d/common-password)
		checkMinClass
	fi

	# This looks messy, but stay with me -
	# First, define the two functions to print PASSED or FAILED, since we can't call those functions from within an AWK script.
	#
	# Second, set the field separator to a Space, and set a few bool variables to determine if each of the 4 required parameters are present
	# 	- recall that the settings for pwquality/cracklib are *all on one line!*, so the variable $upper will look like this:
	#	"pam_cracklib is enabled (try_first_pass retry=3 difok=3 ucredit=-1 lcredit=-1 ocredit=-1 type=)"
	#
	# Third, loop through each field split by awk (ignoring extra fields like retry or type). difok should be 3, so it gets it's own case. 
	#	The 3 '.+cred' parameters should all be -1, so they are in a chunk. For all 4 (difok + creds) parameters, if awk finds 
	#	the parameter set, then set the "bool" variable to true.
	#
	# Fourth, after testing all the fields in the for-loop, print off any that are missing entirely (based on the bool values)
	#
	#	Note: Remember that '~/[pattern]/' is a regex comparison operator, so "if ($i~/credit/)" will match ucredit, ocredit, lcredit, 
	#		and any other field with 'credit' in it.
	
	echo ${upper} | awk '\
		function Passed() { printf "\033[0;32mPASSED\033[0m\n" }
		function Failed(needed) { printf "\033[0;31mFAILED\033[0m (Should be %s)\n", needed }
		BEGIN {FS=" "; uc=0; oc=0; lc=0; dif=0};
		 { 
			for(i=1; i <= NF; i++)
		 	{
				if ( $i~/difok/ ) { dif=1; {gsub(/=/, " == ", $i); printf "  %s ... ",$i} if ( $i~/3/) { Passed() } else { Failed("3") } }
				else if ( $i~/credit/ ) {
					cred=substr($i,0,1);
					if(cred=="u") {uc=1}
					else if(cred=="o") {oc=1}
					else if(cred=="l") {lc=1}
					{gsub(/=/, " == ", $i); printf "  %s ... ", $i} if ($i~/-1/) { Passed() } else { Failed("-1") }
				}
				else { } 
			}
			if(dif==0) {printf "  difok unset..."; Failed("3");}
		  	if(uc==0) {printf "  ucredit unset..."; Failed("-1");}
			if(oc==0) {printf "  ocredit unset..."; Failed("-1");}
			if(lc==0) {printf "  lcredit unset..."; Failed("-1");}
		 }' | tee -a $outFile

	[[ ${OS_ROOT} = "RHE" ]] && \
		printPF '=' "Hashing algorithm" $(authconfig --test | grep hashing | awk -F' ' '{print $NF}') "sha512" || \
		printPF_NotEmpty "Hashing algorithm (should be SHA512)" $( grep sha512 /etc/pam.d/common-password | grep -v '#' )

	[[ -f /etc/pam.d/common-auth ]] && \
		printCFGFileHead "/etc/pam.d/common-auth" || \
		printCFGFileHead "/etc/pam.d/[system|password]-auth"
	#These are checking all 4 values, but will only display one to the user
	fl_unlock=$(grep 'pam_faillock\|pam_tally2' /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-auth 2>/dev/null | grep -no 'unlock_time=[^"]*' | awk -F'=| ' '{print $2}' | uniq -u)
	printf "  unlock_time == unset or 604800 ... "
	ulVal=${fl_unlock}
	if [ ${#ulVal[@]} -gt 1 ]; then
		printFailedExplanation "Multiple settings across PAM files"
	else
		if [ ${#ulVal} -lt 1 ]; then
			fl_unlock=$(grep 'pam_faillock\|pam_tally2' /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-auth 2>/dev/null | grep -no 'unlock_time=[^"]*' | awk -F'=| ' '{print $2}' | uniq -d)
			ulVal=${fl_unlock}
		fi
		if [ ${#ulVal} -lt 1 ]; then
			printPassedExplanation "Unset"
		elif [ ${ulVal} == "604800" ]; then
			printPassedExplanation "604800"
		else
			printFailed
		fi
	fi
	
	# printPF '=' "unlock_time" $(echo ${fl_unlock} | awk '{print}') "604800"
	

	# This is a funky case. If system-auth and password-auth are set correctly, $fl_deny will have 4 lines, each with nothing but '6' on it.
	# If *any one of those 4 lines* is not '6', the config failes.
	# So we use grep -v to remove all lines that are '6' - then test to see if there is anything left. If true (there is something left),
	# the config fails. If false (nothing left), then the config had all 6's and passes. Inverse logic.
	fl_deny=$(grep 'pam_faillock\|pam_tally2' /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-auth 2>/dev/null | grep -no 'deny=[^"]*' | awk -F'=| ' '{print $2}')
	printf "  deny == $(echo ${fl_deny} | awk -F' ' '{print $1}') ... " | tee -a $outFile
	[[ $(echo ${fl_deny} | grep -v 6) ]] && printFailed "6" || printPassed

	# Same funky inverse logic as "deny"
	[[ -f /etc/pam.d/common-auth ]] && printf "  ${GRAY}fail_interval is not compatible with pam_tally2${NC}\n"  | tee -a ${outFile}|| {
		fl_int=$(grep pam_faillock /etc/pam.d/system-auth /etc/pam.d/password-auth | grep -no 'fail_interval=[^"]*' | awk -F'=| ' '{print $2}');
		printf "  fail_interval == $(echo ${fl_int} | awk -F' ' '{print $1}') ... " | tee -a ${outFile};
		[[ $(echo ${fl_int} | grep -v 900) ]] && printFailed "900" || printPassed
	}


	printCFGFileHead "/etc/passwd"
	nonshdw=$(awk -F: '{if($2 != "x") print $1}' </etc/passwd)
	printf "  All passwords stored in /etc/shadow ... " | tee -a -a $outFile
	if [ -z ${nonshdw} ]; then
		printPassed
	else
		printFailed
		printf "!!${nonshdw} has a password that isn't in Shadow\n" | tee -a -a $outFile
	fi
}

checkRoot() {
	printSecHead "Checking Root UID and ownership:"
	printPF '=' "UID 0 user" $(awk -F : '($3==0) {print $1}' /etc/passwd) "root"
	printPF "/etc/shadow owned by" $(ls -l /etc/shadow | awk 'BEGIN { FS = " " } ; {print $3}') "root"
	printPF "/etc/passwd owned by" $(ls -l /etc/passwd | awk 'BEGIN { FS = " " } ; {print $3}') "root"
}

checkMOTD() {
	printSecHead "Checking MOTD:"
#-- Need to check /etc/ssh/sshd-banner as well, for REH
	motd=$(cat /etc/issue)
	width=70
	
	printf "  MOTD set to Standard..." | tee -a -a $outFile
	if [ ${#motd} -eq 0 ]; then
		printFailed " MOTD"
	else
		if [[ -f /etc/issue ]]; then
			printf "\n    ${ORANGE}Existing MOTD ${PURPLE}(/etc/issue)${NC}:\n" | tee -a -a $outFile		
		
			printVSeparator ${width}
			while read -r line; do
				# Resolve MOTD switches
				[[ ${OS_VER} -ge 7 ]] && line=${line//\\S/$(hostnamectl | grep "Operating" | sed 's/.*Operating System:\s*//g')}
				line=${line//\\r/$(uname -r)}
				line=${line//\\m/$(uname -i)}
				line=${line//\\l/$( ps ax | grep $$ | awk '{ print $2 }' | head -1 )}
				line=${line//\\n/$(hostname)}
				
				padding=$((${width}-${#line}))
				printf "\t| ${YELLOW}${line}${NC}" | tee -a -a $outFile
				printf '%*s|\n' ${padding} | tee -a $outFile
			done < "/etc/issue"
			printVSeparator ${width}
			echo ""
		fi
		
		if [[ -f /etc/motd ]]; then
			printf "\n    ${ORANGE}Existing MOTD ${PURPLE}(/etc/motd)${NC}:\n" | tee -a $outFile
		
			printVSeparator ${width}
			while read -r line; do
				# Resolve MOTD switches
				[[ ${OS_VER} -ge 7 ]] && line=${line//\\S/$(hostnamectl | grep "Operating" | sed 's/.*Operating System:\s*//g')}
				line=${line//\\r/$(uname -r)}
				line=${line//\\m/$(uname -i)}
				
				padding=$((${width}-${#line}))
				printf "\t| ${YELLOW}${line}${NC}" | tee -a $outFile
				printf '%*s|\n' ${padding} | tee -a $outFile
			done < "/etc/motd"
			printVSeparator ${width}
		fi
		
		if [[ -f /etc/issue.net ]]; then
			printf "\n    ${ORANGE}Existing Remote MOTD ${PURPLE}(/etc/issue.net)${NC}:\n" | tee -a $outFile
		
			printVSeparator ${width}
			while read -r line; do
				# Resolve MOTD switches
				[[ ${OS_VER} -ge 7 ]] && line=${line//\\S/$(hostnamectl | grep "Operating" | sed 's/.*Operating System:\s*//g')}
				line=${line//\\r/$(uname -r)}
				line=${line//\\m/$(uname -i)}
				
				padding=$((${width}-${#line}))
				printf "\t| ${YELLOW}${line}${NC}" | tee -a $outFile
				printf '%*s|\n' ${padding} | tee -a $outFile
			done < "/etc/issue.net"
			printVSeparator ${width}
		fi			
		
		if [[ -f /etc/ssh/sshd-banner ]]; then
			printf "\n    ${ORANGE}Existing SSH MOTD ${PURPLE}(/etc/ssh/sshd-banner)${NC}:\n" | tee -a $outFile
		
			printVSeparator ${width}
			while read -r line; do
				# Resolve MOTD switches
				[[ ${OS_VER} -ge 7 ]] && line=${line//\\S/$(hostnamectl | grep "Operating" | sed 's/.*Operating System:\s*//g')}
				line=${line//\\r/$(uname -r)}
				line=${line//\\m/$(uname -i)}
				
				padding=$((${width}-${#line}))
				printf "\t| ${YELLOW}${line}${NC}" | tee -a $outFile
				printf '%*s|\n' ${padding} | tee -a $outFile
			done < "/etc/ssh/sshd-banner"
			printVSeparator ${width}
		fi			
		
		echo ""
		
		printf "    standard MOTD ${PURPLE}(TCS 100)${NC}:\n" | tee -a $outFile
		i=0
		
		
		printVSeparator ${width}
		
		echo ${MOTD} | fold -w ${width} -s | while IFS= read -r line
		do
			padding=$((${width}-${#line}))
			printf "\t| ${BLUE}${line}${NC}" | tee -a $outFile
			printf '%*s|\n' ${padding} | tee -a $outFile
		done
		
		printVSeparator ${width}
	fi
}

printVSeparator() {
	printf "\t " | tee -a $outFile
	printf '%*s' ${1} | tr ' ' '-' | tee -a $outFile
	printf "\n" | tee -a $outFile
}

checkSEP() {
	printSecHead "Checking SEP Install:"
	
	sepsvcs[0]="symcfgd"
	sepsvcs[1]="rtvscand"
	sepsvcs[2]="smcd"
	
	for i in {0..2}
	do
		printPF "${sepsvcs[${i}]}.service" $( getService symcfgd ) "running"
	done
	
#	SEP services are symcfgd, rtvscand, and smcd
#	if [[ ${OS_VER} -ge 7]]; then		
#		for i in {0..2}
#		do
#			printPF "${sepsvcs[${i}]}.service" $( getService symcfgd ) "running"
#		done
#		
#	else
#	printf "Else..."
#		for i in {0..2}
#		do
#			out=$(service ${sepsvcs[${i}]} status | grep -v not)
#			printf "  ${sepsvcs[${i}]}.service running ... " | tee -a $outFile
#			[[ ${#out} -gt 0 ]] && printPassed || { printFailed; return 1; }
#		done
#	fi
	if [[ -s "/etc/Symantec.conf" ]]; then
		sepBaseDir=$(grep BaseDir /etc/Symantec.conf 2>/dev/null| awk -F'=' '{print $2}')
		sav=$(${sepBaseDir}/symantec_antivirus/sav manage -p 2>/dev/null)
		printf "  Configured profile S/N: " | tee -a $outFile
		[[ ${#sav} -gt 0 ]] && \
			printf "${sav} ... ${YELLOW}MANUAL CHECK${NC}\n"  | tee -a $outFile || \
			printf "${RED}Unable to contact SEP servers${NC}\n" | tee -a $outFile
			
		printf "  SEP Defs file: ${LTPURPLE}$(${sepBaseDir}/symantec_antivirus/sav info -d)${NC}\n" | tee -a $outFile
	else
		printf "  SEP has no configuration file ... "
		printFailed
	fi
}

checkLogging() {
	printSecHead "Checking system logging:"
	
	printCFGFileHead "/var/log/"
	printf "  Authorization logs ... " | tee -a $outFile
	[[ -f /var/log/secure || -f /var/log/auth.log ]] && printPassed || printFailed
	
	printf "  Kernel logs ... " | tee -a $outFile
	[[ -f /var/log/kern.log ]] && printPassed || printFailed
	
	printf "  System logs ... " | tee -a $outFile
	[[ -f /var/log/messages || -f /var/log/syslog ]] && printPassed || printFailed
	
	# Log Rotation Chunk
	[[ -f /etc/logrotate.conf ]] || { printf "  ${RED}Log rotation not enabled${NC}\n" | tee -a ${outFile}; return 1; }
	
	printCFGFileHead "/etc/logrotate.conf"
	printPF '=' " Log rotation interval" $(awk '/#.*rotate log files/{getline; print}' /etc/logrotate.conf) "daily"
	printPF '=' " Backlog archive" $(awk '/#.*backlogs/{getline; print $2}' /etc/logrotate.conf) "30"	
	printPF '=' " Log Suffix" $(awk '/#.*suffix/{getline; print}' /etc/logrotate.conf) "dateext"	
#	printPF '=' " Max log size" $(awk '/#.*size to rotate/{getline; print $2}' /etc/logrotate.conf) "500M"

#-- Need to have log file 500 OR backlog 30, don't need both to pass.
	printPF '=' " Max log size" $(grep maxsize /etc/logrotate.conf | awk '{print $2}') "500M"
	printPF '=' " Log Compression" $(awk '/#.*compressed/{getline; print}' /etc/logrotate.conf) "compress"
}

checkAuditing() {
	printSecHead "Checking Server Auditing:"
	
	if [[ ${OS_ROOT} == "DEB" ]]; then
		ad=$(dpkg -s auditd 2>/dev/null | grep Status)
	else
		ad=$(rpm -qa | grep audit)
	fi
	
	if [[ ${#ad} -gt 0 ]]; then
		printPF "Auditd Service" $( getService "auditd" ) "running"
		printCFGFileHead "/etc/audit/auditd.conf"
		printPF '=' "num_logs" $(grep num_logs /etc/audit/auditd.conf | awk '{print $3}') 5
		printPF '=' "max_log_file" $(grep max_log_file /etc/audit/auditd.conf | grep -v action | awk '{print $3}') 10
		printPF '=' "max_log_file_action" $(grep max_log_file_action /etc/audit/auditd.conf | awk '{print $3}') "ROTATE"
		
		printCFGFileHead "/etc/audit/audit.rules"
		printPF_NotEmpty "Watching /etc/localtime" $(grep -w "/etc/localtime" /etc/audit/audit.rules)
		printPF_NotEmpty "Watching /etc/passwd" $(grep -w "/etc/passwd" /etc/audit/audit.rules)
		printPF_NotEmpty "Watching /etc/shadow" $(grep -w "/etc/shadow" /etc/audit/audit.rules)
		printPF_NotEmpty "Watching /etc/group" $(grep -w "/etc/group" /etc/audit/audit.rules)
		printPF_NotEmpty "Watching /etc/gshadow" $(grep -w "/etc/gshadow" /etc/audit/audit.rules)
		printPF_NotEmpty "Watching /etc/security/opasswd" $(grep -w "/etc/security/opasswd" /etc/audit/audit.rules)
		
#-- Only need to watch issue* for Deb, REH watches MOTD and/or sshd-banner
	if [[ -f /etc/issue ]]; then 
		printPF_NotEmpty "Watching /etc/issue" $(grep -w "/etc/issue" /etc/audit/audit.rules)
	fi
	if [[ -f /etc/issue.net ]]; then
		printPF_NotEmpty "Watching /etc/issue.net" $(grep -w "/etc/issue.net" /etc/audit/audit.rules)
	fi
	if [[ -f /etc/ssh/sshd-banner ]]; then	
		printPF_NotEmpty "Watching /etc/ssh/sshd-banner" $(grep -w "etc/ssh/sshd-banner" /etc/audit/audit.rules)
	fi
	if [[ -f /etc/motd ]]; then
		printPF_NotEmpty "Watching /etc/motd" $(grep -q "/etc/motd" /etc/audit/audit.rules)
	fi
		
		printPF_NotEmpty "Watching /etc/hosts" $(grep -w "/etc/hosts" /etc/audit/audit.rules)
		printPF_NotEmpty "Watching /etc/sysconfig/network" $(grep -w "/etc/sysconfig/network" /etc/audit/audit.rules)
		printPF_NotEmpty "Watching command 'sethostname'" $(grep -w "sethostname" /etc/audit/audit.rules)
		printPF_NotEmpty "Watching command 'setdomainname'" $(grep -w "setdomainname" /etc/audit/audit.rules)
	else
		printf "  Auditing service installed and running..." | tee -a $outFile
		printFailed
		if [[ ${OS_ROOT} == "DEB" ]]; then
			printf "${ORANGE}apt-get install auditd${NC}\n" | tee -a $outFile
		else
			printf "${ORANGE}yum install audit${NC}\n" | tee -a $outFile
		fi
	fi
	
	printCFGFileHead "/etc/hosts"
	printf "  Review hosts file:\n\n" | tee -a $outFile
	while read -r line; do
		printf "\t${YELLOW}${line}${NC}\n" | tee -a $outFile
	done < "/etc/hosts"
}

checkSVCs() {

	printSecHead "Checking service configurations:"
	
	if [[ ${OS_ROOT} == "DEB" ]]; then
		printPF_Empty "Telnet Server not installed" $(dpkg -s telnetd 2>/dev/null | grep "Status")
	else
		printPF_Empty "Telnet Server not installed" $(rpm -q telnet-server | grep -v "not installed")
	fi

	if [[ ${OS_ROOT} == "DEB" ]]; then
		printPF_Empty "RSH not installed" $(dpkg -s rshd 2>/dev/null | grep "Status")
	else
		printPF_Empty "RSH not installed" $(rpm -q rsh-server | grep -v "not installed")
	fi

	printPF_Empty "rexecd not running" $(chkconfig "rexec" --list 2>/dev/null)
	printPF_Empty "rlogin not running" $(chkconfig "rlogin" --list 2>/dev/null)
	
	printCFGFileHead "/etc/ssh/sshd_config"
	printPF_Empty "sshd not using SSHv1" $(grep Protocol /etc/ssh/sshd_config | grep 1)
	printPF_Empty "sshd does not allow empty passwords" $(grep -i PermitEmptyPasswords /etc/ssh/sshd_config | grep -v 'no\|#')
	
	# on CentOS6, check /etc/init/control-alt-delete.override
	# on CentOS7+, a service needs to be maseked via 
	#	ln -sf /dev/null /etc/systemd/system/ctrl-alt-del.target
	# or
	#	systemctl mask ctrl-alt-del.target
	# need to find a way to check that the svc is masked in 7+
	
	if [[ ${OS_ROOT} == "RHE" ]]; then
		if [[ OS_VER -ge 7 ]]; then
			printf "\n ${PURPLE}/etc/systemd/system/ctrl-alt-del.target${NC}\n  Ctrl-Alt-Del Disabled ... " | tee -a $outFile
			[[ -e /etc/systemd/system/ctrl-alt-del.target ]] && printPassed || printFailed
		elif [[ OS_VER -lt 6 ]]; then
			printf "\n ${PURPLE}/etc/inittab${NC}\n  Ctrl-Alt-Del Disabled ... " | tee -a $outFile
			cad=$(grep -w "ctrlaltdel:/sbin/shutdown" /etc/inittab | grep -v '#' )
			[[ ${#cad} -gt 0 ]] && printFailed || printPassed
		else
			printf "\n ${PURPLE}/etc/init/control-alt-delete.override${NC}\n  Ctrl-Alt-Del Disabled ... " | tee -a $outFile
			[[ -f /etc/init/control-alt-delete.override ]] && \
				{ cad=$(grep 'shutdown' /etc/init/control-alt-delete.override);
					if [ ${#cad} -gt 0 ]; then
						printFailed;
					else
						printPassed;
					fi;
				} || \
				printFailed
		fi
	else # this assumes anything NOT redhat will be running systemd. So we need to check for systemD rather than OS here.
		printf "\n ${PURPLE}/etc/systemd/system/ctrl-alt-del.target${NC}\n  Ctrl-Alt-Del Disabled ... " | tee -a $outFile
		[[ -e /etc/systemd/system/ctrl-alt-del.target ]] && printPassed || printFailed		
	fi
	
	printf "\n ${PURPLE}/etc/exports${NC}\n" | tee -a $outFile
	printPF_Empty "NFS does \033[4mnot\033[0m have insecure file locking" $(grep insecure_locks /etc/exports 2>/dev/null)
	
	
	printCFGFileHead "/etc/xinetd.d/tftp";
	[[ -f /etc/xinetd.d/tftp ]] && \
		printPF_Empty "TFTP server running in secure mode" $(grep "server_args" /etc/xinetd.d/tftp | grep -v "\-s")	|| \
		printf "  ${GRAY}TFTP server not installed${NC}\n" | tee -a $outFile
		
	printCFGFileHead "/etc/snmp/snmpd.conf"
	[[ -f /etc/snmp/snmpd.conf ]] && \
		printPF_Empty "SNMP service must not use a default password (no lines contain '${ORANGE}public${NC}')" $(grep -v "^#" /etc/snmp/snmpd.conf | grep public) || \
		printf "  ${GRAY}SNMP service not installed${NC}\n" | tee -a $outFile
	
	if [[ ${OS_ROOT} == "RHE" ]]; then
		printf "\n  RPM Package Management tool cryptographically verifies all software packages:\n" | tee -a $outFile
		checkRPM 0
		echo ""
	fi
	
}


# rpmrc is a multi-file configuration. Files are read in reverse order from the array, with later reads overwriting earlier.
# Therefore, we need to check each file in order of what would cause it to fail - i.e. local user config overrules all, so check that
# for non-complaince first. If it's ok, check the next one down, etc.
# Using recursion because it's fun.
checkRPM() 
{
	rpmrcLocs[0]="~root/.rpmpc"
	rpmrcLocs[1]="/etc/rpmrc"
	rpmrcLocs[2]="/usr/lib/rpm/rpmrc"
	rpmrcLocs[3]="/usr/lib/redhat/rpmrc"

	if [[ $# -lt 1 || $1 -eq 0 ]]; then
		set -- 0 "${@:1}"
	fi
	
	if [[ -f ${rpmrcLocs[${1}]} ]]; then
		printf "   ${LTBLUE}${rpmrcLocs[${1}]}${NC} ... " | tee -a $outFile
		nosig=$(grep nosignature ${rpmrcLocs[${1}]})
		if [[ ${#nosig} -gt 0 ]]; then
			printFailed
		else
			printPassed
		fi
		[[ ${1} -lt 3 ]] && checkRPM $((${1}+1));
	else
		[[ ${1} -lt 3 ]] && checkRPM $((${1}+1))
	fi
 }

getService() {

#	[[ ${OS_VER} -ge 7 ]] && \

	[[ -d "/usr/lib/systemd" ]] && \
		svcstat=$(systemctl status ${1} 2>/dev/null | grep Active | awk -F'[ ()]' '{print $7}') || \
		svcstat=$(service ${1} status 2>/dev/null | awk '{print $NF}' | sed 's/\.//g')
			
	echo ${svcstat}	
}

printDoubleHeight() {
	printf "${BOLD}\033#3${1}${NC}\n" | tee -a $outFile
	printf "${BOLD}\033#4${1}${NC}" | tee -a $outFile
}

# Make the printed OS on the header all centered and 'purty-like.
centerOS() {
#release=$(cat /etc/redhat-release)
padding=$((((${#SEP}/2)-${#1})/2))
pad=$(printf '%*s' $((${padding}+2)))
printDoubleHeight "${pad}${1}"
}

setDeb() {
	printf "${DEBL}\n" | tee -a $outFile
	#deb=$(lsb_release -i | awk '{print $3}')
	#ver=$(lsb_release -r | awk '{print $2}')
	#aka=$(lsb_release -c | awk '{print $2}')
	
	deb=$(cat /etc/*-release | grep 'DISTRIB_ID' | awk -F'=' '{print $2}')
	ver=$(cat /etc/*-release | grep 'DISTRIB_RELEASE' | awk -F'=' '{print $2}')
	aka=$(cat /etc/*-release | grep 'DISTRIB_CODENAME' | awk -F'=' '{print $2}')
	
	os="${deb} release ${ver}, \"${aka}\""
	OS_VER=$(echo ${ver} | awk -F'.' '{print $1}')
	OS_ROOT="DEB"
}

setRHE() {
	printf "${RHEL}\n" | tee -a $outFile
	os="$(cat /etc/redhat-release)"
	OS_VER=$(sed 's/[^0-9.]*//g' < /etc/redhat-release | awk -F'.' '{print $1}')
	OS_ROOT="RHE"
}

distroTest() {
		checkRPM=$(which rpm)
		[[ ${#checkRPM} < 1 ]] && setDeb || setRHE
}

testRoot

SEP="---------------------------------------------------------------------------------------"
outFile="verifyOutput.txt"

echo "" > $outFile

echo ""

printf " %s\n" ${SEP} | tee -a $outFile
distroTest
printf " %s\n" ${SEP} | tee -a $outFile
centerOS "${os}"
echo ""

checktime
checkPW
checkRoot
fileCheck
kernelChecks
checkFW
checkMOTD
checkSEP
checkLogging
checkAuditing
checkSVCs

printf "\n${LTGREEN} Finished!${NC}\n %s\n" ${SEP} | tee -a $outFile
