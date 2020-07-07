#!/bin/bash
# manual = https://docs.imunifyav.com/cli/
# Powered by ImunifyAV / imunifyav.com
# Developed by ChrootID / chrootid.com
 
# report to
EMAIL=adit@chrootid.com
 
# date process
DATE=$(date +%F)
 
# destination scan directory
SCANDIR="/home*/*"
 
# logging
TMPLOG=/var/log/malwares.txt
TMPLOG2=/var/log/malwares2.txt
LOGFILE=/var/log/imunifyav-$DATE.txt
LOGROTATE=5
 
# malware scan result MODE option
# 1 = ls
# 2 = chmod ls
# 3 = chmod chattr ls
MODE=1
 
# cpanel user contact email notification
# enabled
# disabled
SENDTO=disabled
 
# colours
red='\033[1;31m'
green='\033[1;32m'
yellow='\033[1;33m'
blue='\033[1;34m'
light_cyan='\033[1;96m'
reset='\033[0m'

# scan duration
function scan_duration {
if [[ $DURATION -lt 60 ]];then
	DURATION=$(echo $DURATION second[s])
elif [[ $DURATION -ge 60 ]] && [[ $DURATION -lt 3600 ]];then
	DURATION=$(expr $DURATION / 60)
	DURATION=$(echo $DURATION minute[s])
elif [[ $DURATION -ge 3600 ]] && [[ $DURATION -lt 86400 ]];then
	DURATION=$(expr $DURATION / 3600)
	DURATION=$(echo $DURATION hour[s])
elif [[ $DURATION -ge 86400 ]] && [[ $DURATION -lt 604800 ]];then
	DURATION=$(expr $DURATION / 86400)
	DURATION=$(echo $DURATION day[s])
fi
}

# status check
function status_check {
i=1
bar="/-\|"
printf "ImunifyAV on-demand scan:${yellow} $STATUS ${reset}[ "
while [[ $STATUS == "running" ]];do
    printf "\b${bar:i++%${#bar}:1}"
    sleep 0.001s
    STATUS=$(imunify-antivirus malware on-demand status|grep status|awk '{print $2}')
done
printf "] ${red}$STATUS ${reset}\n"

# loading scan result
i=1
bar="/-\|"
DURATION=$(imunify-antivirus malware on-demand list|grep $SCANID|awk '{print $3}')
printf "ImunifyAV on-demand scan:${yellow} loading ${reset}[ "
while [[ $DURATION == "None" ]];do
    printf "\b${bar:i++%${#bar}:1}"
    sleep 0.001s
    DURATION=$(imunify-antivirus malware on-demand list|grep $SCANID|awk '{print $3}')
done
printf "] ${green}loaded ${reset}"
printf "\nImunifyAV on-demand scan:${green} completed ${reset}\n"
}

# load scan result
function load_scan_result {
	COMPLETED=$(imunify-antivirus malware on-demand list|grep $SCANID|awk '{print $1}')
	ERROR=$(imunify-antivirus malware on-demand list|grep $SCANID|awk '{print $4}')
	PATHSCAN=$(imunify-antivirus malware on-demand list|grep $SCANID|awk '{print $5}')
	SCAN_TYPE=$(imunify-antivirus malware on-demand list|grep $SCANID|awk '{print $7}')
	STARTED=$(imunify-antivirus malware on-demand list|grep $SCANID|awk '{print $9}')
	TOTAL=$(imunify-antivirus malware on-demand list|grep $SCANID|awk '{print $10}')
	TOTAL_FILES=$(imunify-antivirus malware on-demand list|grep $SCANID|awk '{print $11}')
    TOTAL_MALICIOUS=$(imunify-antivirus malware on-demand list|grep $SCANID|awk '{print $12}')
}

# 
function mailling_to_user {
    # Send to contact email?
    if [[ $SENDTO == enabled ]];then
    printf "Sending to${blue} $CONTACT${reset} for user${blue} $USERS${reset}:${green} $SENDTO ${reset}\n"
        mail -s "MALWARE SCAN REPORT: $MAINDOMAIN $DATE" $CONTACT < $TMPLOG
    else
        printf "Send to${blue} $CONTACT${reset} for user${blue} $USERS${reset}:${red} $SENDTO ${reset}\n"
    fi
}
# print scan result
function print_scan_result {
	echo "Hostname        : $HOSTNAME" > $LOGFILE
	echo "Started         : $(date --date=@$STARTED)" >> $LOGFILE
	echo "Completed       : $(date --date=@$COMPLETED)" >> $LOGFILE
	echo "Duration        : $DURATION" >> $LOGFILE
	echo "Error           : $ERROR" >> $LOGFILE
	echo "Path            : $PATHSCAN" >> $LOGFILE
	echo "Scan Type       : $SCAN_TYPE" >> $LOGFILE
	echo "Scan ID         : $SCANID" >> $LOGFILE
	echo "Total Scanned   : $TOTAL file[s]" >> $LOGFILE
	echo "Total File      : $TOTAL_FILES file[s]" >> $LOGFILE
	echo "Total Malicious : Found $TOTAL_MALICIOUS malicious file[s]" >> $LOGFILE
	echo "Action Mode     : $MESSAGE" >> $LOGFILE
	echo "Log File        : $LOGFILE" >> $LOGFILE
	echo "" >> $LOGFILE
}

# os check
function os_check {
	if [[ $OPERATINGSYSTEM == 'CloudLinux' ]] || [[ $OPERATINGSYSTEM == 'CentOS' ]] || [[ $OPERATINGSYSTEM == 'Red' ]];then
			cpanel_mode_process
	elif [[ $OPERATINGSYSTEM == 'Ubuntu' ]];then
			ubuntu_mode_process
	fi
}
# MODE option
function mode_options {
case $MODE in
    1) # ls
		MODE=1
		MESSAGE="ls (listing only)"
		os_check
    ;;
    2) # chmod ls
		MODE=2
		MESSAGE="chmod 000 + ls"
		os_check
    ;;
    3) # chmod chattr ls
		MODE=3
		MESSAGE="chmod 000, chattr +i, ls"
		os_check
    ;;
    *) echo "MODE Options: {1|2|3} ?"
    ;;
esac
}

# MODE action
function mode_action {
LIMIT=$TOTAL_MALICIOUS
imunify-antivirus malware malicious list|grep $SCANID|awk '{print $13}'|grep -Ev "USERNAME"|sort|uniq|while read USERS;do
if [[ $MODE -eq 1 ]];then # ls
    echo -e "Location: \t\t\t Type:" > $TMPLOG2
    imunify-antivirus malware malicious list --user $USERS --limit $LIMIT|grep $SCANID|grep True|awk '{print $4"\t\t\t"$12}' |sort >> $TMPLOG2
elif [[ $MODE -eq 2 ]];then # chmod ls
    echo -e "Location: \t\t\t Type:" > $TMPLOG2
    imunify-antivirus malware malicious list --user $USERS --limit $LIMIT|grep $SCANID|grep True|awk '{print $4"\t\t\t"$12}' |sort >> $TMPLOG2
    imunify-antivirus malware malicious list --user $USERS --limit $LIMIT|grep $SCANID|grep True|awk '{print $4}'|sort|uniq|while read LIST;do
        if [ -f $LIST ];then
            chmod 000 $LIST
        fi
    done
elif [[ $MODE -eq 3 ]];then # chmod chattr ls
    echo -e "Location: \t\t\t Type:" > $TMPLOG2
    imunify-antivirus malware malicious list --user $USERS --limit $LIMIT|grep $SCANID|grep True|awk '{print $4"\t\t\t"$12}'|sort >> $TMPLOG2
    imunify-antivirus malware malicious list --user $USERS --limit $LIMIT|grep $SCANID|grep True|awk '{print $4}'|sort|uniq|while read LIST;do
		if [ -f $LIST ];then
            chmod 000 $LIST
            chattr +i $LIST
        fi
    done
fi
cat $TMPLOG >> $LOGFILE
/usr/bin/column -t $TMPLOG2 >> $TMPLOG
/usr/bin/column -t $TMPLOG2 >> $LOGFILE
echo "" >> $TMPLOG
echo "" >> $LOGFILE
mailling_to_user
done
}

# MODE process
function ubuntu_mode_process {
	print_scan_result
	mode_action
}

function cpanel_mode_process {
print_scan_result
LIMIT=$TOTAL_MALICIOUS
imunify-antivirus malware malicious list|grep $SCANID|awk '{print $13}'|grep -Ev "USERNAME"|sort|uniq|while read USERS;do
        MAINDOMAIN=$(grep "/$USERS/" /etc/userdatadomains|grep "=main="|cut -d"=" -f7)
        OWNER=$(grep "/$USERS/" /etc/userdatadomains|grep "=main="|cut -d'=' -f3)
        CONTACT=$(grep CONTACTEMAIL /var/cpanel/users/$USERS|cut -d"=" -f2|head -n1)
        TOTALMAL=$(imunify-antivirus malware malicious list --limit $LIMIT|grep $SCANID |grep $USERS|wc -l)
        echo "Username        : $USERS" > $TMPLOG
        echo "Ownership       : $OWNER" >> $TMPLOG
        echo "Main Domain     : $MAINDOMAIN" >> $TMPLOG
        echo "Contact Email   : $CONTACT" >> $TMPLOG
        echo "Total Malicious : Found $TOTALMAL malicious file(s)" >> $TMPLOG
        if [[ $MODE -eq 1 ]];then # ls
            echo -e "Location: \t\t\t Type:" > $TMPLOG2
            imunify-antivirus malware malicious list --user $USERS --limit $LIMIT|grep $SCANID|grep True|awk '{print $4"\t\t\t"$12}' |sort >> $TMPLOG2
        elif [[ $MODE -eq 2 ]];then # chmod ls
            echo -e "Location: \t\t\t Type:" > $TMPLOG2
            imunify-antivirus malware malicious list --user $USERS --limit $LIMIT|grep $SCANID|grep True|awk '{print $4"\t\t\t"$12}' |sort >> $TMPLOG2
            imunify-antivirus malware malicious list --user $USERS --limit $LIMIT|grep $SCANID|grep True|awk '{print $4}'|sort|uniq|while read LIST;do
            if [ -f $LIST ];then
                chmod 000 $LIST
            fi
            done
        elif [[ $MODE -eq 3 ]];then # chmod chattr ls
            echo -e "Location: \t\t\t Type:" > $TMPLOG2
            imunify-antivirus malware malicious list --user $USERS --limit $LIMIT|grep $SCANID|grep True|awk '{print $4"\t\t\t"$12}'|sort >> $TMPLOG2
            imunify-antivirus malware malicious list --user $USERS --limit $LIMIT|grep $SCANID|grep True|awk '{print $4}'|sort|uniq|while read LIST;do
            if [ -f $LIST ];then
                chmod 000 $LIST
                chattr +i $LIST
            fi
            done
        fi
        cat $TMPLOG >> $LOGFILE
		/usr/bin/column -t $TMPLOG2 >> $TMPLOG
		/usr/bin/column -t $TMPLOG2 >> $LOGFILE
        echo "" >> $TMPLOG
        echo "" >> $LOGFILE
		mailling_to_user
done
mail -s "MALWARE SCAN REPORT [$HOSTNAME] $DATE" $EMAIL < $LOGFILE
printf "Malware scan result logfile:${light_cyan} $LOGFILE ${reset}\n"
}

# os validation check
echo -n "Checking Operating System:"
if [[ -f /usr/bin/hostnamectl ]];then
	OPERATINGSYSTEM=$(/usr/bin/hostnamectl|grep "Operating System"|cut -d: -f2|awk '{print $1}')
	if [[ $OPERATINGSYSTEM == 'CloudLinux' ]] || [[ $OPERATINGSYSTEM == 'CentOS' ]] || [[ $OPERATINGSYSTEM == 'Red' ]];then
		printf "${green} $(/usr/bin/hostnamectl|grep "Operating System"|cut -d: -f2) ${reset}\n"
		PACKAGEMANAGER=/bin/rpm
	elif [[ $OPERATINGSYSTEM == 'Ubuntu' ]] || [[ $OPERATINGSYSTEM == 'Debian' ]];then
		PACKAGEMANAGER=/usr/bin/dpkg
		mkdir -p /etc/sysconfig/imunify360/
		echo "[paths]" > /etc/sysconfig/imunify360/integration.conf
		echo "ui_path = /var/www/html" >> /etc/sysconfig/imunify360/integration.conf
		printf "${green} $(/usr/bin/hostnamectl|grep "Operating System"|cut -d: -f2) ${reset}\n"
		
	fi
elif [[ -f /etc/redhat-release ]];then
	OPERATINGSYSTEM=$(cat /etc/redhat-release|awk '{print 1}')
	if [[ $OPERATINGSYSTEM == 'CloudLinux' ]] || [[ $OPERATINGSYSTEM == 'CentOS' ]];then
		printf "${green} $(cat /etc/redhat-release|awk '{print 1}') ${reset}\n"
		PACKAGEMANAGER=/bin/rpm
	fi
else
	printf "${red} Unknown ${reset}\n"
	printf "ImunifyAVX: ${red}FAILED${reset}\n"
	echo "Unsupported yet"
	exit
fi

# require mailx
echo -n "Checking mailx: "
if [[ $OPERATINGSYSTEM == 'CloudLinux' ]] || [[ $OPERATINGSYSTEM == 'CentOS' ]] || [[ $OPERATINGSYSTEM == 'Red' ]];then
RPMMAILX=$($PACKAGEMANAGER -qa|grep mailx|cut -d- -f1|head -n1)
	if [[ $RPMMAILX != "mailx" ]];then
		printf "${red}FAILED ${reset}\n"
		printf "mail command not found:${yellow} installing mailx${reset}\n"
		yum install -y mailx
		printf "Checking mailx: ${green}OK ${reset}\n"
	else
		printf "${green}OK ${reset}\n"
	fi
elif [[ $OPERATINGSYSTEM == 'Ubuntu' ]] || [[ $OPERATINGSYSTEM == 'Debian' ]];then
RPMMAILX=$($PACKAGEMANAGER -l|grep mailx)
	if [[ -z $RPMMAILX ]];then
		printf "${red}FAILED ${reset}\n"
		printf "mail command not found:${yellow} installing mailx${reset}\n"
		apt install -y mailx
		printf "Checking mailx: ${green}OK ${reset}\n"
	else
		printf "${green}OK ${reset}\n"
	fi
fi
 
# user check
echo -n "Checking user: "
if [[ $(id -u) -ne 0 ]];then
    printf "${red}FAILED ${reset}\n"
    echo "Root only"| mail -s "MALWARE SCAN FAILED: [$HOSTNAME] $DATE" $EMAIL
    exit
else
    printf "${green}OK ${reset}\n"
fi

# imunifyav check
echo -n "Checking imunifyav: "
if [[ ! -f /usr/bin/imunify-antivirus ]];then
    printf "${red}FAILED ${reset}\n"
    echo "ImunifyAV was not installed"
    echo "checking system requirement before imunifyav installation"
    FREESPACE=$(expr $(df /|awk 'NR==2 {print $4}') / 1000000)
    MEMORY=$(free -m|awk 'NR==2 {print $2}')
    if [[ ${FREESPACE/.*} -ge 21 ]] && [[ $MEMORY -ge 512 ]];then
        echo "starting imunifyav installation"
        wget https://repo.imunify360.cloudlinux.com/defence360/imav-deploy.sh -O /root/imav-deploy.sh
        bash /root/imav-deploy.sh
        if [[ -f /usr/bin/imunify-antivirus ]];then
            printf "checking imunifyav:${green} OK${reset}\n"
        else
            printf "checking imunifyav:${red} FAILED${reset}\n"
            exit 
        fi
    else
        printf "ImunifyAV installation:${red} FAILED${reset}\n"
        printf "Hardware Requirements\n"
        printf "RAM:${green} 512 MB${reset}\n"
        printf "Storage:${green} 20 GB ${reset}available disk space\n\n"
        printf "Your $HOSTNAME server hardware\n"
        if [[ $MEMORY -lt 512 ]];then
            printf "RAM:${red} $MEMORY MB${reset}\n"
        elif [[ $MEMORY -ge 512 ]];then
            printf "RAM:${green} $MEMORY MB${reset}\n"
        fi
        if [[ ${FREESPACE/.*} -lt 21 ]];then
            printf "Storage:${red} $FREESPACE GB ${reset}available disk space\n"
        elif [[ ${FREESPACE/.*} -ge 21 ]];then
            printf "Storage:${green} $FREESPACE GB ${reset}available disk space\n"
        fi
        exit
    fi
elif [[ -f /usr/bin/imunify-antivirus ]];then
	if [[ -f /bin/systemctl ]];then
		SYSSTATUS=$(systemctl status imunify-antivirus|grep Active|cut -d: -f2|awk '{print $1}')
		if [[ $SYSSTATUS == "inactive" ]];then
			/bin/systemctl start imunify-antivirus
			printf "${green}OK ${reset}\n"
		elif [[ $SYSSTATUS == "active" ]];then
			printf "${green}OK ${reset}\n"
		fi
	elif [[ -f /sbin/service ]];then
		SYSSTATUS=$(/sbin/service imunify-antivirus status|cut -d. -f1|awk '{print $5}')
		if [[ $SYSSTATUS == "running" ]];then
			printf "${green}OK ${reset}\n"
		elif [[ $SYSSTATUS != "running" ]];then
			/sbin/service imunify-antivirus start
			printf "${green}OK ${reset}\n"
		fi
	fi
fi

# signature update process
printf "ImunifyAV signatures: ${yellow}updating ${reset}\n"
printf " geo:${green} $(imunify-antivirus update geo) ${reset}\n"
printf " rules:${green} $(imunify-antivirus update modsec-rules) ${reset}\n"
printf " sigs:${green} $(imunify-antivirus update sigs) ${reset}\n"
printf " static whitelist:${green} $(imunify-antivirus update static-whitelist) ${reset}\n"
printf " eula:${green} $(imunify-antivirus update eula) ${reset}\n"
printf " ip-record:${green} $(imunify-antivirus update ip-record) ${reset}\n"
printf " sigs-php:${green} $(imunify-antivirus update sigs-php) ${reset}\n"
printf " ossecp:${green} $(imunify-antivirus update ossec) ${reset}\n"
printf "ImunifyAV signatures: ${green}update completed ${reset}\n"

# scan process
STATUS=$(imunify-antivirus malware on-demand status|grep status|awk '{print $2}')
if [[ $STATUS == "stopped" ]];then
	printf "ImunifyAV on-demand scan:${red} $STATUS ${reset}\n"
	printf "Starting ImunifyAV on-demand scan: ${green}"
    imunify-antivirus malware on-demand start --path=$SCANDIR
	printf "${reset}"
    SCANID=$(imunify-antivirus malware on-demand status|grep scanid|awk '{print $2}')
    STATUS=$(imunify-antivirus malware on-demand status|grep status|awk '{print $2}')
    status_check
	load_scan_result
    if [[ $TOTAL_MALICIOUS -gt "0" ]];then
		printf "Found ${red}$TOTAL_MALICIOUS${reset} malware file(s)\n"
		scan_duration
        mode_options
    else
		printf "${green}Clean${reset}: malware not found\n"
    fi
elif [[ $STATUS == "running" ]];then
	printf "${yellow}WARNING${reset}: On-demand scan is already ${yellow}running${reset}\n"
	exit
else
    echo "ImunifyAV on-demand scan: $STATUS"|mail -s "MALWARE SCAN FAILED: [$HOSTNAME] $DATE" $EMAIL
    exit
fi
 
# log rotate
TOTAL_LOG=$(ls /var/log/imunifyav-*.txt|wc -l)
if [[ $TOTAL_LOG -gt $LOGROTATE ]];then
    DELETELOG=$(expr $TOTAL_LOG - $LOGROTATE)
    ls /var/log/imunifyav-*.txt|sort|head -n $DELETELOG|while read DELETE;do
        if [ -f $DELETE ];then
            rm -f $DELETE;
        fi
    done 
fi