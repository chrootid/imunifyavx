#!/bin/bash
# manual = https://docs.imunifyav.com/cli/
# Powered by ImunifyAV / imunifyav.com
# Developed by ChrootID / chrootid.com

# date process
DATE=$(date +%F)

# logging
TMPLOG=/var/log/malwares.txt
TMPLOG2=/var/log/malwares2.txt
LOGFILE=/var/log/imunifyavx-$DATE.txt
LOGROTATE=5

# cpanel user contact email notification
# enabled
# disabled
REPORTTO=disabled
 
# colours
red='\033[1;31m'
green='\033[1;32m'
yellow='\033[1;33m'
blue='\033[1;34m'
light_cyan='\033[1;96m'
reset='\033[0m'

# scan duration
function scan_duration {
if [[ "$DURATION" -lt 60 ]];then
    DURATION=$(echo "$DURATION" second[s])
elif [[ "$DURATION" -ge 60 ]] && [[ "$DURATION" -lt 3600 ]];then
    DURATION=$(( DURATION / 60 ))
    DURATION=$(echo "$DURATION" minute[s])
elif [[ "$DURATION" -ge 3600 ]] && [[ "$DURATION" -lt 86400 ]];then
    DURATION=$(( DURATION / 3600 ))
    DURATION=$(echo "$DURATION" hour[s])
elif [[ "$DURATION" -ge 86400 ]] && [[ "$DURATION" -lt 604800 ]];then
    DURATION=$(( DURATION / 86400 ))
    DURATION=$(echo "$DURATION" day[s])
fi
}

# status check
function status_check {
i=1
bar="/-\|"
printf "On-demand scan status          : %s  " "$STATUS"
while [[ "$STATUS" == "running" ]];do
    printf "\b${bar:i++%${#bar}:1}"
    sleep 0.001s
    STATUS=$(imunify-antivirus malware on-demand status|awk '/status/ {print $2}')
done
echo -e " $STATUS "

# loading scan result
DURATION=$(imunify-antivirus malware on-demand list|grep "$SCANID"|awk '{print $3}')
while [[ "$DURATION" == "None" ]];do
    printf "\b${bar:i++%${#bar}:1}"
    sleep 0.001s
    DURATION=$(imunify-antivirus malware on-demand list|grep "$SCANID"|awk '{print $3}')
done
echo -e "On-demand scan status          : completed "
}

# load scan result
function load_scan_result {
	COMPLETED=$(imunify-antivirus malware on-demand list|grep "$SCANID"|awk '{print $1}')
	ERROR=$(imunify-antivirus malware on-demand list|grep "$SCANID"|awk '{print $4}')
	PATHSCAN=$(imunify-antivirus malware on-demand list|grep "$SCANID"|awk '{print $5}')
	SCAN_TYPE=$(imunify-antivirus malware on-demand list|grep "$SCANID"|awk '{print $7}')
	STARTED=$(imunify-antivirus malware on-demand list|grep "$SCANID"|awk '{print $9}')
	TOTAL=$(imunify-antivirus malware on-demand list|grep "$SCANID"|awk '{print $10}')
	TOTAL_FILES=$(imunify-antivirus malware on-demand list|grep "$SCANID"|awk '{print $11}')
    TOTAL_MALICIOUS=$(imunify-antivirus malware on-demand list|grep "$SCANID"|awk '{print $12}')
}

# mailreport to mailadmin
function malware_report_to_mailadmin {
	if [[ -n "$EMAIL" ]];then
	    echo -e "On-demand scan report          : $EMAIL"
		mail -s "MALWARE SCAN REPORT ['$HOSTNAME'] '$DATE'" "$EMAIL" < "$LOGFILE"
	elif [[ -z "$EMAIL" ]];then
		echo -e "On-demand scan report          : Please define your email address if you want to recieve malware scan report"
		echo -e "                                 Try: /bin/bash $0 --email=youremail@address.com"
	fi
}

# mailreport to mail user
function malware_report_to_mailuser {
    # Send to contact email?
    if [[ "$REPORTTO" == enabled ]];then
        mail -s "MALWARE SCAN REPORT: '$MAINDOMAIN' '$DATE'" "$CONTACT" < "$TMPLOG"
		echo -e "On-demand scan report for user : $USERS to $CONTACT was sent"
    else
        echo -e "On-demand scan report for user : $USERS to $CONTACT was $REPORTTO"
    fi
}

# MODE option
function mode_options {
case "$MODE" in
    1) # ls
		MODE=1
		MESSAGE="ls (listing only)"
		hostingpanel_check
    ;;
    2) # chmod ls
		MODE=2
		MESSAGE="chmod 000"
		hostingpanel_check
    ;;
    3) # chmod chattr ls
		MODE=3
		MESSAGE="chmod 000 && chattr +i"
		hostingpanel_check
    ;;
    *) echo "MODE Options: {1|2|3} ?"
    ;;
esac
}

# hosting panel check
function hostingpanel_check {
	if [[ "$OPERATINGSYSTEM" == 'CloudLinux' ]] || [[ "$OPERATINGSYSTEM" == 'CentOS' ]] || [[ "$OPERATINGSYSTEM" == 'Red' ]];then
		if [[ -f /usr/local/cpanel/version ]];then
			HOSTINGPANEL="cPanel/WHM $(cat /usr/local/cpanel/version)"
			cpanel_mode_process
		else
			standalone_mode_process
		fi
	elif [[ "$OPERATINGSYSTEM" == 'Ubuntu' ]];then
		HOSTINGPANEL='Stand Alone'
		standalone_mode_process
	else
		HOSTINGPANEL='Stand Alone'
		standalone_mode_process
	fi
}

# standalone mode process
function standalone_mode_process {
	print_scan_result
	mode_action
	malware_report_to_mailadmin
	echo -e "ImunifyAVX log file            : $LOGFILE "
}

# cpanel mode process
function cpanel_mode_process {
print_scan_result
LIMIT="$TOTAL_MALICIOUS"
imunify-antivirus malware malicious list|grep "$SCANID"|awk '{print $13}'|grep -Ev "USERNAME"|sort|uniq|while read -r USERS;do
        MAINDOMAIN=$(grep "/$USERS/" /etc/userdatadomains|grep "=main="|cut -d"=" -f7)
        OWNER=$(grep "/$USERS/" /etc/userdatadomains|grep "=main="|cut -d'=' -f3)
        #CONTACT=$(grep CONTACTEMAIL /var/cpanel/users/"$USERS"|cut -d"=" -f2|head -n1)
		CONTACT=$(awk -F '=' '/CONTACTEMAIL=/ {print $2}' /var/cpanel/users/"$USERS")
        TOTALMAL=$(imunify-antivirus malware malicious list --limit "$LIMIT"|grep "$SCANID" |grep -c "$USERS")
        echo "Username        : $USERS" > "$TMPLOG"
        {
                echo "Ownership       : $OWNER"
                echo "Main Domain     : $MAINDOMAIN"
                echo "Contact Email   : $CONTACT"
                echo "Total Malicious : Found $TOTALMAL malicious file(s)"
        } >> "$TMPLOG"
        if [[ "$MODE" -eq 1 ]];then # ls
            echo -e "Location: \t\t\t Type:" > "$TMPLOG2"
            imunify-antivirus malware malicious list --user "$USERS" --limit "$LIMIT"|grep "$SCANID"|awk '/True/ {print $4"\t\t\t"$12}' |sort >> "$TMPLOG2"
        elif [[ "$MODE" -eq 2 ]];then # chmod ls
            echo -e "Location: \t\t\t Type:" > "$TMPLOG2"
            imunify-antivirus malware malicious list --user "$USERS" --limit "$LIMIT"|grep "$SCANID"|awk '/True/ {print $4"\t\t\t"$12}' |sort >> "$TMPLOG2"
            imunify-antivirus malware malicious list --user "$USERS" --limit "$LIMIT"|grep "$SCANID"|awk '/True/ {print $4}'|sort|uniq|while read -r LIST;do
			# if malware file still exist, then change its file permission
            if [ -f "$LIST" ];then
                chmod 000 "$LIST"
            fi
            done
        elif [[ "$MODE" -eq 3 ]];then # chmod chattr ls
            echo -e "Location: \t\t\t Type:" > "$TMPLOG2"
            imunify-antivirus malware malicious list --user "$USERS" --limit "$LIMIT"|grep "$SCANID"|awk '/True/ {print $4"\t\t\t"$12}'|sort >> "$TMPLOG2"
            imunify-antivirus malware malicious list --user "$USERS" --limit "$LIMIT"|grep "$SCANID"|awk '/True/ {print $4}'|sort|uniq|while read -r LIST;do
            if [ -f "$LIST" ];then
                chmod 000 "$LIST"
                chattr +i "$LIST"
            fi
            done
        fi
        cat "$TMPLOG" >> "$LOGFILE"
		/usr/bin/column -t "$TMPLOG2" >> "$TMPLOG"
		/usr/bin/column -t "$TMPLOG2" >> "$LOGFILE"
        echo "" >> "$TMPLOG"
        echo "" >> "$LOGFILE"
		malware_report_to_mailuser
done
malware_report_to_mailadmin
echo -e "ImunifyAVX log file            : $LOGFILE "
}

# print scan result
function print_scan_result {
	echo "Hostname        : $HOSTNAME" > "$LOGFILE"
	{
	        echo "OS              : $OPERATINGSYSTEM"
	        echo "Hosting Panel   : $HOSTINGPANEL"
	        echo "Started         : $(date --date=@"$STARTED")"
	        echo "Completed       : $(date --date=@"$COMPLETED")"
	        echo "Duration        : $DURATION"
	        echo "Error           : $ERROR"
	        echo "Path            : $PATHSCAN"
	        echo "Scan Type       : $SCAN_TYPE"
	        echo "Scan ID         : $SCANID"
	        echo "Total Scanned   : $TOTAL file[s]"
	        echo "Total File      : $TOTAL_FILES file[s]"
	        echo "Total Malicious : Found $TOTAL_MALICIOUS malicious file[s]"
	        echo "Action Mode     : $MESSAGE"
	        echo "Log File        : $LOGFILE"
	        echo ""
	} >> "$LOGFILE"
}

# MODE action
function mode_action {
	LIMIT="$TOTAL_MALICIOUS"
	imunify-antivirus malware malicious list|grep "$SCANID"|awk '{print $13}'|grep -Ev "USERNAME"|sort|uniq|while read -r USERS;do
	echo "Username        : '$USERS'" > "$TMPLOG"
	message_tips
	if [[ "$MODE" -eq 1 ]];then # ls
		echo -e "Location: \t\t\t Type:" > "$TMPLOG2"
		imunify-antivirus malware malicious list --user "$USERS" --limit "$LIMIT"|grep "$SCANID"|awk '/True/ {print $4"\t\t\t"$12}' |sort >> "$TMPLOG2"
	elif [[ "$MODE" -eq 2 ]];then # chmod ls
		echo -e "Location: \t\t\t Type:" > "$TMPLOG2"
		imunify-antivirus malware malicious list --user "$USERS" --limit "$LIMIT"|grep "$SCANID"|awk '/True/ {print $4"\t\t\t"$12}' |sort >> "$TMPLOG2"
		imunify-antivirus malware malicious list --user "$USERS" --limit "$LIMIT"|grep "$SCANID"|awk '/True/ {print $4}'|sort|uniq|while read -r LIST;do
			if [ -f "$LIST" ];then
				chmod 000 "$LIST"
			fi
		done
	elif [[ "$MODE" -eq 3 ]];then # chmod chattr ls
		echo -e "Location: \t\t\t Type:" > "$TMPLOG2"
		imunify-antivirus malware malicious list --user "$USERS" --limit "$LIMIT"|grep "$SCANID"|awk '/True/ {print $4"\t\t\t"$12}'|sort >> "$TMPLOG2"
		imunify-antivirus malware malicious list --user "$USERS" --limit "$LIMIT"|grep "$SCANID"|awk '/True/ {print $4}'|sort|uniq|while read -r LIST;do
			if [ -f "$LIST" ];then
				chmod 000 "$LIST"
				chattr +i "$LIST"
			fi
		done
	fi
	cat "$TMPLOG" >> "$LOGFILE"
	/usr/bin/column -t "$TMPLOG2" >> "$TMPLOG"
	/usr/bin/column -t "$TMPLOG2" >> "$LOGFILE"
	echo "" >> "$TMPLOG"
	echo "" >> "$LOGFILE"
	malware_report_to_mailuser
	done
}

# usage
function usage {
echo "USAGE: $0 --email=[EMAIL ADDRESS] --mode=[ACTION MODE] --path=[PATH]"
echo ""
echo "-e, --email=[EMAIL ADDRESS]        send malware scan report to email address"
echo "-m, --mode=[ACTION MODE]           default value is 1"
echo "     1 = ls                        only for print malicious file list"
echo "     2 = chmod 000                 change permission malicious files to 000"
echo "     3 = chmod 000 && chattr +i    change permission malicious files to 000 and change its attribute to immutable"
echo "-r, --report                       report malware scan result to hosting user contact mail"
echo "-p, --path=[PATH]                  scan directory, default value is /home*/*"
echo "-h, --help                         show usage information"
echo ""
echo "Example:"
echo "bash $0 --email=youremail@address.com --mode=1 --path=/home/"
echo "bash $0 -e=your@email.com -m=1 -p=/home/"
}

##### main ####
for i in "$@"
do
case "$i" in
    -e=*|--email=*)
        EMAIL="${i#*=}"
        shift
        ;;
    -m=*|--mode=*)
        MODE="${i#*=}"
        shift
        ;;
    -p=*|--path=*)
        SCANDIR="${i#*=}"
        shift
        ;;
	-r|--report)
		REPORTTO=enabled
		shift
	;;
	-h|--help)
		usage
		exit
		;;
    *)
        usage
        exit
        ;;
esac
done
if [[ -z "$MODE" ]];then
	MODE=1
elif [[ "$MODE" -eq 0 ]];then
	MODE=1
elif [[ "$MODE" -gt 3 ]];then
	usage
	exit
fi

if [[ -z "$SCANDIR" ]];then
	SCANDIR='/home*/*'
elif [[ ! -d "$SCANDIR" ]];then
	echo -e "'$SCANDIR': not found"
	usage
	exit	
fi

clear

# os validation check
echo -n "Checking for Operating System  :"
if [[ -f /usr/bin/hostnamectl ]];then
	OPERATINGSYSTEM=$(/usr/bin/hostnamectl|grep "Operating System"|cut -d: -f2|awk '{print $1}')
	if [[ "$OPERATINGSYSTEM" == 'CloudLinux' ]] || [[ "$OPERATINGSYSTEM" == 'CentOS' ]] || [[ "$OPERATINGSYSTEM" == 'Red' ]];then
		echo -e "$(/usr/bin/hostnamectl|grep "Operating System"|cut -d: -f2) "
		PACKAGEMANAGER=/bin/rpm
	elif [[ "$OPERATINGSYSTEM" == 'Ubuntu' ]] || [[ "$OPERATINGSYSTEM" == 'Debian' ]];then
		PACKAGEMANAGER=/usr/bin/dpkg
		if [[ ! -d /etc/sysconfig/imunify360/ ]];then
			mkdir -p /etc/sysconfig/imunify360/
		fi
		if [[ ! -f /etc/sysconfig/imunify360/integration.conf ]];then
			echo "[paths]" > /etc/sysconfig/imunify360/integration.conf
			echo "ui_path = /var/www/html" >> /etc/sysconfig/imunify360/integration.conf
		fi
		echo -e "$(/usr/bin/hostnamectl|grep "Operating System"|cut -d: -f2) "
		
	fi
elif [[ -f /etc/redhat-release ]];then
	OPERATINGSYSTEM=$(awk '{print $1}' /etc/redhat-release)
	if [[ "$OPERATINGSYSTEM" == 'CloudLinux' ]] || [[ "$OPERATINGSYSTEM" == 'CentOS' ]];then
		echo -e "$(awk '{print $1}' /etc/redhat-release) "
		PACKAGEMANAGER=/bin/rpm
	fi
else
	echo -e " '$OPERATINGSYSTEM' "
	echo -e "ImunifyAVX: FAILED"
	echo "Unsupported yet"
	exit
fi

# require mailx
echo -n "Checking for mailx             : "
if [[ "$OPERATINGSYSTEM" == 'CloudLinux' ]] || [[ "$OPERATINGSYSTEM" == 'CentOS' ]] || [[ "$OPERATINGSYSTEM" == 'Red' ]];then
RPMMAILX=$("$PACKAGEMANAGER" -qa|grep mailx|cut -d- -f1|head -n1)
	if [[ "$RPMMAILX" != "mailx" ]];then
		echo -e "FAILED "
		echo -e "mail command not found: installing mailx"
		yum install -y mailx
		echo -e "Checking mailx: OK "
	else
		echo -e "OK "
	fi
elif [[ "$OPERATINGSYSTEM" == 'Ubuntu' ]] || [[ "$OPERATINGSYSTEM" == 'Debian' ]];then
RPMMAILX=$("$PACKAGEMANAGER" -l|grep mailx)
	if [[ -z "$RPMMAILX" ]];then
		echo -e "FAILED "
		echo -e "mail command not found: installing mailx"
		apt install -y mailx
		echo -e "Checking mailx: OK "
	else
		echo -e "OK "
	fi
fi
 
# user check
echo -n "Checking for user              : "
if [[ $(id -u) -ne 0 ]];then
    echo -e "FAILED "
    echo -e "Require root priviledge. Please try 'sudo su' or 'su -u root' and try again."
    exit
else
    echo -e "OK "
fi

# imunifyav check
echo -n "Checking for imunifyav         : "
if [[ ! -f /usr/bin/imunify-antivirus ]];then
    echo -e "FAILED "
    echo -e "ImunifyAV was not installed"
    echo -e "checking system requirement before imunifyav installation"
    FREESPACE=$(( $(df /home|awk 'NR==2 {print $4}') / 1000000 ))
    MEMORY=$(free -m|awk 'NR==2 {print $2}')
    if [[ ${FREESPACE/.*} -ge 21 ]] && [[ "$MEMORY" -ge 512 ]];then
        echo "starting imunifyav installation"
        wget https://repo.imunify360.cloudlinux.com/defence360/imav-deploy.sh -O /root/imav-deploy.sh
        bash /root/imav-deploy.sh
        if [[ -f /usr/bin/imunify-antivirus ]];then
            echo -e "checking for imunifyav: OK"
        else
            echo -e "checking for imunifyav: FAILED"
            exit 
        fi
    else
        echo -e "ImunifyAV installation: FAILED"
        echo -e "Minimum Hardware Requirements"
        echo -e "RAM: 512 MB"
        echo -e "Storage: 20 GB available disk space"
		echo ""
        echo -e "Your $HOSTNAME server hardware spec"
        if [[ "$MEMORY" -lt 512 ]];then
            echo -e "RAM: '$MEMORY' MB"
        elif [[ "$MEMORY" -ge 512 ]];then
            echo -e "RAM: '$MEMORY' MB"
        fi
        if [[ ${FREESPACE/.*} -lt 21 ]];then
            echo -e "Storage: '$FREESPACE' GB available disk space"
        elif [[ ${FREESPACE/.*} -ge 21 ]];then
            echo -e "Storage: '$FREESPACE' GB available disk space"
        fi
        exit
    fi
elif [[ -f /usr/bin/imunify-antivirus ]];then
	if [[ -f /bin/systemctl ]];then
		SYSSTATUS=$(systemctl status imunify-antivirus|grep Active|cut -d: -f2|awk '{print $1}')
		if [[ "$SYSSTATUS" == "inactive" ]];then
			/bin/systemctl start imunify-antivirus
			echo -e "OK "
		elif [[ "$SYSSTATUS" == "active" ]];then
			echo -e "OK "
		fi
	elif [[ -f /sbin/service ]];then
		SYSSTATUS=$(/sbin/service imunify-antivirus status|cut -d. -f1|awk '{print $5}')
		if [[ "$SYSSTATUS" == "running" ]];then
			echo -e "OK "
		elif [[ "$SYSSTATUS" != "running" ]];then
			/sbin/service imunify-antivirus start
			echo -e "OK "
		fi
	fi
fi

# signature update process
echo -e "Checking for signatures update : Updating "
echo -e "   sigs: $(imunify-antivirus update sigs) "
echo -e "   eula: $(imunify-antivirus update eula) "
echo -e "Checking for signatures update : Done "

# scan process
STATUS=$(imunify-antivirus malware on-demand status|grep status|awk '{print $2}')
if [[ "$STATUS" == "stopped" ]];then
	echo -e "On-demand scan status          : $STATUS "
	printf "Starting on-demand scan        : "
    imunify-antivirus malware on-demand start --path="$SCANDIR"
	printf ""
    SCANID=$(imunify-antivirus malware on-demand status|awk '/scanid/ {print $2}')
    STATUS=$(imunify-antivirus malware on-demand status|awk '/status/ {print $2}')
    status_check
	load_scan_result
    if [[ "$TOTAL_MALICIOUS" -gt "0" ]];then
		echo -e "On-demand scan result          : Found $TOTAL_MALICIOUS suspicious file(s)"
		scan_duration
        mode_options
    else
		echo -e "On-demand scan result          : Clean, suspicous file not found"
    fi
elif [[ "$STATUS" == "running" ]];then
	echo -e "On-demand scan status          : WARNING: On-demand scan is already running"
	pgrep -f imunifyavx|xargs ps
	exit
else
    echo "On-demand scan status          : $STATUS"|mail -s "MALWARE SCAN FAILED: [$HOSTNAME] $DATE" "$EMAIL"
    exit
fi
 
# log rotate
if [[ -f "$LOGFILE" ]];then
	TOTAL_LOG=$(find /var/log/ -name 'imunifyav-*.txt' -type f|wc -l)
	if [[ "$TOTAL_LOG" -gt "$LOGROTATE" ]];then
		DELETELOG=$(( "$TOTAL_LOG" - "$LOGROTATE" ))
		find /var/log/ -name 'imunifyavx-*.txt' -type f|sort|head -n "$DELETELOG"|while read -r DELETE;do
			if [ -f "$DELETE" ];then
				rm -f "$DELETE";
			fi
		done 
	fi
fi