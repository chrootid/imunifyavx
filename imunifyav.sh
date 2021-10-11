#!/bin/bash
# manual = https://docs.imunifyav.com/cli/
# Powered by ImunifyAV / imunifyav.com
# Developed by ChrootID / chrootid.com

# date process
DATE=$(date +%F)

# logging
TMPLOG=/var/log/malwares.txt
TMPLOG2=/var/log/malwares2.txt
LOGFILE=/var/log/imunifyav-$DATE.txt
LOGROTATE=5

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
if [[ "$DURATION" -lt 60 ]];then
	DURATION=$(echo "$DURATION" second[s])
elif [[ "$DURATION" -ge 60 ]] && [[ "$DURATION" -lt 3600 ]];then
	DURATION=$(expr "$DURATION" / 60)
	DURATION=$(echo "$DURATION" minute[s])
elif [[ "$DURATION" -ge 3600 ]] && [[ "$DURATION" -lt 86400 ]];then
	DURATION=$(expr "$DURATION" / 3600)
	DURATION=$(echo "$DURATION" hour[s])
elif [[ "$DURATION" -ge 86400 ]] && [[ "$DURATION" -lt 604800 ]];then
	DURATION=$(expr "$DURATION" / 86400)
	DURATION=$(echo "$DURATION" day[s])
fi
}

# status check
function status_check {
i=1
bar="/-\|"
printf "ImunifyAV on-demand scan:${yellow} $STATUS ${reset} "
while [[ "$STATUS" == "running" ]];do
    printf "\b${bar:i++%${#bar}:1}"
    sleep 0.001s
    STATUS=$(imunify-antivirus malware on-demand status|awk '/status/ {print $2}')
done
echo -e " ${red}"$STATUS" ${reset}"

# loading scan result
DURATION=$(imunify-antivirus malware on-demand list|grep "$SCANID"|awk '{print $3}')
while [[ "$DURATION" == "None" ]];do
    printf "\b${bar:i++%${#bar}:1}"
    sleep 0.001s
    DURATION=$(imunify-antivirus malware on-demand list|grep "$SCANID"|awk '{print $3}')
done
echo -e "ImunifyAV on-demand scan:${green} completed ${reset}"
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
	if [[ ! -z "$EMAIL" ]];then
		mail -s "MALWARE SCAN REPORT ["$HOSTNAME"] "$DATE"" "$EMAIL" < "$LOGFILE"
	elif [[ -z "$EMAIL" ]];then
		echo -e "Please define your ${red}email address${reset} to recieve malware scan report"
		echo -e "$0 --email=${red}youremail@address.com${reset}"
	fi
}

# mailreport to mail user
function malware_report_to_mailuser {
    # Send to contact email?
    if [[ "$SENDTO" == enabled ]];then
    echo -e "Sending to${blue} "$CONTACT"${reset} for user${blue} "$USERS"${reset}:${green} "$SENDTO" ${reset}"
        mail -s "MALWARE SCAN REPORT: "$MAINDOMAIN" "$DATE"" "$CONTACT" < "$TMPLOG"
    else
        echo -e "Send to${blue} "$CONTACT"${reset} for user${blue} "$USERS"${reset}:${red} "$SENDTO" ${reset}\n"
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
			HOSTINGPANEL=$(echo "cPanel/WHM" $(cat /usr/local/cpanel/version))
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
	printf "Malware scan result logfile:${light_cyan} "$LOGFILE" ${reset}\n"
}

# cpanel mode process
function cpanel_mode_process {
print_scan_result
LIMIT="$TOTAL_MALICIOUS"
imunify-antivirus malware malicious list|grep "$SCANID"|awk '{print $13}'|egrep -v "USERNAME"|sort|uniq|while read USERS;do
        MAINDOMAIN=$(grep "/$USERS/" /etc/userdatadomains|grep "=main="|cut -d"=" -f7)
        OWNER=$(grep "/$USERS/" /etc/userdatadomains|grep "=main="|cut -d'=' -f3)
        CONTACT=$(grep CONTACTEMAIL /var/cpanel/users/"$USERS"|cut -d"=" -f2|head -n1)
        TOTALMAL=$(imunify-antivirus malware malicious list --limit "$LIMIT"|grep "$SCANID" |grep "$USERS"|wc -l)
        echo "Username        : "$USERS"" > "$TMPLOG"
        echo "Ownership       : "$OWNER"" >> "$TMPLOG"
        echo "Main Domain     : "$MAINDOMAIN"" >> "$TMPLOG"
        echo "Contact Email   : "$CONTACT"" >> "$TMPLOG"
        echo "Total Malicious : Found "$TOTALMAL" malicious file(s)" >> "$TMPLOG"
		echo "How to Clean Up : 1. Lakukan backup data terlebih dahulu sebelum pembersihan malware" >> "$TMPLOG"
		echo "                  2. Tinjau ulang source code:" >> "$TMPLOG"
		echo "                     a. Jika dalam satu file secara keseluruhan merupakan baris program malware" >> "$TMPLOG"
		echo "                        maka bisa langsung dilakukan penghapusan file tersebut." >> "$TMPLOG"
		echo "                     b. Jika dalam satu file terdapat (infeksi) baris program malware" >> "$TMPLOG"
		echo "                        maka cukup lakukan penghapusan baris program tersebut tanpa" >> "$TMPLOG"
		echo "                        harus menghapus satu file atau ganti dengan file original dari situs resmi." >> "$TMPLOG"
		echo "                  3. Kordinasikan dengan tim webdeveloper perihal pembersihan malware." >> "$TMPLOG"
		echo "                  4. Permbersihan malware tersebut di luar support kami, apabila tidak" >> "$TMPLOG"
		echo "                     menggunakan layanan profesional web kami." >> "$TMPLOG"
		echo "                  5. Informasi perihal layanan profesional web, mulai dari pembuatan," >> "$TMPLOG"
		echo "                     pengembangan, pemeliharaan web. Silahkan bisa menghubungi adit[at]chrootid.com" >> "$TMPLOG"
		echo "Note            : Firewall AntiVirus akan melakukan 'lock file permission' secara otomatis" >> "$TMPLOG"
		echo "                  apabila belum melakukan permbersihan lebih dari 6 jam setelah email ini dikirimkan" >> "$TMPLOG"
		echo "                  guna menghindari infeksi malware/virus yang lebih meluas," >> "$TMPLOG"
		echo "                  Silahkan rikues 'unlock file permission', kirimkan melalui email ke alamat" >> "$TMPLOG"
		echo "                  $EMAIL apabila ingin langsung melakukan pembersihan malware." >> "$TMPLOG"
        if [[ "$MODE" -eq 1 ]];then # ls
            echo -e "Location: \t\t\t Type:" > "$TMPLOG2"
            imunify-antivirus malware malicious list --user "$USERS" --limit "$LIMIT"|grep "$SCANID"|awk '/True/ {print $4"\t\t\t"$12}' |sort >> "$TMPLOG2"
        elif [[ "$MODE" -eq 2 ]];then # chmod ls
            echo -e "Location: \t\t\t Type:" > "$TMPLOG2"
            imunify-antivirus malware malicious list --user "$USERS" --limit "$LIMIT"|grep "$SCANID"|awk '/True/ {print $4"\t\t\t"$12}' |sort >> "$TMPLOG2"
            imunify-antivirus malware malicious list --user "$USERS" --limit "$LIMIT"|grep "$SCANID"|awk '/True/ {print $4}'|sort|uniq|while read LIST;do
			# if malware file still exist, then change its file permission
            if [ -f "$LIST" ];then
                chmod 000 "$LIST"
            fi
            done
        elif [[ "$MODE" -eq 3 ]];then # chmod chattr ls
            echo -e "Location: \t\t\t Type:" > "$TMPLOG2"
            imunify-antivirus malware malicious list --user "$USERS" --limit "$LIMIT"|grep "$SCANID"|awk '/True/ {print $4"\t\t\t"$12}'|sort >> "$TMPLOG2"
            imunify-antivirus malware malicious list --user "$USERS" --limit "$LIMIT"|grep "$SCANID"|awk '/True/ {print $4}'|sort|uniq|while read LIST;do
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
echo -e "Malware scan result logfile:${light_cyan} "$LOGFILE" ${reset}\n"
}

# print scan result
function print_scan_result {
	echo "Hostname        : "$HOSTNAME"" > "$LOGFILE"
	echo "OS              : "$OPERATINGSYSTEM"" >> "$LOGFILE"
	echo "Hosting Panel   : "$HOSTINGPANEL"" >> "$LOGFILE"
	echo "Started         : $(date --date=@"$STARTED")" >> "$LOGFILE"
	echo "Completed       : $(date --date=@"$COMPLETED")" >> "$LOGFILE"
	echo "Duration        : "$DURATION"" >> "$LOGFILE"
	echo "Error           : "$ERROR"" >> "$LOGFILE"
	echo "Path            : "$PATHSCAN"" >> "$LOGFILE"
	echo "Scan Type       : "$SCAN_TYPE"" >> "$LOGFILE"
	echo "Scan ID         : "$SCANID"" >> "$LOGFILE"
	echo "Total Scanned   : "$TOTAL" file[s]" >> "$LOGFILE"
	echo "Total File      : "$TOTAL_FILES" file[s]" >> "$LOGFILE"
	echo "Total Malicious : Found "$TOTAL_MALICIOUS" malicious file[s]" >> "$LOGFILE"
	echo "Action Mode     : "$MESSAGE"" >> "$LOGFILE"
	echo "Log File        : "$LOGFILE"" >> "$LOGFILE"
	echo "" >> "$LOGFILE"
}

# MODE action
function mode_action {
	LIMIT="$TOTAL_MALICIOUS"
	imunify-antivirus malware malicious list|grep "$SCANID"|awk '{print $13}'|egrep -v "USERNAME"|sort|uniq|while read USERS;do
	echo "Username        : "$USERS"" > "$TMPLOG"
	message_tips
	if [[ "$MODE" -eq 1 ]];then # ls
		echo -e "Location: \t\t\t Type:" > "$TMPLOG2"
		imunify-antivirus malware malicious list --user "$USERS" --limit "$LIMIT"|grep "$SCANID"|grep True|awk '{print $4"\t\t\t"$12}' |sort >> "$TMPLOG2"
	elif [[ "$MODE" -eq 2 ]];then # chmod ls
		echo -e "Location: \t\t\t Type:" > "$TMPLOG2"
		imunify-antivirus malware malicious list --user "$USERS" --limit "$LIMIT"|grep "$SCANID"|grep True|awk '{print $4"\t\t\t"$12}' |sort >> "$TMPLOG2"
		imunify-antivirus malware malicious list --user "$USERS" --limit "$LIMIT"|grep "$SCANID"|grep True|awk '{print $4}'|sort|uniq|while read LIST;do
			if [ -f "$LIST" ];then
				chmod 000 "$LIST"
			fi
		done
	elif [[ "$MODE" -eq 3 ]];then # chmod chattr ls
		echo -e "Location: \t\t\t Type:" > "$TMPLOG2"
		imunify-antivirus malware malicious list --user "$USERS" --limit "$LIMIT"|grep "$SCANID"|grep True|awk '{print $4"\t\t\t"$12}'|sort >> "$TMPLOG2"
		imunify-antivirus malware malicious list --user "$USERS" --limit "$LIMIT"|grep "$SCANID"|grep True|awk '{print $4}'|sort|uniq|while read LIST;do
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
echo "     3 = chmod 000 && chattr +i    change permission malicious files to 000 and change the attribute to immutable"
echo "-p, --path=[PATH]                  scan directory, default value is /home*/*"
echo "-h, --help                         show usage information"
echo ""
echo "Example:"
echo "$0 --email=youremail@address.com --mode=1 --path=/home/"
echo "$0 -e=your@email.com -m=1 -p=/home/"
}

clear
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
	printf "${red}"$SCANDIR"${reset}: not found\n"
	usage
	exit	
fi

# os validation check
echo -n "Checking Operating System:"
if [[ -f /usr/bin/hostnamectl ]];then
	OPERATINGSYSTEM=$(/usr/bin/hostnamectl|grep "Operating System"|cut -d: -f2|awk '{print $1}')
	if [[ "$OPERATINGSYSTEM" == 'CloudLinux' ]] || [[ "$OPERATINGSYSTEM" == 'CentOS' ]] || [[ "$OPERATINGSYSTEM" == 'Red' ]];then
		echo -e "${green} $(/usr/bin/hostnamectl|grep "Operating System"|cut -d: -f2) ${reset}"
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
		echo -e "${green} $(/usr/bin/hostnamectl|grep "Operating System"|cut -d: -f2) ${reset}"
		
	fi
elif [[ -f /etc/redhat-release ]];then
	OPERATINGSYSTEM=$(cat /etc/redhat-release|awk '{print 1}')
	if [[ "$OPERATINGSYSTEM" == 'CloudLinux' ]] || [[ "$OPERATINGSYSTEM" == 'CentOS' ]];then
		echo -e "${green} $(cat /etc/redhat-release|awk '{print 1}') ${reset}"
		PACKAGEMANAGER=/bin/rpm
	fi
else
	printf "${red} "$OPERATINGSYSTEM" ${reset}\n"
	printf "ImunifyAVX: ${red}FAILED${reset}\n"
	echo "Unsupported yet"
	exit
fi

# require mailx
echo -n "Checking mailx: "
if [[ "$OPERATINGSYSTEM" == 'CloudLinux' ]] || [[ "$OPERATINGSYSTEM" == 'CentOS' ]] || [[ "$OPERATINGSYSTEM" == 'Red' ]];then
RPMMAILX=$("$PACKAGEMANAGER" -qa|grep mailx|cut -d- -f1|head -n1)
	if [[ "$RPMMAILX" != "mailx" ]];then
		echo -e "${red}FAILED ${reset}"
		echo -e "mail command not found:${yellow} installing mailx${reset}"
		yum install -y mailx
		echo -e "Checking mailx: ${green}OK ${reset}"
	else
		echo -e "${green}OK ${reset}"
	fi
elif [[ "$OPERATINGSYSTEM" == 'Ubuntu' ]] || [[ "$OPERATINGSYSTEM" == 'Debian' ]];then
RPMMAILX=$("$PACKAGEMANAGER" -l|grep mailx)
	if [[ -z "$RPMMAILX" ]];then
		echo -e "${red}FAILED ${reset}"
		echo -e "mail command not found:${yellow} installing mailx${reset}"
		apt install -y mailx
		echo -e "Checking mailx: ${green}OK ${reset}"
	else
		echo -e "${green}OK ${reset}"
	fi
fi
 
# user check
echo -n "Checking user: "
if [[ $(id -u) -ne 0 ]];then
    echo -e "${red}FAILED ${reset}"
    echo -e "Require root priviledge. Please try 'sudo su' or 'su -u root' and try again."
    exit
else
    echo -e "${green}OK ${reset}"
fi

# imunifyav check
echo -n "Checking imunifyav: "
if [[ ! -f /usr/bin/imunify-antivirus ]];then
    echo -e "${red}FAILED ${reset}"
    echo -e "ImunifyAV was not installed"
    echo -e "checking system requirement before imunifyav installation"
    FREESPACE=$(expr $(df /home|awk 'NR==2 {print $4}') / 1000000)
    MEMORY=$(free -m|awk 'NR==2 {print $2}')
    if [[ ${FREESPACE/.*} -ge 21 ]] && [[ "$MEMORY" -ge 512 ]];then
        echo "starting imunifyav installation"
        wget https://repo.imunify360.cloudlinux.com/defence360/imav-deploy.sh -O /root/imav-deploy.sh
        bash /root/imav-deploy.sh
        if [[ -f /usr/bin/imunify-antivirus ]];then
            echo -e "checking imunifyav:${green} OK${reset}"
        else
            echo -e "checking imunifyav:${red} FAILED${reset}"
            exit 
        fi
    else
        echo -e "ImunifyAV installation:${red} FAILED${reset}"
        echo -e "Minimum Hardware Requirements"
        echo -e "RAM:${green} 512 MB${reset}"
        echo -e "Storage:${green} 20 GB ${reset}available disk space"
		echo ""
        echo -e "Your $HOSTNAME server hardware spec"
        if [[ "$MEMORY" -lt 512 ]];then
            echo -e "RAM:${red} "$MEMORY" MB${reset}"
        elif [[ "$MEMORY" -ge 512 ]];then
            echo -e "RAM:${green} "$MEMORY" MB${reset}"
        fi
        if [[ ${FREESPACE/.*} -lt 21 ]];then
            echo -e "Storage:${red} "$FREESPACE" GB ${reset}available disk space"
        elif [[ ${FREESPACE/.*} -ge 21 ]];then
            echo -e "Storage:${green} "$FREESPACE" GB ${reset}available disk space"
        fi
        exit
    fi
elif [[ -f /usr/bin/imunify-antivirus ]];then
	if [[ -f /bin/systemctl ]];then
		SYSSTATUS=$(systemctl status imunify-antivirus|grep Active|cut -d: -f2|awk '{print $1}')
		if [[ "$SYSSTATUS" == "inactive" ]];then
			/bin/systemctl start imunify-antivirus
			echo -e "${green}OK ${reset}"
		elif [[ "$SYSSTATUS" == "active" ]];then
			echo -e "${green}OK ${reset}"
		fi
	elif [[ -f /sbin/service ]];then
		SYSSTATUS=$(/sbin/service imunify-antivirus status|cut -d. -f1|awk '{print $5}')
		if [[ "$SYSSTATUS" == "running" ]];then
			printf "${green}OK ${reset}"
		elif [[ "$SYSSTATUS" != "running" ]];then
			/sbin/service imunify-antivirus start
			echo -e "${green}OK ${reset}"
		fi
	fi
fi

# signature update process
echo -e "ImunifyAV signatures: ${yellow}updating ${reset}"
echo -e " geo:${green} $(imunify-antivirus update geo) ${reset}"
echo -e " rules:${green} $(imunify-antivirus update modsec-rules) ${reset}"
echo -e " sigs:${green} $(imunify-antivirus update sigs) ${reset}"
echo -e " static whitelist:${green} $(imunify-antivirus update static-whitelist) ${reset}"
echo -e " eula:${green} $(imunify-antivirus update eula) ${reset}"
echo -e " ip-record:${green} $(imunify-antivirus update ip-record) ${reset}"
echo -e " sigs-php:${green} $(imunify-antivirus update sigs-php) ${reset}"
echo -e " ossecp:${green} $(imunify-antivirus update ossec) ${reset}"
echo -e "ImunifyAV signatures: ${green}update completed ${reset}"

# scan process
STATUS=$(imunify-antivirus malware on-demand status|grep status|awk '{print $2}')
if [[ "$STATUS" == "stopped" ]];then
	echo -e "ImunifyAV on-demand scan:${red} "$STATUS" ${reset}"
	printf "Starting ImunifyAV on-demand scan: ${green}"
    imunify-antivirus malware on-demand start --path="$SCANDIR"
	printf "${reset}"
    SCANID=$(imunify-antivirus malware on-demand status|awk '/scanid/ {print $2}')
    STATUS=$(imunify-antivirus malware on-demand status|awk '/status/ {print $2}')
    status_check
	load_scan_result
    if [[ "$TOTAL_MALICIOUS" -gt "0" ]];then
		echo -e "Found ${red}"$TOTAL_MALICIOUS"${reset} malware file(s)"
		scan_duration
        mode_options
    else
		echo -e "${green}Clean${reset}: malware not found"
    fi
elif [[ "$STATUS" == "running" ]];then
	echo -e "${yellow}WARNING${reset}: On-demand scan is already ${yellow}running${reset}"
	exit
else
    echo "ImunifyAV on-demand scan: "$STATUS""|mail -s "MALWARE SCAN FAILED: ["$HOSTNAME"] "$DATE"" "$EMAIL"
    exit
fi
 
# log rotate
if [[ -f "$LOGFILE" ]];then
	TOTAL_LOG=$(ls /var/log/imunifyav-*.txt|wc -l)
	if [[ "$TOTAL_LOG" -gt "$LOGROTATE" ]];then
		DELETELOG=$(expr "$TOTAL_LOG" - "$LOGROTATE")
		ls /var/log/imunifyav-*.txt|sort|head -n "$DELETELOG"|while read DELETE;do
			if [ -f "$DELETE" ];then
				rm -f "$DELETE";
			fi
		done 
	fi
fi