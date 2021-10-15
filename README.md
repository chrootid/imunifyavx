# imunifyavx
ImunifyAVX is a malware scanner tools powered by ImunifyAV with some additional features

# Supported OS
1. Stand Alone
- Ubuntu 18.04 LTS 64 bit
2. cPanel/WHM
- CentOS 6.x / 7.x 64 bit
- CloudLinux 6.x / 7.x 64 bit

# Requirements
1. root priviledge
2. mailx
3. imunifyav

# Features
1. Mailware scan report and notification for server admin or hosting user
2. Provide action mode option for malware scan result
- ls; for suspicuous list
- chmod 000; ls; change permission to 000 for suspicious list
- chmod 000; chattr +i; ls; change permission to 000 and mute it for suspicious list.

# Download
```
# sudo git clone https://github.com/chrootid/imunifyavx
# cd imunifyavx   
# sudo bash imunifyavx.sh
```

# Usage
```
# bash imunifyavx.sh --help
USAGE: imunifyavx.sh --email=[EMAIL ADDRESS] --mode=[ACTION MODE] --path=[PATH]

-e, --email=[EMAIL ADDRESS]        send malware scan report to an email address
-m, --mode=[ACTION MODE]           default value is 1 (list only)
     1 = ls                        only for print malicious file list
     2 = chmod 000                 change permission malicious file(s) to 000
     3 = chmod 000 && chattr +i    change permission malicious file(s) to 000 and attribute to immutable
-r, --report                       send malware scan report to user contact mail
-p, --path=[PATH]                  scan directory, default value is /home*/*
-h, --help                         show usage information

Example:
bash imunifyavx.sh --report --email=youremail@address.com --mode=2 --path=/home/
bash imunifyavx.sh -r -e=your@email.com -m=2 -p=/home/
```

# Command Usage Output
```
# sudo bash imunifyavx.sh --email=sysadmin@server.com --mode=2 --path=/home/user01/public_html/
Checking for Operating System  : CentOS Linux 7 (Core)
Checking for mailx             : OK
Checking for user              : OK
Checking for imunifyav         : OK
Checking for signatures update : Updating
   sigs: OK
   eula: OK
Checking for signatures update : Done
On-demand scan status          : stopped
Starting on-demand scan        : OK
On-demand scan status          : running - stopped
On-demand scan status          : completed
On-demand scan result          : Found 841 suspicious file(s)
On-demand scan report for user : user01 to user1@webdomain1.com was disabled
On-demand scan report          : sysadmin@server.com
ImunifyAVX log file            : /var/log/imunifyavx-2021-10-15.txt
```

# Sample Output
```
# sudo more /var/log/imunifyavx-2021-10-15.txt
Hostname        : server.hostdomain.com
OS              : CentOS Linux 7 (Core)
Hosting Panel   : cPanel/WHM 11.98.0.8
Started         : Fri Oct 15 20:56:32 WIB 2021
Completed       : Fri Oct 15 20:57:27 WIB 2021
Duration        : 55 second[s]
Error           : None
Path            : /home/user01/public_html/
Scan Type       : on-demand
Scan ID         : cd7c575bef2e448bbae5e4b4ffc52b53
Total Scanned   : 6096 file[s]
Total File      : 6096 file[s]
Total Malicious : Found 841 malicious file[s]
Action Mode     : chmod 000
Log File        : /var/log/imunifyavx-2021-10-15.txt

Username        : user01
Ownership       : root
Main Domain     : webdomain1.com
Contact Email   : user@webdomain.com
Total Malicious : Found 22 malicious file(s)
Location:                                                                             Type:
/home/user01/public_html/00x.html                                                   SMW-SA-16489-php.deface.gen-14
/home/user01/public_html/0256-12.pdf                                                SMW-INJ-13278-php.tool.upld-29
/home/user01/public_html/0337-12.pdf                                                SMW-INJ-13278-php.tool.upld-29
/home/user01/public_html/0752keyloger.jpg                                           SMW-SA-04961-php.bkdr.wshll-14
/home/user01/public_html/1.html                                                     SMW-INJ-13278-php.tool.upld-29
/home/user01/public_html/1.php.html                                                 SMW-INJ-13278-php.tool.upld-29
/home/user01/public_html/20190429161937-zero.jpg                                    SMW-SA-18937-php.bkdr.wshll-3
/home/user01/public_html/20190615162420-marijuana.pdf                               SMW-SA-12880-mlw.wshell-2
/home/user01/public_html/20190615162450-marijuana.php.pdf                           SMW-SA-12880-mlw.wshell-2
/home/user01/public_html/20190926005054-1337.php.pdf                                SMW-SA-16521-html.deface.gen-2
/home/user01/public_html/20190926010612-mini.pdf                                    SMW-SA-05636-mlw.wshll-11
/home/user01/public_html/20190926011026-root.pdf                                    SMW-SA-17668-php.bkdr.upldr-1
/home/user01/public_html/20201003112037-0.pdf                                       SMW-SA-16855-php.bkdr.wshll-3
/home/user01/public_html/20201003112133-0.jpg                                       SMW-SA-16855-php.bkdr.wshll-3
/home/user01/public_html/20201003112207-0.jpg                                       SMW-SA-16855-php.bkdr.wshll-3
/home/user01/public_html/20201003112237-0.jpg                                       SMW-SA-16855-php.bkdr.wshll-3
/home/user01/public_html/20201003112357-0.jpg                                       SMW-SA-16855-php.bkdr.wshll-3
/home/user01/public_html/23701-2019-05-25-17-00-26.php                              SMW-SA-04812-mlw.wshll-3
/home/user01/public_html/2-factor_verification_confirm.php                          SMW-SA-15878-html.phish.gen-11
/home/user01/public_html/2-factor_verification.php                                  SMW-SA-15878-html.phish.gen-11
/home/user01/public_html/403.php                                                    SMW-INJ-13278-php.tool.upld-29
/home/user01/public_html/5902-12.pdf                                                SMW-INJ-13278-php.tool.upld-29
```