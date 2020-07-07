# imunifyavx
ImunifyAV merupakan tools atau script versi free yang dikembangkan oleh CloudLinux yang bertujuan untuk melakukan pengecekan/pencarian (scanning) dan pembersihan (cleaning) file malware pada setiap aplikasi website berbasis php, seperti CMS wordpress, joomla, drupal atau CMS berbasis php semisalnya.
Versi free memiliki keterbatasan fitur yang disediakan oleh pengembang yang terbatas pada proses scanning malware serta menampilkan hasil dari scanning malware tersebut, tanpa adanya action atau eksekusi atas hasil file malware yang telah ditemukan tersebut. Namun pengembang menyediakan fitur cli (command line interface) untuk memudahkan interaksi penggunaan ImunifyAV melalui console/terminal. Dengan adanya cli tersebut, maka keterbatasan fitur versi free bisa dikembangkan kembali tanpa harus melakukan modifikasi kode sumbernya secara langsung. Dalam hal ini, penggunaan bash/shell script dengan ImunifyAV cli bisa dikombinasikan untuk pengembangan fitur anti malware scanner lebih jauh.

# Supported OS
1. Stand Alone
- Ubuntu 18.04 LTS
2. cPanel/WHM
- CentOS 6.x / 7.x
- CloudLinux 6.x / 7.x

# Requirements
1. mailx
2. imunifyav

# Features
1. Notifikasi hasil scan malware melalui email.
2. Action mode untuk proses eksekusi terhadap file malware. Saat ini terdapat tiga opsi
- Listing: untuk list file file malware hasil scan. 
- Chmod + Listing: perubahan permission setiap file malware menjadi 000 (chmod 000 $LIST), kemudian dilakukan listing.
- Chmod + chattr + Listing: Perubahan permission setiap file malware , muted permission (chattr +i) file malware tersebut, kemudian dilakukan listing.

# Download
Proses download script bisa langsung melalui terminal/console dengan menggunakan command wget sebagai berikut.
```
wget repo.chrootid.com/imunifyav.sh && bash imunifyav.sh
```

# Usage
`imunifyav.sh --help`

```
USAGE: imunifyav.sh --email=[EMAIL ADDRESS] --mode=[ACTION MODE] --p=[PATH]
-e, --email=[EMAIL ADDRESS]        sending malware scan report to an email address
-m, --mode=[ACTION MODE]           default value is 1
     1 = ls                        only for print malicious file list
     2 = chmod 000                 change permission malicious files to 000
     3 = chmod 000 && chattr +i    change permission malicious files to 000 and change the attribute to immutable
-p, --path[PATH]                   scan directory, default value is /home*/*
-h, --help                         show usage information
Example:
imunifyav.sh --email=youremail@address.com --mode=1 --p=/home/
imunifyav.sh -e=your@email.com -m=1 -p=/home/
```
