# 3.9_1
# 1,2
Зарегистрировался в BitWarden, подключил Google Authenticator
![image](https://user-images.githubusercontent.com/97126500/154990662-c612e22a-ed51-4a0d-a754-2907436bb797.png)
# 3
Сгенерировал самоподписанный сертификат, настроил apache2
![image](https://user-images.githubusercontent.com/97126500/154997681-79ee6721-a83a-4bf3-8b8a-6ff9cb4c1c90.png)
# 4
Проверил сайт bioreformed.ru
```
pashi@pashi-ub2004-test:/etc/apache2/conf-enabled/testssl.sh$ ./testssl.sh -U --sneaky https://bioreformed.ru

###########################################################
    testssl.sh       3.1dev from https://testssl.sh/dev/
    (7b38198 2022-02-17 09:04:23 -- )

      This program is free software. Distribution and
             modification under GPLv2 permitted.
      USAGE w/o ANY WARRANTY. USE IT AT YOUR OWN RISK!

       Please file bugs @ https://testssl.sh/bugs/

###########################################################

 Using "OpenSSL 1.0.2-chacha (1.0.2k-dev)" [~183 ciphers]
 on pashi-ub2004-test:./bin/openssl.Linux.x86_64
 (built: "Jan 18 17:12:17 2019", platform: "linux-x86_64")


Testing all IPv4 addresses (port 443): 90.156.201.107 90.156.201.113 90.156.201.53 90.156.201.108
--------------------------------------------------------------------------------------------------------------------------------------------------------------
 Start 2022-02-21 20:06:30        -->> 90.156.201.107:443 (bioreformed.ru) <<--

 Further IP addresses:   90.156.201.113 90.156.201.53 90.156.201.108 2a00:15f8:a000:5:1:13:2:7ea2 2a00:15f8:a000:5:1:14:2:7ea2 2a00:15f8:a000:5:1:11:2:7ea2 2a00:15f8:a000:5:1:12:2:7ea2
 rDNS (90.156.201.107):  fe.shared.masterhost.ru.
 Service detected:       HTTP


 Testing vulnerabilities

 Heartbleed (CVE-2014-0160)                not vulnerable (OK), no heartbeat extension
 CCS (CVE-2014-0224)                       not vulnerable (OK)
 Ticketbleed (CVE-2016-9244), experiment.  not vulnerable (OK), no session ticket extension
 ROBOT                                     not vulnerable (OK)
 Secure Renegotiation (RFC 5746)           OpenSSL handshake didn't succeed
 Secure Client-Initiated Renegotiation     not vulnerable (OK)
 CRIME, TLS (CVE-2012-4929)                not vulnerable (OK)
 BREACH (CVE-2013-3587)                    potentially NOT ok, "gzip" HTTP compression detected. - only supplied "/" tested
                                           Can be ignored for static pages or if no secrets in the page
 POODLE, SSL (CVE-2014-3566)               not vulnerable (OK)
 TLS_FALLBACK_SCSV (RFC 7507)              Downgrade attack prevention supported (OK)
 SWEET32 (CVE-2016-2183, CVE-2016-6329)    VULNERABLE, uses 64 bit block ciphers
 FREAK (CVE-2015-0204)                     not vulnerable (OK)
 DROWN (CVE-2016-0800, CVE-2016-0703)      not vulnerable on this host and port (OK)
                                           make sure you don't use this certificate elsewhere with SSLv2 enabled services
                                           https://censys.io/ipv4?q=5F715E6ED99703667BD62546A7076BFAE73FF237E8358D74A7F54E48327E6A88 could help you to find out
 LOGJAM (CVE-2015-4000), experimental      not vulnerable (OK): no DH EXPORT ciphers, no common prime detected
 BEAST (CVE-2011-3389)                     TLS1: ECDHE-RSA-AES128-SHA ECDHE-RSA-AES256-SHA DHE-RSA-AES128-SHA DHE-RSA-AES256-SHA ECDHE-RSA-DES-CBC3-SHA EDH-RSA-DES-CBC3-SHA AES128-SHA AES256-SHA DES-CBC3-SHA
                                           VULNERABLE -- but also supports higher protocols  TLSv1.1 TLSv1.2 (likely mitigated)
 LUCKY13 (CVE-2013-0169), experimental     potentially VULNERABLE, uses cipher block chaining (CBC) ciphers with TLS. Check patches
 Winshock (CVE-2014-6321), experimental    not vulnerable (OK)
 RC4 (CVE-2013-2566, CVE-2015-2808)        no RC4 ciphers detected (OK)


 Done 2022-02-21 20:07:02 [  33s] -->> 90.156.201.107:443 (bioreformed.ru) <<--

--------------------------------------------------------------------------------------------------------------------------------------------------------------
```
Найдены уязвимости.

# 5
Сгенерировал ключ, скопировал на другой сервер, зашёл без ввода пароля
```
pashi@pashi-ub2004-test2:~$ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/pashi/.ssh/id_rsa):
Created directory '/home/pashi/.ssh'.
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in /home/pashi/.ssh/id_rsa
Your public key has been saved in /home/pashi/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:u16FKweG4U4hzhLDfDon4BfMESfO2FL9gQfzZPtA3jU pashi@pashi-ub2004-test2
The key's randomart image is:
+---[RSA 3072]----+
|   =o+o+   E     |
| oO +oBoo . .    |
|.o=Bo ==..       |
|...B.o =o  .     |
| .=.+ + S.. .    |
|  .= o . o o     |
|      . o +      |
|         =       |
|       .o        |
+----[SHA256]-----+
pashi@pashi-ub2004-test2:~$ ssh-copy-id pashi@10.1.4.94
/usr/bin/ssh-copy-id: INFO: Source of key(s) to be installed: "/home/pashi/.ssh/                                                                                                                                                             id_rsa.pub"
The authenticity of host '10.1.4.94 (10.1.4.94)' can't be established.
ECDSA key fingerprint is SHA256:S2In1C0Bnx+dLa8QocYmuPj5IuHtC11jb8iRtlvl6AE.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
/usr/bin/ssh-copy-id: INFO: attempting to log in with the new key(s), to filter                                                                                                                                                              out any that are already installed
/usr/bin/ssh-copy-id: INFO: 1 key(s) remain to be installed -- if you are prompt                                                                                                                                                             ed now it is to install the new keys
pashi@10.1.4.94's password:

Number of key(s) added: 1

Now try logging into the machine, with:   "ssh 'pashi@10.1.4.94'"
and check to make sure that only the key(s) you wanted were added.

pashi@pashi-ub2004-test2:~$ ssh pashi@10.1.4.94
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.13.0-28-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

5 updates can be applied immediately.
1 of these updates is a standard security update.
To see these additional updates run: apt list --upgradable

Your Hardware Enablement Stack (HWE) is supported until April 2025.
*** System restart required ***
Last login: Thu Feb 17 19:17:54 2022 from 10.1.4.162
pashi@pashi-ub2004-test:~$ exit
logout
Connection to 10.1.4.94 closed.
pashi@pashi-ub2004-test2:~$
```
# 6
Переименовал файлы ключей, настроил `config` для доступо по `ssh` по имени сервера
```
pashi@pashi-ub2004-test2:~/.ssh$ ls
id_rsa  id_rsa.pub  known_hosts
pashi@pashi-ub2004-test2:~/.ssh$ mv id_rsa id_rsa_new
pashi@pashi-ub2004-test2:~/.ssh$ mv id_rsa
id_rsa_new  id_rsa.pub
pashi@pashi-ub2004-test2:~/.ssh$ mv id_rsa
id_rsa_new  id_rsa.pub
pashi@pashi-ub2004-test2:~/.ssh$ mv id_rsa.pub id_rsa.pub_new
pashi@pashi-ub2004-test2:~/.ssh$ ll
total 20
drwx------ 2 pashi pashi 4096 Feb 22 10:51 ./
drwxr-xr-x 4 pashi pashi 4096 Feb 22 10:37 ../
-rw------- 1 pashi pashi 2610 Feb 22 10:37 id_rsa_new
-rw-r--r-- 1 pashi pashi  578 Feb 22 10:37 id_rsa.pub_new
-rw-r--r-- 1 pashi pashi  222 Feb 22 10:40 known_hosts
pashi@pashi-ub2004-test2:~/.ssh$ touch config
pashi@pashi-ub2004-test2:~/.ssh$ cat config
Host TEST2
        HostName 10.1.4.94
        IdentityFile ~/.ssh/id_rsa_new
        User pashi
pashi@pashi-ub2004-test2:~/.ssh$ ssh TEST2
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.13.0-28-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

5 updates can be applied immediately.
1 of these updates is a standard security update.
To see these additional updates run: apt list --upgradable

Your Hardware Enablement Stack (HWE) is supported until April 2025.
*** System restart required ***
Last login: Tue Feb 22 13:41:08 2022 from 10.1.4.81
pashi@pashi-ub2004-test:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: ens160: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:0c:29:ab:0f:7e brd ff:ff:ff:ff:ff:ff
    altname enp3s0
    inet 10.1.4.94/24 brd 10.1.4.255 scope global dynamic noprefixroute ens160
       valid_lft 64488sec preferred_lft 64488sec
    inet6 fe80::8042:b022:3eda:816f/64 scope link noprefixroute
       valid_lft forever preferred_lft forever
4: dummy5: <BROADCAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN group default qlen 1000
    link/ether be:54:d9:53:7e:62 brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.1/24 scope global dummy5
       valid_lft forever preferred_lft forever
    inet6 fe80::bc54:d9ff:fe53:7e62/64 scope link
       valid_lft forever preferred_lft forever
pashi@pashi-ub2004-test:~$ exit
logout
Connection to 10.1.4.94 closed.
pashi@pashi-ub2004-test2:~/.ssh$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: ens160: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:0c:29:6e:59:a0 brd ff:ff:ff:ff:ff:ff
    inet 10.1.4.81/24 brd 10.1.4.255 scope global dynamic ens160
       valid_lft 73449sec preferred_lft 73449sec
    inet6 fe80::20c:29ff:fe6e:59a0/64 scope link
       valid_lft forever preferred_lft forever
pashi@pashi-ub2004-test2:~/.ssh$
```
# 7
Собрал дамп по 22 порту
```
pashi@pashi-ub2004-test:~$ sudo tcpdump -c 100 -i ens160 -nn -s0 -v port 22 -w /home/pashi/test.pcap
tcpdump: listening on ens160, link-type EN10MB (Ethernet), capture size 262144 bytes
100 packets captured
158 packets received by filter
0 packets dropped by kernel
```
![image](https://user-images.githubusercontent.com/97126500/155121498-71edb800-8c80-48cc-8ce3-dae6acb839ef.png)
