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

