#!/usr/bin/env perl


########################################################################################################
## Tenable checks and writes a detailed report
##
##Version 1.0
##Version 2.0 FIX AFTER's
#
#########################################################################################################

use strict;
use warnings;
use Data::Dumper;
use FindBin qw($Bin);

umask 0077;

my $OS = `uname`;
my $hostname = `hostname`;
chomp ($OS, $hostname);

my ($sec,$min,$hour,$day,$month,$year) = localtime(time);
$year += 1900;
$month++;

foreach my $part ($sec, $min, $hour, $day, $month) {
    if ($part < 10){
        $part = "0$part";
    }
}

my $compliance = '/root/compliance/';
`mkdir -p /root/compliance/` unless (-d $compliance);
my $REPORT = $compliance.$hostname."_Comp_Report_"."$month$day$year".".txt";
my $emp_accounts_file = $compliance."EmptyPasswordAccounts.txt";
my $regex_file = $compliance."regex_info.txt";
my $exclude_list = '/opt/scripts/sudo/monitor/exclude_list';
my $cksum;

if ($OS eq 'Linux') {
    chomp($cksum = `md5sum /opt/scripts/sudo/monitor/compliance_report.pl | awk '{print \$1}'`);
} elsif($OS eq 'AIX') {
    chomp($cksum = `csum -h MD5 /opt/scripts/sudo/monitor/compliance_report.pl | awk '{print \$1}'`);
}

open (LOG, "+>$REPORT") or die ("Unable to open file $REPORT: $!");
open(REGEX, "+>$regex_file") or die ("Unable to open file $regex_file : $!");
print LOG "\n\t\t\t\t\t\tBuild Compliance Report for $hostname : ENV $OS : MD5 Hash $cksum \t \t \n\n";
print "\n\t\t\t\t\t\tBuild Compliance Report for $hostname : ENV $OS : MD5 Hash $cksum\t \t \n\n\n";

open(EMP, "+>$emp_accounts_file") or die ("Unable to open file $emp_accounts_file: $!");

if ($OS eq 'Linux') {

    chomp (my $release = `cat /etc/redhat-release | awk '{print \$7}' | awk -F. '{print \$1}'`);

    check_on_file("^ *[^#]*Protocol *", 'Protocol 2$', "/etc/ssh/ssh_config", "Protocol is set to 2 for client");
    check_on_file("^ *[^#]*Protocol *", 'Protocol 2$', "/etc/ssh/sshd_config", "Protocol is set to 2 for server");
    check_on_file('PubkeyAuthentication', 'PubkeyAuthentication[\s|\t]*yes[\s|\t]*$', '/etc/ssh/ssh_config', 'PubkeyAuthentication is set to \'yes\' for client' );
    check_on_file('PubkeyAuthentication', 'PubkeyAuthentication[\s|\t]*yes[\s|\t]*$', '/etc/ssh/sshd_config', 'PubkeyAuthentication is set to \'yes\' for server' );
    check_on_file('LogLevel', 'LogLevel[\s|\t]*(VERBOSE)[\s|\t]*$', "/etc/ssh/sshd_config", 'LogLevel is set to VERBOSE for server' );
    check_on_file('RhostsRSAAuthentication' , 'RhostsRSAAuthentication[\s|\t]*no[\s|\t]*$' , '/etc/ssh/sshd_config', 'RhostsRSAAuthentication is set to \'no\' for server');
    check_on_file('IgnoreRhosts','IgnoreRhosts[\s|\t]*yes[\s|\t]*$','/etc/ssh/sshd_config','IgnoreRhosts is set to \'yes\' for server');
    check_on_file('PermitEmptyPasswords','PermitEmptyPasswords[\s|\t]*no[\s|\t]*$','/etc/ssh/sshd_config','PermitEmptyPasswords is set to \'yes\' server');

#FIX AFTER : File  need to be changed from issue.net to motd
    check_on_file('Banner','Banner[\s|\t]*/etc/motd[\s|\t]*$','/etc/ssh/sshd_config','Checking if Banner is set to \'/etc/issue.net\'');
    #check_on_file('Banner','Banner[\s|\t]*/etc/issue.net[\s|\t]*$','/etc/ssh/sshd_config','Checking if Banner is set to \'/etc/issue.net\'');

#FIX AFTER : Leaving behind the Locked Accounts

    my @ACCOUNTS = `cat /etc/passwd | grep /home | cut -f1 -d ':' | sort`;
    chomp @ACCOUNTS;

    my @EMP_ACCOUNTS;

    foreach my $account (@ACCOUNTS) {

        my $emp_account = `grep "$account" /etc/shadow | egrep '^[^:]+::|^[^:]+:!!:'`;
        chomp $emp_account;

        unless ($emp_account eq ''){

            chomp(my $val = `passwd -S $account | awk '{print \$2}'`);
            chomp(my $emp_regex = `passwd -S $account`);
            unless ($val eq 'LK'){
                print REGEX "Emp password accounts: ",$emp_regex, "\n";
                push (@EMP_ACCOUNTS, $account);
            }
        }
    }

    unless (scalar(@EMP_ACCOUNTS) == 0 ) {
        PRINTME('Accounts With Empty Password Fields NOT EXISTs',"[**FAIL**]");
        foreach my $account (@EMP_ACCOUNTS){
            print EMP "$account \n";
        }
    } else {
        PRINTME( 'Accounts With Empty Password Fields NOT EXISTs', "[PASS]");
    }

    check_on_file('PASS_MAX_DAYS','PASS_MAX_DAYS[\s|\t]*49[\s|\t]*$','/etc/login.defs','Checking that Password Max Days is 49');
    check_on_file('PASS_MIN_DAYS','PASS_MIN_DAYS[\s|\t]*0[\s|\t]*$','/etc/login.defs','Checking that Password Min Days is 0');
    check_on_file('PASS_MIN_LEN','PASS_MIN_LEN[\s|\t]*8[\s|\t]*$','/etc/login.defs','Checking that Password Min LEN is 8');
    check_on_file('PASS_WARN_AGE','PASS_WARN_AGE[\s|\t]*14[\s|\t]*$','/etc/login.defs','Checking that Password Warn Age equals 14');
    check_on_file('FAIL_DELAY','FAIL_DELAY[\s|\t]*5[\s|\t]*$','/etc/login.defs','Checking that Fail Delay equals 5');

    foreach my $service ( qw(amanda auth chargen-dgram chargen-stream cvs daytime-dgram daytime-stream disard-dgram discard-stream echo-dgram echo-stream finger imap imaps ipop2 ipop3 ekrb5-telnet krb5-telnet ktalk ntalk
                             rexec talk tftp time-dgram time-stream uucp)) {

        unless (check_excludelist($service) == 1 ) {
            my $cmd = '/sbin/chkconfig --list | egrep \'\b'.$service.'\b\'';
            my $check = `$cmd`;
            chomp $check;
            #print "\$check => $check \n";
            unless($check){
                print REGEX $check, "\n";
            }
            if ( (grep /[\s|\t]+$service:[\s|\t]+off[\s|\t]*$/, $check) || (!$check) ) {
                PRINTME("Disable $service",  "[PASS]");
            } else {
                PRINTME("Disable $service","[**FAIL**]");
            }
        }
    }

    foreach my $service( qw/bluetooth cupsd cyrus-imapd dovecot lpd mysql named netfs nfs nis postgresql samba snmp sendmail squid vsftp xfs kudzu/) {

        unless (check_excludelist($service) == 1 ) {
            my $check = `/sbin/chkconfig --list | egrep \"^$service | $service | $service\$\"`;
            #my $check = `/sbin/chkconfig --list | egrep \"\\b$service\\b\"`;
            my $rc = $?;
            chomp $check;

            #print REGEX "chkconfig --list | egrep \"$service\\b\" >  ", $check , "\n";
            unless($check){
                print REGEX $check, "\n";
            }
            if ($rc == 0){
                if ( grep /^\b$service\b.*1:off.*2:off.*3:off.*4:off.*5:off.*$/, $check) {
                    PRINTME("Disable $service",  "[PASS]");
                } else {
                    PRINTME("Disable $service","[**FAIL**]");
                }
            } else {
                PRINTME("Disable $service", "[PASS]");
            }
        }
    }

    check_on_file('net.ipv4.tcp_syncookies','^[\s|\t]*net.ipv4.tcp_syncookies[\s|\t]*=[\s|\t]*1.*$','/etc/sysctl.conf','Checking that net.ipv4.tcp_syncookies is set to \'1\'');
    check_on_file('net.ipv4.conf.all.rp_filter','^[\s|\t]*net.ipv4.conf.all.rp_filter[\s|\t]*=[\s|\t]*1.*$','/etc/sysctl.conf','Checking that net.ipv4.conf.all.rp_filter is set to \'1\'');
    check_on_file('net.ipv4.conf.all.accept_source_route','^[\s|\t]*net.ipv4.conf.all.accept_source_route[\s|\t]*=[\s|\t]*0.*$','/etc/sysctl.conf','Checking that net.ipv4.conf.all.accept_source_route is set to \'0\'');
    check_on_file('net.ipv4.conf.all.accept_redirects','^[\s|\t]*net.ipv4.conf.all.accept_redirects[\s|\t]*=[\s|\t]*0.*$','/etc/sysctl.conf','Checking that net.ipv4.conf.all.accept_redirects is set to \'0\'');
    check_on_file('net.ipv4.conf.all.secure_redirects','^[\s|\t]*net.ipv4.conf.all.secure_redirects[\s|\t]*=[\s|\t]*0.*$','/etc/sysctl.conf','Checking that net.ipv4.conf.all.secure_redirects is set to \'0\'');
    check_on_file('net.ipv4.conf.default.rp_filter','^[\s|\t]*net.ipv4.conf.default.rp_filter[\s|\t]*=[\s|\t]*1.*$','/etc/sysctl.conf','Checking that net.ipv4.conf.default.rp_filter is set to \'1\'');
    check_on_file('net.ipv4.conf.default.accept_source_route','^[\s|\t]*net.ipv4.conf.default.accept_source_route[\s|\t]*=[\s|\t]*0.*$','/etc/sysctl.conf','Checking that net.ipv4.conf.default.accept_source_route is set to \'0\'');
    check_on_file('net.ipv4.conf.default.accept_redirects','^[\s|\t]*net.ipv4.conf.default.accept_redirects[\s|\t]*=[\s|\t]*0.*$','/etc/sysctl.conf','Checking that net.ipv4.conf.default.accept_redirects is set to \'0\'');
    check_on_file('net.ipv4.conf.default.secure_redirects ','^[\s|\t]*net.ipv4.conf.default.secure_redirects[\s|\t]*=[\s|\t]*0.*$','/etc/sysctl.conf','Checking that net.ipv4.conf.default.secure_redirects is set to \'0\'');
    check_on_file('net.ipv4.ip_forward','^[\s|\t]*net.ipv4.ip_forward[\s|\t]*=[\s|\t]*0.*$','/etc/sysctl.conf','Checking that net.ipv4.ip_forward is set to \'0\'');
    check_on_file('net.ipv4.conf.all.send_redirects','^[\s|\t]*net.ipv4.conf.all.send_redirects[\s|\t]*=[\s|\t]*0.*$','/etc/sysctl.conf','Checking that net.ipv4.conf.all.send_redirects is set to \'0\'');
    check_on_file('net.ipv4.conf.default.send_redirects','^[\s|\t]*net.ipv4.conf.default.send_redirects[\s|\t]*=[\s|\t]*0.*$','/etc/sysctl.conf','Checking that net.ipv4.conf.default.send_redirects is set to \'0\'');
    check_on_file('net.ipv4.icmp_ignore_bogus_error_responses','^[\s|\t]*net.ipv4.icmp_ignore_bogus_error_responses[\s|\t]*=[\s|\t]*0.*$','/etc/sysctl.conf','Checking that net.ipv4.icmp_ignore_bogus_error_responses is set to \'0\'');

    if (-e '/etc/vsftpd/vsftpd.conf') {
        check_on_file('^xferlog_std_format=[nN][oO]$','^xferlog_std_format=[nN][oO]$','/etc/vsftpd/vsftpd.conf','Checking that xferlog_std_format is set to \'NO\' ');
        check_on_file('^log_ftp_protocol=[yY][eE][sS]$','^log_ftp_protocol=[yY][eE][sS]$','/etc/vsftpd/vsftpd.conf','Checking that log_ftp_protocol is set to \'YES\'');
    }

    foreach  my $file (qw(/var/log/btmp /var/log/boot.log /var/log/cron /var/log/dmesg /var/log/gdm /var/log/kernel /var/log/ksyms /var/log/httpd /var/log/lastlog /var/log/maillog /var/log/mailman /var/log/messages
                          /var/log/news /var/log/pgsql /var/log/rpmpkgs /var/log/sa /var/log/samba /var/log/scrollkeeper.log /var/log/secure /var/log/spooler /var/log/squid /var/log/syslog  /var/log/vbox))  {
#FIX AFTER: /var/log/wtmp neednt check on March 5
#/var/log/news /var/log/pgsql /var/log/rpmpkgs /var/log/sa /var/log/samba /var/log/scrollkeeper.log /var/log/secure /var/log/spooler /var/log/squid /var/log/syslog  /var/log/vbox /var/log/wtmp))  {

        if ( -e $file ) {
            my $value  = `ls -ld $file |  awk '{print \$3, \$4}'`;
            $value =~ s/^[\s|\t]*//gi;
            chomp $value;

            unless ($value =~ /root\sroot/gi) {
                PRINTME("Checking that $file is owned by root:root", "[**FAIL**]");
            } else { next; }

            $value = `ls -ld $file`;
            chomp $value;
            print REGEX "ls -ld $file > ".$value, "\n";
        }
    }

#FIX AFTER: wtmp neednt check on march 5
#    check_on_file('chmod.*/var/run/utmp.*/var/log/wtmp\b.*$','chmod.*0600.*/var/run/utmp.*/var/log/wtmp\b.*$','/etc/rc.d/rc.sysinit','Confirm Permissions 0600 on System Log File /etc/rc.d/rc.sysinit for \'wtmp\'');
    check_on_file('chmod.*/var/run/utmpx.*/var/log/wtmpx.*$', 'chmod.*0664.*/var/run/utmpx.*/var/log/wtmpx.*$', '/etc/rc.d/rc.sysinit', 'Confirm Permissions 0664 on System Log File /etc/rc.d/rc.sysinit for \'wtmpx\'');

#FIX AFTER: Check added to handle REDHAT 5 and 6 for syslog.conf
    if ($release <= 5 ) {
        check_on_cmd("ls -l /etc/syslog.conf |  awk \'{print \$3, \$4}\'", 'root\sroot', "Checking for correct syslog.conf ownership and mode");
        check_on_file('authpriv.*;auth.*;local7.*@arcsl[1|2]{1}','authpriv.*;auth.*;local7.*@arcsl[1|2]{1}','/etc/syslog.conf','Checking if remote logging is setup correctly');
    }elsif($release >= 6) {
        check_on_cmd("ls -l /etc/rsyslog.conf |  awk \'{print \$3, \$4}\'", 'root\sroot', "Checking for correct rsyslog.conf ownership and mode");
        check_on_file('authpriv.*;auth.*;local7.*@arcsl[1|2]{1}','authpriv.*;auth.*;local7.*@arcsl[1|2]{1}','/etc/rsyslog.conf','Checking if remote logging is setup correctly');
    }

#FIX AFTER: IGNORING / from fstab

    chomp(my @fstab = `egrep "^[\\s|\\t]*.*ext[2-4].*\$" /etc/fstab | grep -vw /`);

    my @TEST;

    foreach my $line (@fstab) {

        my $expect = '^[\s|\t]*.*ext[2-4][\s|\t]+.*nodev.*[\s|\t]+[0-9]';

        my ($test);
        if ( grep /$expect/i, $line) {
            $test =  '[PASS]';
            push(@TEST, $test)
            }
        else {
            $test = '[**FAIL**]';
            push(@TEST, $test)
            }
    }

    if ( grep /fail/i, @TEST) {
        PRINTME( "Checking that the 'nodev' option has been added to /etc/fstab" , '[**FAIL**]' );
    } else  {
        PRINTME( "Checking that the 'nodev' option has been added to /etc/fstab", '[PASS]' );
    }

    check_on_cmd("ls -l  /etc/fstab | awk \'{print \$3, \$4}\'",'root\sroot','Check for correct /etc/fstab ownership and mode');

    foreach my $file (qw (/etc/group /etc/gshadow /etc/passwd /etc/shadow)) {
        check_on_cmd("ls -l $file |  awk \'{print \$3, \$4}\'", 'root\sroot', "Checking that the OWNER,GROUP for $file are 'root'");
        my $value = `ls -ld $file`;
        chomp $value;
        print REGEX "ls -ld $file : ".$value, "\n";
    }

#FIX AFTER: Check added to handle REDHAT 5 and 6
    if ($release == 5 ) {
        check_on_file('^.*install.*usb-storage','[\s]*install[\s]*usb-storage\s+\/bin\/true\s*$','/etc/modprobe.conf','Checking that usb-storage is disabled in /etc/modprobe.conf');
    }elsif($release == 6) {
        check_on_file('^.*blacklist.*usb-storage','[\s]*blacklist[\s]*usb-storage.*$','/etc/modprobe.d/blacklist.conf','Checking that usb-storage is disabled in /etc/modprobe.d/blacklist.conf');
    }

    my ($rhosts, $rc) = check_cmd_status("egrep '\brhosts_auth\b' /etc/pam.d/* | awk -F ':' '{print \$1}'");

    my $rhosts_string = join(", ",@{$rhosts});
    print REGEX "egrep '\brhosts_auth\b' /etc/pam.d/* | awk -F ':' '{print \$1}' > ".$rhosts_string, "\n";

    if ( scalar(@{$rhosts}) < 1 ) {
        PRINTME("Checking if rhost_auth is NOT present in any file under /etc/pam.d" , "[PASS]");
    } else {

        PRINTME("Checking if rhost_auth is NOT present in any file under /etc/pam.d" , "[**FAIL**]");
        foreach my $file (@{$rhosts}) {
            check_on_cmd("ls -l $file | awk \'{print \$1}\'", '-rw-------', "Checking that rhosts file $file have permissions 600");
        }
    }

    if(-e '/etc/ftpusers') {

        check_on_cmd("ls -l /etc/ftpusers |  awk \'{print \$3, \$4}\'", 'root\sroot', "Checking that the OWNER,GROUP for /etc/ftpusers are 'root'");

        my @USERS = `cat /etc/ftpusers  | egrep -v '#'`;
        chomp @USERS;

        foreach (@USERS) {
            my $user = $_;
            my $uid = `id -u $user`;
            chomp $uid;

            print REGEX "id -u $user >  $uid \n";

            next if ($uid =~ /No such user/ig);
            if ($uid < 500 ){
                PRINTME("Check UID less than 500 for Existing user $_ in /etc/ftpusers", "[PASS]");
            } else {
                PRINTME("Check UID less than 500 for Existing user $_ in /etc/ftpusers", "[**FAIL**]");
            }
        }
    }

    if(-e '/etc/vsftpd/vsftpd.conf'){
        check_on_cmd("ls -l /etc/vsftpd/vsftpd.conf |  awk \'{print \$3, \$4}\'", 'root\sroot', "Checking that the OWNER,GROUP for /etc/vsftpd/vsftpd.conf are 'root'");
        check_on_file('^userlist_deny=[nN][oO]$','^userlist_deny=[nN][oO]$','/etc/vsftpd/vsftpd.conf','Checking if \'userlist_deny\' is set to NO in /etc/vsftpd/vsftpd.conf');
    }

    if (-e '/etc/X11/xdm/Xservers'){
        check_on_cmd("ls -l /etc/X11/xdm/Xservers |  awk \'{print \$3, \$4}\'", 'root\sroot', "Checking that the OWNER,GROUP for /etc/X11/xdm/Xservers are 'root'");
        check_on_file('^[\s|\t]*.*/usr/X11R6/bin/X.*','^[\s|\t]*.*/usr/X11R6/bin/X.*-nolisten tcp','/etc/X11/xdm/Xservers','Checking if \'nolisten tcp\' is set in /etc/X11/xdm/Xservers');
    }

    if( -e '/etc/X11/xinit/xserverrc'){
        check_on_cmd("ls -l /etc/X11/xinit/xserverrc |  awk \'{print \$3, \$4}\'", 'root\sroot', "Checking that the OWNER,GROUP for /etc/X11/xinit/xserverrc are 'root'");
        check_on_cmd('grep \'nolisten tcp\' /etc/X11/xinit/xserverrc', '-nolisten tcp', 'Checking if \'nolisten tcp\' is set in /etc/X11/xinit/xserverrc');
    }

    check_file_not_exists("/etc/cron.deny");
    check_file_not_exists("/etc/at.deny");

    if (-e "/etc/cron.allow" ) {
        check_on_cmd("ls -l /etc/cron.allow |  awk \'{print \$3, \$4}\'", 'root\sroot', "Checking that the OWNER,GROUP for /etc/cron.allow are 'root'");
        check_on_file('^root$','^root$','/etc/cron.allow','Checking if \'root\' exists in /etc/cron.allow');
     }

    if (-e "/etc/at.allow" ) {
        check_on_cmd("ls -l /etc/at.allow |  awk \'{print \$3, \$4}\'", 'root\sroot', "Checking that the OWNER,GROUP for /etc/at.allow are 'root'");
        check_on_file('^root$','^root$','/etc/at.allow','Checking if \'root\' exists in /etc/at.allow');
    }

    check_on_cmd("ls -l /etc/securetty |  awk \'{print \$3, \$4}\'", 'root\sroot', "Checking that the OWNER,GROUP for /etc/securetty are 'root'");
    (my $res, $rc) =  check_cmd_status("egrep -v '(console|vc/[1-6])\$' /etc/securetty");

    my ($term_string) = join (", ", @{$res});
    print REGEX "egrep -v '(console|vc/[1-6])\$' /etc/securetty > ".$term_string, "\n";

#FIX AFTER : MArch 18
=pod
    if ($rc != 0 ) {
        PRINTME("Checking if only vc/1-6 and console are present in /etc/securetty", "[PASS]");
    } elsif($rc == 0) {
        PRINTME("Checking if only vc/1-6 and console are present in /etc/securetty", "[**FAIL**]");
    }
=cut

    if (-e '/etc/X11/gdm/gdm.conf'){
        check_on_cmd("ls -l /etc/X11/gdm/gdm.conf |  awk \'{print \$3, \$4}\'", 'root\sroot', "Checking that the OWNER,GROUP for /etc/X11/gdm/gdm.conf are 'root'");
        check_on_file('^[^#]*AllowRoot=.*$','AllowRoot=false$','/etc/X11/gdm/gdm.conf','Checking if /etc/X11/gdm/gdm.conf restricts Root login in gdm.conf');
        check_on_file('^[^#]*AllowRemoteRoot=.*','AllowRemoteRoot=false$','/etc/X11/gdm/gdm.conf','Checking if /etc/X11/gdm/gdm.conf restricts RemoteRoot in gdm.conf');
    }

    check_on_file('^[\s|\t]*password[\s|\t]*','^[\s\t]*password[\s|\t]*[$a-zA-Z0-9]*','/boot/grub/grub.conf','Checking if \'password\' is set in /etc/grub.conf');
    check_on_cmd("ls -l /boot/grub/grub.conf | awk \'{print \$3, \$4}\'", 'root\sroot', "Checking that the OWNER,GROUP for /boot/grub/grub.conf are 'root'");

    check_on_file('^~~:S:wait:/sbin/sulogin$','^~~:S:wait:/sbin/sulogin$','/etc/inittab','Checking if \'sulogin\' is invoked by \'init\' in single user mode');
    check_on_cmd("ls -l /etc/inittab | awk \'{print \$3, \$4}\'", 'root\sroot', "Checking that the OWNER,GROUP for /etc/inittab are 'root'");

#FIX AFTER: CHECK need to be other way around
    #check_on_file('^[^#].*\(.*insecure','^.*\(.*insecure','/etc/exports','Checking if the insecure keyword is not present in /etc/exports');
    check_string_not_exist_file('^[^#].*\(.*insecure','^.*\(.*insecure','/etc/exports','Checking if the insecure keyword is not present in /etc/exports');
    check_on_cmd("ls -l /etc/exports | awk \'{print \$3, \$4}\'", 'root\sroot', "Checking that the OWNER,GROUP for /etc/exports are 'root'");

#FIX AFTER: EMPTY SHELLS To a Seperate File
    my @SHELLS;
    my $non_dev_null = $compliance."NoLoginShellAccounts.txt";
    foreach (`egrep '^[A-Za-z0-9_-]+:x:([1-9]:|[0-9][0-9]:|[0-4][0-9][0-9]:)[0-9]+:[A-Za-z0-9_ \/-]*:[A-Za-z0-9_\/-]+:' /etc/passwd | awk -F : '{print \$1,\$7}' | sort`) {
        chomp $_;
        my ($user,$shell)=split(/ /,$_);

        unless ($shell eq '/dev/null') {
            push(@SHELLS, $user);
        }
    }

#FIX AFTER: March 18
=pod
    unless (scalar(@SHELLS) == 0 ) {
        PRINTME( "Checking if the default shell for all accounts with UID less than 500 is set to /dev/null", "[**FAIL**]");
    } else {
        PRINTME("Checking if the default shell for all accounts with UID less than 500 is set to /dev/null", "[PASS]");
    }
=cut

    open(SHELL, "+>$non_dev_null") or die ("Unable to open file $non_dev_null: $!");
    print SHELL "\t\t Accounts with default shell for all accounts with UID less than 500 is not /dev/null \n";

    foreach my $account (@SHELLS){
        print SHELL "$account \n";
    }
    close SHELL;

    check_on_file('^root:x:0:0:root:/root:/bin/bash', '^root:x:0:0:root:/root:/bin/bash', '/etc/passwd' , 'Check if root shell is set to /bin/bash');
    check_on_cmd('grep INACTIVE /etc/default/useradd','INACTIVE=180','Checking in /etc/default/useradd INACTIVE is set to \'180\'');

#FIX AFTER: March 18

    #check_on_cmd('egrep \'^[\s|\t]*auth.*required.*pam_tally.so\sonerr=\w+[\s]*\w.\d\' /etc/pam.d/system-auth','auth.*required.*pam_tally.so\sonerr=fail\sdeny=3','Check in /etc/pam.d/system-auth set to auth required pam_tally.so onerr=fail deny=3');

    foreach (qw(/etc/group /etc/gshadow /etc/passwd /etc/shadow)) {
        my  ($res, $rc) = check_cmd_status("egrep '^[+]:' $_ ");

        print REGEX "egrep '^[+]:' $_ > ".join(", ", @{$res}), "\n";
        if ($rc == 0 )  {
            PRINTME("Checking that No Legacy '+' Entries Exist In $_", "[**FAIL**]");
        } else {
            PRINTME("Checking that No Legacy '+' Entries Exist In $_", "[PASS]");
        }
    }

#FIX AFTER: Check changed to ignore '#' preceding lines
    check_on_cmd_hash("egrep '[Aa]uthorized us(er|ers) only' /etc/issue",'[Aa]uthorized us(er|ers) only','Checking that /etc/issue has the proper warning banner');
    check_on_cmd_hash("egrep '[Aa]uthorized us(er|ers) only' /etc/motd",'[Aa]uthorized us(er|ers) only','Checking that /etc/motd has the proper warning banner');

    if (-e '/etc/X11/xdm/kdmrc') {
        check_on_file('^GreetString=[\s|\t]+.*Authorized[\s]*USE[\s]*only','^GreetString=[\s|\t]+.*Authorized[\s]*USE[\s]*only','/etc/X11/xdm/kdmrc','Checking if \'GreetString\' is set to \'Authorized uses only\' in /etc/X11/xdm/kdmrc');
    }

    if (-e '/etc/X11/xdm/Xresources') {
        check_on_file('^xlogin\*greeting:[\s|\t]+.*Authorized[\s]*USE[\s]*only','^xlogin\*greeting:[\s|\t]+.*Authorized[\s]*USE[\s]*only','/etc/X11/xdm/Xresources','Checking if \'xlogingreeting\' is set to \'Authorized uses only\' in /etc/X11/xdm/Xresources');
    }

    if (-e "/etc/vsftpd/vsftpd.conf") {
        check_on_file('^ftpd_banner=Authorized users only. All activity may be monitored','^ftpd_banner=Authorized users only. All activity may be monitored','/etc/vsftpd/vsftpd.conf','Checking if \'ftpd_banner\' is appropriately set in /etc/vsftpd/vsftpd.conf');
        check_on_cmd("ls -l /etc/vsftpd/vsftpd.conf |  awk \'{print \$3, \$4}\'", 'root\sroot', "Checking that the OWNER,GROUP for /etc/vsftpd/vsftpd.conf are 'root'");
    }

    foreach ( qw/auditd sysstat/) {

        unless (check_excludelist($_) == 1 ) {

            my $check = `/sbin/chkconfig --list |  grep -i $_ `;
            chomp $check;
            my $rc = $?;

            print REGEX "/sbin/chkconfig --list |  grep -i $_ > ".$check , "\n";

            if ($rc == 0){
                if ( grep /3:on.*5:on/, $check) {
                    PRINTME("ENABLE $_ on levels 3 and 5",  "[PASS]");
                } else {
                    PRINTME("ENABLE $_ on levels 3 and 5","[**FAIL**]");
                }
            } else {
                PRINTME("ENABLE $_ on levels 3 and 5",  "[PASS]");
            }
        }
    }

    check_on_cmd("awk -F ':' '{print \$1}' /etc/passwd | sort | uniq -d | wc -l",'0','Checking duplicate users in /etc/passwd');
    check_on_cmd("awk -F ':' '{print \$1}' /etc/group | sort | uniq -d | wc -l",'0','Checking duplicate groups in /etc/groups');
    check_on_cmd('ls -l / | grep root$ | awk \'{print $1}\'','drwx------','Checking the /root directory permissions to 700');
    check_on_cmd("ls -ld /root | awk \'{print \$3, \$4}\'", 'root\sroot', "Checking that the OWNER,GROUP for /root are 'root'");

    ($res, undef) = check_cmd_status('find /usr/share/doc/ -type f -perm /go+w -print');
    print REGEX "find /usr/share/doc/ -type f -perm /go+w -print > ".join(", ", @{$res})."\n";

    if (scalar (@{$res}) > 1) {
        PRINTME('Check to Restrict permissions to 0644 on /usr/share/doc/', "[**FAIL**]");
    } else {
        PRINTME('Check to Restrict permissions to 0644 on /usr/share/doc/', "[PASS]");
    }

    if (-e '/usr/local/share/doc/') {
        check_on_cmd('find /usr/local/share/doc/ -type f -perm /go+w -print | wc -l','\b0\b','Check to Restrict permissions to 0644 on /usr/local/share/doc/');
    }

    check_on_cmd('find /usr/share/man/ -type f -perm /go+w -print | wc -l','\b0\b','Check to Restrict permissions to 0644 on /usr/share/man/');

    if (-e '/usr/local/share/man/') {
        check_on_cmd('find /usr/local/share/man/ -type f -perm /go+w -print | wc -l','\b0\b','Check to Restrict permissions to 0644 on /usr/local/share/man/');
    }

#FIX after: Space Issue
    check_on_cmd('egrep "^.*echo.*1.*>.*/proc/sys/net/ipv4/tcp_syncookies[\s|\t]*$" /etc/rc.d/rc.local', '^[\s|\t]*echo[\s|\t]*1[\s|\t]*>[\s|\t]*/proc/sys/net/ipv4/tcp_syncookies[\s|\t]*$', 'Checking added \'tcp_syncookies\' settings to /etc/rc.d/rc.local');

    check_on_cmd("ls -l /etc/rc.d/rc.local | awk \'{print \$3, \$4}\'", 'root\sroot', "Checking that the OWNER,GROUP for /etc/rc.d/rc.local are 'root'");

#FIX after: Check symbolic Link and fix grub.conf file else straight Fix to menu.lst:
   # if (-l '/boot/grub/menu.lst') {
#       check_on_cmd("lsattr /boot/grub/grub.conf | awk -F ' ' '{print \$1'}", 'i', "Additional GRUB Security - /boot/grub/grub.conf");
 #   }else {
#       check_on_cmd("lsattr /boot/grub/menu.lst | awk -F ' ' '{print \$1'}", 'i', "Additional GRUB Security - /boot/grub/menu.lst");
#    }

#    check_on_cmd('[ -e /boot/grub/grub.conf ] && /usr/bin/chattr +i /boot/grub/grub.conf && echo $?', '0', 'Additional GRUB Security - /boot/grub/grub.conf');
#    check_on_cmd('[ -e /boot/grub/menu.lst ] && /usr/bin/chattr +i /boot/grub/menu.lst && echo $?', '0', 'Additional GRUB Security - /boot/grub/menu.lst');

#FIX AFTER: NEEDNT CHECK on March 5

#    check_on_cmd("egrep '^[\\s|\\t]*%wheel[\\s|\\t]+ALL[\\s|\\t]*=[\\s|\\t]*\(ALL\)[\\s|\\t]+ALL[\\s|\\t]*\$' /etc/sudoers", '^[\s|\t]*%wheel[\s|\t]+ALL[\s|\t]*=[\s|\t]*\(ALL\)[\s|\t]+ALL[\s|\t]*$', 'Install and Configure sudo - %wheel defined in /etc/sudoers');
    check_on_cmd("ls -l /etc/sudoers | awk \'{print \$3, \$4}\'", 'root\sroot', "Checking that the OWNER,GROUP for /etc/sudoers are 'root'");

#Fix After:PAM Tally Checks Doesnt need.
## IF checking PAM TALLY need to look for pam_faillock.so in Redhat 6 and  pam_tally.so in Redhat 5

    #check_on_file('auth.*required.* pam_tally.so.*onerr=fail[\s|\t]*no_magic_root', 'auth.*required.* pam_tally.so.*onerr=fail[\s|\t]*no_magic_root', '/etc/pam.d/system-auth', 'Checking if \'onerr\' is correctly set in /etc/pam.d/system-auth');

    #check_on_file('account.*required.*pam_tally2.so[\s|\t]*deny=3[\s|\t]*no_magic_root reset', 'account.*required.*pam_tally2.so[\s|\t]*deny=3[\s|\t]*no_magic_root reset', '/etc/pam.d/system-auth', 'Checking if \'deny\' is correctly set in /etc/pam.d/system-auth');

    ($res, undef)= check_cmd_status('awk -F: \'$3 == "0" { print $1}\' /etc/group');

    print REGEX "awk -F: \'\$3 == \"0\" { print \$1}\' /etc/group > ".join(", ", @{$res}) , "\n";

    if(scalar @{$res} != 1) {
        PRINTME("Checking that no duplicate names with UID 0 exist in /etc/group","[**FAIL**]");
    } else {
        PRINTME("Checking that no duplicate names with UID 0 exist in /etc/group",  "[PASS]");
    }

    ($res, undef) = check_cmd_status('awk -F: \'$3 == "0" { print $1}\' /etc/passwd');
    print REGEX "awk -F: \'\$3 == \"0\" { print \$1}\' /etc/passwd > ".join(", ", @{$res}) , "\n";
    if(scalar @{$res} != 1) {
        PRINTME("Checking that no duplicate names with UID 0 exist in /etc/passwd","[**FAIL**]");
    } else {
        PRINTME("Checking that no duplicate names with UID 0 exist in /etc/passwd","[PASS]");
    }

} elsif($OS eq 'AIX'){

    check_on_cmd('grep pwd_algorithm /etc/security/login.cfg','[\s|\t]*pwd_algorithm[\s|\t]*=[\s|\t]*smd5[\s|\t]*$','Check for Password Algorithm set to smd5');
    check_on_cmd('/usr/bin/lssec -f /etc/security/user -s default -a minage', 'default[\s\\t]*minage[\s|\t]*=[\s|\t]*0[\s|\t]*$', 'Check the minimum number of weeks before a password can be changed');
    check_on_cmd('/usr/bin/lssec -f /etc/security/user -s default -a maxage', 'default[\s|\t]*maxage[\s|\t]*=[\s|\t]*7[\s|\t]*$', 'Check the maximum number of weeks that a password is valid');
    check_on_cmd('/usr/bin/lssec -f /etc/security/user -s default -a minlen', 'default[\s|\t]*minlen[\s|\t]*=[\s|\t]*8[\s|\t]*$', 'Check the minimum length of a password');
    check_on_cmd('/usr/bin/lssec -f /etc/security/user -s default -a minalpha', 'default[\s|\t]*minalpha[\s|\t]*=[\s|\t]*1[\s|\t]*$','Check the minimum number of alphabetic characters in a password');
    check_on_cmd('/usr/bin/lssec -f /etc/security/user -s default -a minother','default[\s|\t]*minother[\s|\t]*=[\s|\t]*1[\s|\t]*$','Check the minimum number of non-alphabetic characters in a password');
    check_on_cmd('/usr/bin/lssec -f /etc/security/user -s default -a histsize','default[\s|\t]*histsize[\s|\t]*=[\s|\t]*5[\s|\t]*$','Check the number of previous passwords that a user may not reuse');
    check_on_cmd('/usr/bin/lssec -f /etc/security/user -s default -a maxexpired', 'default[\s|\t]*maxexpired[\s|\t]*=[\s|\t]*26[\s|\t]*$','Check the number of weeks after expiration that a user can change their password');
    check_on_cmd('/usr/bin/lssec -f /etc/security/login.cfg -s default -a logininterval', 'default[\s|\t]*logininterval[\s|\t]*=[\s|\t]*0[\s|\t]*$', 'Check the time interval in seconds when unsuccessful logins must occur to disable a port');
    check_on_cmd('/usr/bin/lssec -f /etc/security/login.cfg -s default -a logindisable','default[\s|\t]*logindisable[\s|\t]*=[\s|\t]*0[\s|\t]*$', 'Check the number of unsuccessful login attempts required before a port will be locked');
    check_on_cmd('/usr/bin/lssec -f /etc/security/login.cfg -s default -a loginreenable', 'default[\s|\t]*loginreenable[\s|\t]*=[\s|\t]*0[\s|\t]*$', 'Check the time interval (in minutes) when a port is unlocked after a system lock.');

    check_on_cmd('/usr/bin/lssec -f /etc/security/login.cfg -s usw -a logintimeout', 'usw[\s|\t]*logintimeout[\s|\t]*=[\s|\t]*60[\s|\t]*$', 'Check the time interval (in seconds) when a password must be typed in at login');
    check_on_cmd('/usr/bin/lssec -f /etc/security/login.cfg -s default -a logindelay','default[\s|\t]*logindelay[\s|\t]*=[\s|\t]*0[\s|\t]*$','Check the delay (in seconds) between each failed login attempt');
    check_on_cmd('/usr/bin/lssec -f /etc/security/user -s default -a loginretries', 'default[\s|\t]*loginretries[\s|\t]*=[\s|\t]*3[\s|\t]*$','Check the number of attempts a user has to login to the system before their account is disabled');
    check_on_cmd('/usr/bin/lssec -f /etc/security/user -s default -a rlogin', 'default[\s|\t]*rlogin[\s|\t]*=[\s|\t]*false[\s|\t]*$', 'Check whether direct login is available to the generic system account default');

    check_on_file('[\s|\t]*Protocol','Protocol[\s|\t]*2[\s|\t]*$','/etc/ssh/sshd_config','Configuring SSH - server protocol - \'Protocol 2\'');
    check_on_file('[\s|\t]*Protocol','Protocol[\s|\t]*2[\s|\t]*$','/etc/ssh/ssh_config','Configuring SSH - client protocol - \'Protocol 2\'');

    check_on_cmd('/usr/bin/lssec -f /etc/security/login.cfg -s default -a herald','default[\s|\t]*herald[\s|\t]*=[\s|\t]*\"Unauthorized[\s]*use[\s]*of[\s]*this[\s]*system[\s]*is[\s]*prohibited\.\"$','Check that the login herald has been set in /etc/security/login.cfg');

    check_on_file('[\s|\t]*Banner', 'Banner[\s|\t]*\/etc\/motd[\s|\t]*$', '/etc/ssh/sshd_config' , 'Checking that /etc/ssh/sshd_config has been edited to use a login herald');
    check_on_file('IgnoreRhosts','IgnoreRhosts[\s|\t]*yes[\s|\t]*$','/etc/ssh/sshd_config','IgnoreRhosts is set to \'yes\'');
    check_on_file('[\s|\t]*PermitEmptyPasswords','PermitEmptyPasswords[\s|\t]*[Nn][Oo][\s|\t]*$','/etc/ssh/sshd_config','disable null passwords - PermitEmptyPasswords to \'no\'');
    #check_on_cmd('/usr/bin/pwdck -n ALL 2>&1 | awk \'{print} END {if (NR == 0) print "none"}\'','none','Check that all unlocked accounts have a password set');
    check_on_file('[\s|\t]*HostbasedAuthentication.*','HostbasedAuthentication[\s|\t]*[Nn][Oo][\s|\t]*','/etc/ssh/sshd_config','disallow host based authentication - HostbasedAuthentication to \'no\'');
    check_on_file('[\s|\t]*UsePrivilegeSeparation','UsePrivilegeSeparation[\s|\t]*[Yy][Ee][Ss][\s|\t]*$','/etc/ssh/sshd_config','set privilege separation - UsePrivilegeSeparation to \' yes\'');
    check_on_cmd('perl -e\'printf "%o\n",(stat shift)[2]\' /etc/ssh/sshd_config','644','Check Permissions on sshd_config 644');


#FIX AFTER: Change for VIO's April 3
    if ($hostname =~ /vio/i) {
        check_on_cmd('lssec -f /etc/security/user -s root -a sugroups -a su','^root[\s|\t]*sugroups[\s|\t]*=[\s|\t]*[Aa][Ll][Ll][\s]+su[\s|\t]*=[\s|\t]*[Ff][Aa][Ll][Ss][Ee]$','Checking whether root, via su, is restricted to a specific group');
    } else {
        check_on_cmd('lssec -f /etc/security/user -s root -a sugroups -a su','^root[\s|\t]*sugroups[\s|\t]*=[\s|\t]*[Aa][Ll][Ll][\s]+su[\s|\t]*=[\s|\t]*[Tt][Rr][Uu][Ee]$','Checking whether root, via su, is restricted to a specific group');
    }
#FIX AFTER: Checking for only accounts existing in /etc/passwd
    foreach my $user (qw(daemon bin sys adm uucp nobody lpd)) {
        if (`grep ^$user /etc/passwd`){
            check_on_cmd("/usr/sbin/lsuser -a login rlogin $user",'^'.$user.'[\s|\t]*login=false[\s|\t]*rlogin=false$',"Check whether direct login is available to the generic system account $user");
        }
    }

    unless(check_excludelist('piobe') == 1 ) { check_on_cmd('/usr/sbin/lsitab piobe && echo yes || echo none','^none$','Check whether the piobe service has been disabled in /etc/inittab'); }
    unless(check_excludelist('dt') == 1 ) { check_on_cmd('/usr/sbin/lsitab dt && echo yes || echo none','^none$','Check whether the dt service has been disabled in /etc/inittab'); }
    unless(check_excludelist('rcnfs') == 1 ) { check_on_cmd('/usr/sbin/lsitab rcnfs && echo yes || echo none ','^none$','Check whether the rcnfs service has been disabled in /etc/inittab'); }
    unless(check_excludelist('rquotad') == 1 ) { check_on_cmd_hash("egrep '^[#]?rquotad' /etc/inetd.conf", '^\#[\s|\t]*rquotad.*\/usr\/sbin\/rpc\.rquotad.*$', 'Check whether the rquotad service has been disabled in /etc/inetd.conf');}
    unless(check_excludelist('sendmail') == 1 ) { check_on_cmd_hash("egrep 'start.*/usr/lib/sendmail' /etc/rc.tcpip",'^\#[\s|\t]*start[\s|\t]*\/.*\/sendmail.*$','Check whether the sendmail service has been disabled in /etc/rc.tcpip');}

    foreach (qw(snmpd hostmibd snmpmibd aixmibd dhcpcd dhcprd dhcpsd autoconf6 ndpd-host ndpd-router gated mrouted named routed rwhod timed dpid2)) {
        unless(check_excludelist($_) == 1 ) {
            check_on_cmd_hash("egrep 'start.*/usr/sbin/$_' /etc/rc.tcpip",'^[#]+[\s|\t]*start[\s|\t]*\/.*\/'.$_.'.*$',"Check whether the $_ service has been disabled in /etc/rc.tcpip");
        }
    }

    unless(check_excludelist('telnet') == 1 ) { check_on_cmd_hash("egrep '^[#]?telnet' /etc/inetd.conf",'^#[\s|\t]*telnet[\s|\t]+.*/usr/sbin/telnetd.*$','Check whether the telnet service has been disabled in /etc/inetd.conf'); }
    unless(check_excludelist('rexecd') == 1 ) { check_on_cmd_hash("egrep '^[#]?exec' /etc/inetd.conf",'^#[\s|\t]*exec[\s|\t]+.*/usr/sbin/rexecd.*$','Check whether the rexecd service has been disabled in /etc/inetd.conf'); }
    unless(check_excludelist('daytime-tcp') == 1 ) { check_on_cmd_hash("egrep ^[#]?daytime.*tcp /etc/inetd.conf",'^#[\s|\t]*daytime[\s|\t]+.*tcp.*internal.*$','Check whether the daytime-tcp service has been disabled in /etc/inetd.conf');}
    unless(check_excludelist('daytime-udp') == 1 ) { check_on_cmd_hash("egrep ^[#]?daytime.*udp /etc/inetd.conf",'^#[\s|\t]*daytime[\s|\t]+.*udp.*internal.*$','Check whether the daytime-udp service has been disabled in /etc/inetd.conf');}
    unless(check_excludelist('uucp') == 1 ) { check_on_cmd_hash("egrep ^[#]?uucp /etc/inetd.conf",'^#[\s|\t]*uucp[\s|\t]+.*/usr/sbin/uucpd.*$','Check whether the uucp service has been disabled in /etc/inetd.conf');}
    unless(check_excludelist('time-tcp') == 1 ) { check_on_cmd_hash("egrep ^[#]?time.*tcp /etc/inetd.conf",'^#[\s|\t]*time[\s|\t]+.*tcp.*internal.*$','Check whether the time-tcp service has been disabled in /etc/inetd.conf');}
    unless(check_excludelist('time-udp') == 1 ) { check_on_cmd_hash("egrep ^[#]?time.*udp /etc/inetd.conf",'^#[\s|\t]*time[\s|\t]+.*udp.*internal.*$','Check whether the time-udp service has been disabled in /etc/inetd.conf');}
    unless(check_excludelist('talkd') == 1 ) { check_on_cmd_hash("egrep ^[#]?talk /etc/inetd.conf",'^#[\s|\t]*talk[\s|\t]+.*/usr/sbin/talkd.*$','Check whether the talkd service has been disabled in /etc/inetd.conf');}
    unless(check_excludelist('ftpd')== 1 ) { check_on_cmd_hash("egrep ^[#]?ftp /etc/inetd.conf",'^#[\s|\t]*ftp[\s|\t]+.*/usr/sbin/ftpd.*$','Check whether the ftpd service has been disabled in /etc/inetd.conf');}
    unless(check_excludelist('chargen-tcp') == 1 ) { check_on_cmd_hash("egrep ^[#]?chargen.*tcp /etc/inetd.conf",'^#[\s|\t]*chargen[\s|\t]+.*tcp.*internal.*$','Check whether the chargen-tcp service has been disabled in /etc/inetd.conf');}
    unless(check_excludelist('chargen-udp') == 1 ) { check_on_cmd_hash("egrep ^[#]?chargen.*udp /etc/inetd.conf",'^#[\s|\t]*chargen[\s|\t]+.*udp.*internal.*$','Check whether the chargen-udp service has been disabled in /etc/inetd.conf');}
    unless(check_excludelist('discard-tcp') == 1 ) { check_on_cmd_hash("egrep ^[#]?discard.*tcp /etc/inetd.conf",'^#[\s|\t]*discard[\s|\t]+.*tcp.*internal.*$','Check whether the discard-tcp service has been disabled in /etc/inetd.conf');}
    unless(check_excludelist('discard-udp') == 1 ) { check_on_cmd_hash("egrep ^[#]?discard.*udp  /etc/inetd.conf",'^#[\s|\t]*discard[\s|\t]+.*udp.*internal.*$','Check whether the discard-udp service has been disabled in /etc/inetd.conf');}
    unless(check_excludelist('echo-tcp') == 1 ) { check_on_cmd_hash("egrep ^[#]?echo.*tcp /etc/inetd.conf",'^#[\s|\t]*echo[\s|\t]+.*tcp.*internal.*$','Check whether the echo-tcp service has been disabled in /etc/inetd.conf');}
    unless(check_excludelist('echo-udp') == 1 ) { check_on_cmd_hash("egrep ^[#]?echo.*udp /etc/inetd.conf",'^#[\s|\t]*echo[\s|\t]+.*udp.*internal.*$','Check whether the echo-udp service has been disabled in /etc/inetd.conf');}
    unless(check_excludelist('pcnfsd') == 1 ) { check_on_cmd_hash("egrep ^[#]?pcnfsd /etc/inetd.conf",'^#[\s|\t]*pcnfsd[\s|\t]+.*/usr/sbin/rpc\.pcnfsd.*$','Check whether the pcnfsd service has been disabled in /etc/inetd.conf');}
    unless(check_excludelist('rstatd') == 1 ) { check_on_cmd_hash("egrep ^[#]?rstatd /etc/inetd.conf",'^#[\s|\t]*rstatd[\s|\t]+.*/usr/sbin/rpc\.rstatd.*$','Check whether the rstatd service has been disabled in /etc/inetd.conf');}
    unless(check_excludelist('rusersd') == 1 ) { check_on_cmd_hash("egrep ^[#]?rusersd /etc/inetd.conf",'^#[\s|\t]*rusersd[\s|\t]+.*/usr/lib/netsvc/rusers/rpc\.rusersd.*$','Check whether the rusersd service has been disabled in /etc/inetd.conf'); }
    unless(check_excludelist('rwalld') == 1 ) { check_on_cmd_hash("egrep ^[#]?rwalld /etc/inetd.conf",'^#[\s|\t]*rwalld[\s|\t]+.*/usr/lib/netsvc/rwall/rpc\.rwalld.*$','Check whether the rwalld service has been disabled in /etc/inetd.conf');}
    unless(check_excludelist('sprayd') == 1 ) { check_on_cmd_hash("egrep ^[#]?sprayd /etc/inetd.conf",'^#[\s|\t]*sprayd[\s|\t]+.*/usr/lib/netsvc/spray/rpc\.sprayd.*$','Check whether the sprayd service has been disabled in /etc/inetd.conf');}
    unless(check_excludelist('finger') == 1 ) { check_on_cmd_hash("egrep ^[#]?finger /etc/inetd.conf",'^#[\s|\t]*finger[\s|\t]+.*/usr/sbin/fingerd.*$','Check whether the finger service has been disabled in /etc/inetd.conf');}

    check_on_cmd("ls -l /usr/sbin/tftpd | awk '{print \$1}'", '-rw-r--r--', 'Checking permissions 644 for /usr/sbin/tftpd');

    check_on_cmd('/usr/bin/egrep "^[^\#].+$" /etc/hosts.equiv | /usr/bin/awk \'{print} END {if (NR == 0) print "none"}\'','none','Removal of entries from /etc/hosts.equiv file - \'hosts.equiv has no entries\'');
    check_on_file('[\s|\t]*ipsrcrouteforward','^[\s|\t]*ipsrcrouteforward[\s|\t]*=[\s|\t]*\"0\"$','/etc/tunables/nextboot','Check whether ipsrcrouteforward = 0 in /etc/tunables/nextboot');
    check_on_file('[\s|\t]*clean_partial_conns','^[\s|\t]*clean_partial_conns[\s|\t]*=[\s|\t]*\"1\"$','/etc/tunables/nextboot','Check whether clean_partial_conns = 1 in /etc/tunables/nextboot');
    check_on_file('[\s|\t]*ipforwarding','^[\s|\t]*ipforwarding[\s|\t]*=[\s|\t]*\"0\"$','/etc/tunables/nextboot','Check whether ipforwarding=0 in /etc/tunables/nextboot');
    check_on_file('[\s|\t]*ipsendredirects','^[\s|\t]*ipsendredirects[\s|\t]*=[\s|\t]*\"0\"$','/etc/tunables/nextboot','Check whether ipsendredirects=0 in /etc/tunables/nextboot');
    check_on_file('[\s|\t]*ip6srcrouteforward','^[\s|\t]*ip6srcrouteforward[\s|\t]*=[\s|\t]*\"0\"$','/etc/tunables/nextboot','Check whether ip6srcrouteforward=0 in /etc/tunables/nextboot');
    check_on_file('[\s|\t]*directed_broadcast','^[\s|\t]*directed_broadcast[\s|\t]*=[\s|\t]*\"0\"$','/etc/tunables/nextboot','Check whether directed_broadcast=0 in /etc/tunables/nextboot');
#FIX AFTER: Space Issue
    check_on_file('[\s|\t]*[^_]rfc1323','^[\s|\t]*rfc1323[\s|\t]*=[\s|\t]*\"1\"$','/etc/tunables/nextboot','Check whether rfc1323=1 in /etc/tunables/nextboot');
#    check_on_file('^[\s|\t]*rfc1323','^[\s|\t]*rfc1323[\s|\t]*=[\s|\t]*\"1\"$','/etc/tunables/nextboot','Check whether rfc1323=1 in /etc/tunables/nextboot');

    #check_on_cmd_hash('/usr/bin/lssec -f /etc/security/login.cfg -s default -a herald','^default[\s|\t]+herald[\s|\t]*=[\s|\t]*\"Unauthorized[\s]+use[\s]+of[\s]+this[\s]+system[\s]+is[\s]+prohibited\.\"$','Checks that the login herald has been set in /etc/security/login.cfg');

    check_on_cmd("/usr/sbin/lsuser guest 2>/dev/null | /usr/bin/awk \'{print} END {if (NR == 0) print \"none\"}\'",'none','Checks that the guest account has been removed');

    if ( -e '/usr/sbin/skulker') {
        check_on_cmd('find /usr/sbin/skulker -type f -perm -22 -print | wc -l','\b0\b','Checking that /usr/sbin/skulker exists and is mode 755');
    }

    if (-e '/usr/lib/ras/dumpcheck') {
        check_on_cmd('find /usr/lib/ras/dumpcheck  -type f -perm -27 -print | wc -l', '\b0\b', 'Checking that /usr/lib/ras/dumpcheck exists and is mode 750');
    }

    check_on_cmd('/usr/bin/lssec -f /etc/security/user -s default -a umask','^default[\s|\t]*umask=27$','Checks the default umask is 27 in /etc/security/user');

    check_file_not_exists('/etc/shosts.equiv');

#FIX AFTER: Check is already on Nagios. Not Needed anymore
#    check_on_cmd_hash('egrep \'start.*/usr/sbin/portmap\' /etc/rc.tcpip','^#[\s|\t]*start[\s|\t]+/.*/portmap.*$','Checks whether the portmap service has been disabled in /etc/rc.tcpip');

    check_on_cmd('ls -ld /etc/security  |  awk \'{print $1, $3, $4}\'','^drwxr-x---\sroot\ssecurity','Checking that /etc/security is owned by root:security and is mode 750');
    check_on_cmd('ls -l /etc/group  |  awk \'{print $1, $3, $4}\'','^-rw-r--r--\sroot\ssecurity','Checking that /etc/group is owned by root:security and is mode 644');
    check_on_cmd('ls -l /etc/passwd  |  awk \'{print $1, $3, $4}\'','^-rw-r--r--\sroot\ssecurity','Checking that /etc/passwd is owned by root:security and is mode 644');

#FIX AFTER: check only if /smit.log exist
    if ( -e '/smit.log') {
        check_on_cmd('ls -l /smit.log |  awk \'{print $1, $3, $4}\'','^-rw-r-----\sroot\ssystem','Checking that /smit.log is owned by root:system and is mode 640');
    }

    check_on_cmd('ls -l /var/adm/cron/log  |  awk \'{print $1, $3, $4}\'','^-rw-rw----\sroot\scron','Checking that /var/adm/cron/log is owned by root:cron and is mode 660');
    check_on_cmd('ls -ld /var/spool/cron/crontabs/ |  awk \'{print $1, $3, $4}\'','^drwxrwx---\sroot\scron','Checking that /var/spool/cron/crontabs/ is owned by root:cron and is mode 770');
    check_on_cmd('ls -l /var/adm/cron/at.allow |  awk \'{print $1, $3, $4}\'','^-r--------\sroot\ssystem\b','Checking that /var/adm/cron/at.allow is owned by root:system and is mode 400');

#FIX AFTER: Adjusting the test for Banner string issue.
    check_on_cmd('ls -l /etc/motd |  awk \'{print $1, $3, $4}\'','^-r--r--r--\sbin\sbin','Checking that /etc/motd is owned by bin:bin and is mode 444');

    #check_on_cmd_hash("egrep '.+' /etc/motd", '^Authorized[\s]*uses[\s]*only\.[\s]*All[\s]*activity[\s]*may[\s]*be[\s]*monitored[\s]*and[\s]*reported\.$', 'Checking that /etc/motd is configured to post the proper warning message');
    check_on_cmd_hash("egrep '[Aa]uthorized us(er|ers) only' /etc/motd",'[Aa]uthorized us(er|ers) only','Checking that /etc/motd has the proper warning banner');

    check_on_cmd('find /var/adm/ras/ -type f -perm -4 -print |  wc -l','\b0\b','Checking that /var/adm/ras/* does not allow reading by others');
    check_on_cmd('find /var/adm/ras/ -type f -perm -2 -print |  wc -l','\b0\b','Checking that /var/adm/ras/* does not allow writing by others');
    check_on_cmd('ls -l /var/ct/RMstart.log |  awk \'{print $1, $3, $4}\'','^-rw-r-----\sroot\ssystem','Checking that /var/ct/RMstart.log is owned by root:system and is mode 640');
    check_on_cmd('ls -ld /var/adm/sa |  awk \'{print $1, $3, $4}\'','^drwxr-xr-x\sadm\sadm','Checking that /var/adm/sa directory is owned by adm:adm and is mode 755');

    unless(check_excludelist('i4ls') == 1 ) { check_on_cmd('/usr/sbin/lsitab i4ls | /usr/bin/awk \'{print} END {if (NR == 0) print "none"}\'','none','Checking whether the i4ls service has been disabled in /etc/inittab');}
    unless(check_excludelist('rcncs') == 1 ) { check_on_cmd('/usr/sbin/lsitab rcncs | /usr/bin/awk \'{print} END {if (NR == 0) print "none"}\'','none','Checking whether the rcncs service has been disabled in /etc/inittab');}
    unless(check_excludelist('httpdlite') == 1 ) { check_on_cmd('/usr/sbin/lsitab httpdlite | /usr/bin/awk \'{print} END {if (NR == 0) print "none"}\'','none','Checking whether the httpdlite service has been disabled in /etc/inittab');}
    unless(check_excludelist('pmd') == 1 ) { check_on_cmd('/usr/sbin/lsitab pmd | /usr/bin/awk \'{print} END {if (NR == 0) print "none"}\'','none','Checking whether the pmd service has been disabled in /etc/inittab');}
    unless(check_excludelist('writesrv') == 1 ) { check_on_cmd('/usr/sbin/lsitab writesrv | /usr/bin/awk \'{print} END {if (NR == 0) print "none"}\'','none','Checking whether the writesrv service has been disabled in /etc/inittab');}

#FIX AFTER: Adjusting the test for # issue.
    #check_on_cmd('egrep \'^ftp\' /etc/inetd.conf','^ftp[\s|\t]*.+.ftpd[\s]-l[\s]-u017.*$','Checking that inetd.conf is configured ftp umask at least 027');
    check_on_cmd_hash("egrep ^[#]?ftp /etc/inetd.conf",'^[#]?ftp[\s|\t]*.+.ftpd[\s]-l[\s]-u017.*$','Checking that inetd.conf is configured ftp umask at least 017');
#FIX AFTER: Checking the test if only when /usr/lib/nls/msg/en_US/ftpd.cat exist.

    my ($res, $rc) =  check_cmd_status("lslpp -l | grep bos.msg.en_US.net.tcp.client");

    if ($rc == 0 ) {
        check_on_cmd('/usr/bin/dspcat -g /usr/lib/nls/msg/en_US/ftpd.cat','Authorized[\s|\t]*uses[\s\t]*only\.[\s|\t]*All[\s|\t]*activity[\s|\t]*may[\s|\t]*be[\s|\t]*monitored[\s|\t]*and[\s|\t]*reported','Checking that the proper ftp banner is configured');
    } else {
        check_on_cmd('cat /usr/lib/nls/msg/en_US/ftpd.cat','Authorized[\s|\t]*uses[\s\t]*only\.[\s|\t]*All[\s|\t]*activity[\s|\t]*may[\s|\t]*be[\s|\t]*monitored[\s|\t]*and[\s|\t]*reported','Checking that the proper ftp banner is configured');
    }

    chomp(my $cron_string = `grep -i 'cronuser:' $exclude_list | awk -F : '{print \$2}'`);
    my $cronusers = "root|";
    $cronusers .= join("|", split(/,/,$cron_string));

    check_on_file('root','^root$','/var/adm/cron/at.allow','Checking that an entry for root exists in /var/adm/cron/at.allow');
#root at.allow
    check_on_cmd("grep -v -E -e \'$cronusers\' /var/adm/cron/at.allow | /usr/bin/awk '{print} END {if (NR == 0) print \"none\"}'",'none','Checking that no other entries except for root and excluded users exist in /var/adm/cron/at.allow');

    check_on_file('root','^root$','/var/adm/cron/cron.allow','Checking that an entry for root exists in /var/adm/cron/cron.allow');

    if ($hostname =~ /vio/i) {
        check_on_cmd('grep -v -E -e \'root|padmin\' /var/adm/cron/cron.allow | /usr/bin/awk \'{print} END {if (NR == 0) print "none"}\'','none',"Checking that no other entries except for root and padmin exists in /var/adm/cron/cron.allow on $hostname");
    } else {
#root cron.allow
        check_on_cmd("grep -v -E -e \'$cronusers\' /var/adm/cron/cron.allow | /usr/bin/awk '{print} END {if (NR == 0) print \"none\"}'",'none','Checking that no other entries except for root and excluded users in /var/adm/cron/cron.allow');
    }

    check_on_cmd("/usr/bin/pwdck -n ALL 2>&1 | /bin/awk '{print} END {if (NR == 0) print \"none\"}'", 'none', 'Checking that all unlocked accounts have a password set');

    # check_on_cmd("/usr/bin/cut -d: -f 3 /etc/passwd | /usr/bin/sort -n | /usr/bin/uniq -d | /usr/bin/awk '{print} END {if (NR == 0) print \"none\"}'",'none','Checking that all users have a unique user id');

    chomp(my $dup_user_string = `grep -i 'dup_users:' $exclude_list | awk -F : '{print \$2}'`);
    my $dup_users;
    if ($dup_user_string) {
        $dup_users .= join("|", split(/,/, $dup_user_string));
    }

    if ($dup_users) {
        print "dup_users=$dup_users\n";
        check_on_cmd("grep -v -E -e '$dup_users' /etc/passwd | /usr/bin/cut -d: -f 3 | /usr/bin/sort -n | /usr/bin/uniq -d | /usr/bin/awk '{print} END {if (NR == 0) print \"none\"}'",'none','Checking that all users have a unique user id');
    } else {
        check_on_cmd("/usr/bin/cut -d: -f 3 /etc/passwd | /usr/bin/sort -n | /usr/bin/uniq -d | /usr/bin/awk '{print} END {if (NR == 0) print \"none\"}'",
                        'none','Checking that all users have a unique user id');
    }


    check_on_cmd("/usr/bin/cut -d: -f 3 /etc/group | /usr/bin/sort -n | /usr/bin/uniq -d | /usr/bin/awk '{print} END {if (NR == 0) print \"none\"}'","none","Checking that all groups have a unique group id");

#FIX AFTER: This doesnt required as there are few systems with even 5.1
    #check_on_cmd('/usr/bin/oslevel','^6.1','Checking  if this system is running AIX 6.1');
    check_on_cmd("/usr/bin/grep '^PATH=' /etc/environment | /usr/bin/egrep '\\.:|:\\.:|:\\.\$' | /usr/bin/awk '{print} END {if (NR == 0) print \"none\"}'",'none','Checks that no \'dot\' entries exist in the root PATH environment variable in /etc/environment ');
    check_on_cmd("/usr/bin/grep '^PATH=' /etc/profile | /usr/bin/egrep '\\.:|:\\.:|:\\.\$' | /usr/bin/awk '{print} END {if (NR == 0) print \"none\"}'",'none',"Checks that no 'dot' entries exist in the PATH environment variable in /etc/profile");

    #check_on_file('authpriv.*;auth.*;local7.*@arcsl1','authpriv.*;auth.*;local7.*@arcsl1','/etc/syslog.conf','Checking if remote logging is setup correctly');
    check_on_cmd("/usr/bin/grep 'arcsl' /etc/syslog.conf| wc -l","7",'Checking if remote logging is setup correctly');

}

sub PRINTME {
    my $string = shift;
    my $test = shift;
    printf "\t%-100s : %s\n" , "$string" , "$test" ;
    printf LOG "\t%-100s : %s\n" , "$string" , "$test";
}

sub check_on_file {

    my ($regex, $expect, $file, $string) = @_ ;
    my $test;
    my @info  = `egrep "$regex" $file| egrep -v '#'`;
    chomp @info;

    #print Dumper(\@info);

    if ( grep /$expect/, @info) {
        $test =  '[PASS]';
    } else {
        $test = '[**FAIL**]';
    }
    PRINTME( $string , $test );
    print REGEX "egrep \"$regex\" $file| egrep -v '#' > ".join (", ", @info),"\n";
}

sub check_on_cmd {
    my($cmd, $expect, $string) =  @_;
    my $test;
    my @info  = `$cmd | egrep -v '#'`;
    chomp @info;

    #print Dumper(\@info);

    if ( grep /$expect/, @info) {
        $test =  '[PASS]';
    } else {
        $test = '[**FAIL**]';
    }
    PRINTME( $string , $test );
    print REGEX "$cmd | egrep -v '#' > ".join (", ", @info),"\n";
}

sub check_on_cmd_hash {
    my($cmd, $expect, $string) =  @_;
    my $test;
    my @info  = `$cmd`;
    chomp @info;

    #print Dumper(\@info);
    if ( grep /^#/, @info) {
        $test =  '[PASS]';
    } elsif ( grep /$expect/, @info) {
        $test =  '[PASS]';
    } else {
        $test = '[**FAIL**]';
    }
    PRINTME( $string , $test );
    print REGEX "$cmd > ".join (", ", @info),"\n";
}

sub check_cmd_status {

    my $cmd = shift;
    #print "\$cmd = $cmd \n";
    my @res = `$cmd`;
    my $rc = $?;
    chomp @res;

    return (\@res,$rc);
}

sub check_file_not_exists {

    my $file = shift;
    system ("ls -l $file 2>/dev/null");
    my $rc = $?;

    if ($rc != 0 ) {
        PRINTME("Checking $file does not exist", "[PASS]");
    } else {
        PRINTME("Checking $file does not exist", "[**FAIL**]");
    }

    return $rc ;
}

sub check_string_not_exist_file {

    my ($regex, $expect, $file, $string) = @_ ;
    my $test;
    my @info  = `egrep "$regex" $file| egrep -v '#'`;
    chomp @info;

    #print Dumper(\@info);

    if ( !grep /$expect/, @info) {
        $test =  '[PASS]';
    } else {
        $test = '[**FAIL**]';
    }

    PRINTME( $string , $test );
    print REGEX "egrep \"$regex\" $file| egrep -v '#' > ".join (", ", @info),"\n";
}

sub check_excludelist {

    my $service = shift;
    chomp(my $service_line = `grep -i "^$service:" $exclude_list`);

    my $val;

    if ($service_line) {
        my (undef, $servers) = split(/:/ , $service_line);
        my @servers = split(/,/, $servers);
        if (grep { /$hostname/ } @servers) {
            $val = 1;
            PRINTME("Disable $service", "[PASS]");
        } else { $val = 0;}
    } else { $val = 0;}
    return $val;
}

close(LOG);
close (REGEX);
close (EMP);

########################################## Clean up and Lock dow

my @older = `find $compliance -type f -mtime +90 -print`;
chomp @older;
unlink @older;

`chmod 400 $REPORT`;
if(-e $emp_accounts_file) {
    `chmod 400 $emp_accounts_file`;
}

########################################## Making a copy to IT S

#`mkdir -p /home/tenap3a/compliancereport` unless (-d '/home/tena
#`chmod 500 /home/tenap3a/compliancereport`;
#`cp -pr /root/compliance/* /home/tenap3a/compliancereport/`;
#`chown -R tenap3a:security /home/tenap3a/compliancereport`;

exit;
