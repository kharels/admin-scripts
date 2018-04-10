#!/usr/bin/perl
#
#Modified by: kharel.shashank@gmai.com
use Socket;
my $spacing = '32';
my %config;
$Resolve = "/etc/resolv.conf";
$config{osversion} = uc $^O;
if ($config{osversion} eq 'AIX'){
   $config{oslevel} = `oslevel -s`;
   ##$config{model} = `uname -M`;
   $config{model} = `lsattr -El sys0 -a modelname | awk '{print \$2}'`;
   $config{serial} = `uname -u`;
   $config{firmware} = `lsattr -El sys0 -a fwversion -F value`;
   $config{auto_restart} = `lsattr -El sys0 -a autorestart -F value`;
   $config{full_core} = `lsattr -El sys0 -a fullcore -F value`;
   $config{lpar} = `uname -L`;
   my @procs = `lsdev -Cc processor|grep Avail|awk '{print \$1}'`;
   my @tmp = `lsattr -El $procs[0]`;
   my @tmp2 = grep {s/^type\s+(\S+)\s+.*/$1/} @tmp;
   $config{processor_type} = $tmp2[0];
   @tmp2 = ();
   @tmp2 = grep {s/^frequency\s+(\d+)\s+.*/$1/} @tmp;
   $config{processor_speed} = ($tmp2[0]/1000000) . " MHz" ;
   $config{processor_number} = $#procs+1;
   $config{cpu_type} = `getsystype -y` . "-bit";
   $config{cpu_type} =~ s/\s+//g;
   $config{kernel_mode} = `getsystype -K` . "-bit";
   $config{kernel_mode} =~ s/\s+//g;
   $config{memory_size} = `lsattr -El mem0|grep Total`;
   $config{memory_size} =~ s/.*\s+(\d+)\s+.*/$1/;
   $config{swap_size} = `lsps -s|tail -1`;
   $config{swap_size} =~ s/^\s+(\d+).*/$1/g;
   my ($host) = `hostname`;
      chomp($host);
   my $ipaddr = gethostbyname($host);
   if ($ipaddr) {
      $config{IP} = (inet_ntoa($ipaddr));
   $adapter = `netstat -i | grep -vE \"Name|link|lo0\" | awk '{print \$1}' | tail -1`;
      chomp($adapter);
   $config{mask} = `lsattr -El $adapter -a netmask -F value`;
   $config{network_gateway} = `netstat -rn|grep default|awk '{print \$2}'`;
   $config{DNS} = `cat $Resolve | grep nameserver | awk '{print \$2}'`;
   }
}
elsif ($config{osversion} eq 'SOLARIS'){
   $config{oslevel} = `uname -r`;
   my @tmp = `/usr/platform/sun4u/sbin/prtdiag`;
   $tmp[0] =~ /System Configuration:\s+(.*)/;
   $config{model} = $1;
   undef @tmp;
   $config{serial} = "Not Available";
   $config{firmware} = `/usr/sbin/prtconf -V`;
   my @tmp = grep {s/auto-boot\?=//} `/usr/sbin/eeprom`;
   $config{auto_restart} = $tmp[0];
   undef @tmp;
   if (grep {/DUMPADM_ENABLE=yes/} `cat /etc/dumpadm.conf`){
      $config{full_core} = 'true';
   }
   else {
      $config{full_core} = 'false';
   }
   $config{lpar} = "Not Available";
   my @procs = grep {/sparc/i} `/usr/sbin/prtconf`;
   my @tmp = grep {s/.*,(\S+)\s+.*/$1/} @procs;
   $config{processor_type} = $tmp[0];
   my @tmp2 = grep {s/^.*\s+(\d+)\s+.*US-.*/$1/} `/usr/platform/sun4u/sbin/prtdiag`;
   $config{processor_speed} = $tmp2[0] . " MHz";
   $config{processor_number} = $#procs+1;
   $config{cpu_type} = "64-bit";
   $config{kernel_mode} = "64-bit";
   @tmp = ();
   @tmp = grep {/Memory size:/} `/usr/platform/sun4u/sbin/prtdiag`;
   $config{memory_size} =~ s/.*\s+(\d+)\s+.*/$1/;
   $config{page_space} = `swap -s`;
   $config{page_space} =~ s/^total:\s+(\d+)([mkg]).*/$1/ig;
   #todo convert k/m/g to mb
   my ($host) = `hostname`;
      chomp($host);
   my $ipaddr = gethostbyname($host);
   if ($ipaddr) {
      $config{IP} = (inet_ntoa($ipaddr));
   $grep = "/usr/xpg4/bin/grep";
   $config{mask} = `$grep -v \"#\" /etc/netmasks | awk \'{print \$2}\'`;
   $config{network_gateway} = `netstat -rn | $grep default | awk \'{print \$2}\'`;
   $config{DNS} = `cat $Resolve | $grep nameserver | awk \'{print \$2}\'`;
   }
}

elsif ($config{osversion} eq 'LINUX'){
   # do some heavy lifting with hal
   $config{oslevel} = `uname -r`;
   open(LSHAL, "/usr/bin/lshal |");
   while (<LSHAL>) {
	##if ( $_ =~ m/system\.hardware\.serial \=/ ) {
	if ( $_ =~ m/system.hardware.serial/ || $_ =~ m/smbios.system.serial/ ) {
	my @tmp = split("\'", $_);
	$config{serial} = @tmp[1] ;
	}
	if ( $_ =~ m/system.hardware.product/ || $_ =~ m/system.product/ ) {
        my @tmp = split("\'", $_);
        $config{model} = @tmp[1] ;
	}
	if ( $_ =~ m/system.firmware.release_date/ || $_ =~ m/smbios.bios.release_date/ ) {
        my @tmp = split("\'", $_);
        $config{firmware} = @tmp[1] ;
	}
	# version or release date for system.firmware ?
   } # end lshal while code
   close (LSHAL);
   undef @tmp;
   $config{auto_restart} = "Not Available";
   $config{full_core} = "Not Available";
   $config{lpar} = "Not Available";
   my @procinfo = `cat /proc/cpuinfo`;
   my @tmp = grep {s/^model name\s+:\s+(.*)/$1/} @procinfo;
   $config{processor_type} = $tmp[0];
   my @tmp2 = grep {s/^cpu MHz\s+:\s+(.*)/$1/} @procinfo;
   $config{processor_speed} = $tmp2[0] . " MHz";
   my %tmpcpu;
   foreach my $pline (@procinfo){
      if ($pline =~ /physical id\s+:\s+(\d+)/){
         $tmpcpu{$1} = 'true';
      }
      if ($pline =~ /cpu cores\s+:\s+(\d+)/){
         $tmpcpu{cores} = $1;
      }
   }
   if (!$tmpcpu{cores}){
	$tmpcpu{cores} = 1;
   }
   @tmp2 = ();
   @tmp2 = grep {/^\d+$/} keys %tmpcpu;
   $config{processor_number} = ($#tmp2+1) * $tmpcpu{cores};
   if ($config{processor_number} < 1){
      foreach my $pline (@procinfo){
         if ($pline =~ /processor\s+:\s+(\d+)/){
            $config{processor_number}++;
         }
      }
   }
   $config{cpu_type} = `uname -m`;
   $config{kernel_mode} = `uname -m`;
   my @memoryinfo = `free -m`;
   @tmp2 = ();
   @tmp2 = grep {/^(Mem|Swap)/} @memoryinfo;
   $tmp2[0] =~ s/^Mem:\s+(\d+)\s+.*/$1/;
   $config{memory_size} = $tmp2[0];
   #@tmp2 = ();
   #@tmp2 = grep {/^Swap:\s+\d+/} @memoryinfo;
   $tmp2[1] =~ s/^Swap:\s+(\d+)\s+.*/$1/;
   $config{swap_size} = $tmp2[1];

   if ( $config{model} =~ /KVM/ ) {
      @tmp = grep {s/\s*UUID:\s+([\w-]+)/$1/} `/usr/sbin/dmidecode`;
      chomp($tmp[0]);
      $config{serial} = "KVM," . $tmp[0];
   }

   if ( $config{model} =~ /HVM domU/ ) {
      @tmp = grep {s/\s*UUID:\s+([\w-]+)/$1/} `/usr/sbin/dmidecode`;
      chomp($tmp[0]);
      $config{serial} = "XEN," . $tmp[0];
   }

   my @module_list = `lsmod`;

   if (grep (/^xenblk\s+/, @module_list) ) {
      @tmp = grep {s/\s*UUID:\s+([\w-]+)/$1/} `/usr/sbin/dmidecode`;
      chomp($tmp[0]);
      $config{serial} = "XEN," . $tmp[0];
   }
   my ($host) = `hostname`;
      chomp($host);
   my $ipaddr = gethostbyname($host);
   if ($ipaddr) {
      $config{IP} = (inet_ntoa($ipaddr));
   }
   $adapter = `netstat -i|grep -vE \"Kernel|Iface|lo\"|awk '{print \$1}' | tail -1`;
      chomp($adapter);
   $config{mask} = `ifconfig $adapter | grep Mask: | cut -d':' -f4`;
   $config{network_gateway} = `route | grep -i default | awk '{print \$2}'`;
   $config{DNS} = `cat $Resolve | grep nameserver | awk '{print \$2}'`;
}

foreach my $key (keys %config){
      $config{$key} =~ s/\s+/ /g;
      chomp $config{$key};
}

print "System Information\n";
printf "\t%-32s= %s\n", "System Model", $config{model};
printf "\t%-32s= %s\n", "Serial Number", $config{serial};
printf "\t%-32s= %s\n", "Osversion", $config{osversion};
printf "\t%-32s= %s\n", "Oslevel", $config{oslevel};
printf "\t%-32s= %s\n", "Firmware version", $config{firmware};
printf "\t%-32s= %s\n", "Auto Restart", $config{auto_restart};
printf "\t%-32s= %s\n", "Full Core Dump", $config{full_core};
printf "\t%-32s= %s\n", "LPAR", $config{lpar};
print "\nProcessor Information\n";
printf "\t%-32s= %s\n", "Processor Type", $config{processor_type};
printf "\t%-32s= %s\n", "Processor Speed", $config{processor_speed};
printf "\t%-32s= %s\n", "Number of Processor(s)", $config{processor_number};
printf "\t%-32s= %s\n", "CPU TYPE", $config{cpu_type};
printf "\t%-32s= %s\n", "Kernel Mode", $config{kernel_mode};
print "\nMemory/Paging Information\n";
printf "\t%-32s= %s\n", "Memory Size", $config{memory_size};
printf "\t%-32s= %s\n", "Page Space", $config{swap_size};
print "\nNetwork Information\n";
printf "\t%-32s= %s\n", "IP Address", $config{IP};
printf "\t%-32s= %s\n",  "Mask" , $config{mask};
printf "\t%-32s= %s\n",  "Network Gateway" , $config{network_gateway};
printf "\t%-32s= %s\n",  "DNS" , $config{DNS};
