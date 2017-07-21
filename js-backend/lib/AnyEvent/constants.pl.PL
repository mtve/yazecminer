#! perl

# this file is unfortunately only executed at Makefile.PL time

my ($fh, $oldstdout);

BEGIN {
   open $fh, ">constants.pl"
      or die "constants.pl: $!\n";

   $oldstdout = select $fh;

   print "# automatically generated from constants.pl.PL\n";
}

{
   # from common::sense 3.7
   use strict qw(vars subs);
   no warnings;
   use warnings qw(FATAL closed threads internal debugging pack malloc portable prototype
                   inplace io pipe unpack deprecated glob digit printf
                   layer reserved taint closure semicolon);
   no warnings qw(exec newline unopened);

   BEGIN {
      print "sub AnyEvent::common_sense {\n";
      printf "   local \$^W;\n";
      printf "   \${^WARNING_BITS} ^= \${^WARNING_BITS} ^ \"%s\";\n",
             join "", map "\\x$_", unpack "(H2)*", ${^WARNING_BITS};
      # use strict, use utf8;
      printf "   \$^H |= 0x%x;\n", $^H;
      print "}\n";
   }
}

use Config;

print "# generated for perl $] built for $Config{archname}\n";

# when built as part of perl, these are not available
BEGIN { eval "use Socket ()" }
BEGIN { eval "use Fcntl  ()" }
BEGIN { eval "use POSIX  ()" }

sub i($$) {
   print "sub $_[0](){", $_[1]*1, "}\n";
}

sub n($$) {
   print "sub $_[0](){", (defined $_[1] ? $_[1]*1 : "undef"), "}\n";
}

print "package AnyEvent;\n";

our $WIN32 = $^O =~ /mswin32/i;

# used a lot
i CYGWIN => $^O =~ /cygwin/i;
i WIN32  => $WIN32;

# add these purely to avoid loading Fcntl, which is slow and bloated.

i F_SETFD    => eval { Fcntl::F_SETFD() } || 2;
i F_SETFL    => eval { Fcntl::F_SETFL() } || 4;
i O_NONBLOCK => eval { Fcntl::O_NONBLOCK() } || 04000;
i FD_CLOEXEC => eval { Fcntl::FD_CLOEXEC() } || 1;

print "package AnyEvent::Base;\n";

# add these purely to avoid loading POSIX, which is slow and bloated.

i WNOHANG    => eval { POSIX::WNOHANG() } || 1;

print "package AnyEvent::IO;\n";

i O_RDONLY   => eval { Fcntl::O_RDONLY() } || 0;
i O_WRONLY   => eval { Fcntl::O_WRONLY() } || 1;
i O_RDWR     => eval { Fcntl::O_RDWR  () } || 2;
i O_CREAT    => eval { Fcntl::O_CREAT () } || 64;
i O_EXCL     => eval { Fcntl::O_EXCL  () } || 128;
i O_TRUNC    => eval { Fcntl::O_TRUNC () } || 512;
i O_APPEND   => eval { Fcntl::O_APPEND() } || 1024;

print "package AnyEvent::Util;\n";

# broken windows perls use undocumented error codes...
if ($WIN32) {
   i WSAEINVAL      => 10022;
   i WSAEWOULDBLOCK => 10035;
   i WSAEINPROGRESS => 10036;
} else {
   # these should never match any errno value
   i WSAEINVAL      => -1e99;
   i WSAEWOULDBLOCK => -1e99;
   i WSAEINPROGRESS => -1e99;
}

my $af_inet6;

$af_inet6 ||= eval {                  Socket::AF_INET6 () }; # where it should be
$af_inet6 ||= eval { require Socket6; Socket6::AF_INET6() }; # where it actually is ...

# ... or isn't, because nobody has it installed
$af_inet6 ||= 10 if $^O =~ /linux/;
$af_inet6 ||= 23 if $^O =~ /cygwin/i;
$af_inet6 ||= 23 if AnyEvent::WIN32;
$af_inet6 ||= 24 if $^O =~ /openbsd|netbsd/;
$af_inet6 ||= 28 if $^O =~ /freebsd/;

#TODO: EDOM/ESPIPE
#TODO: maybe move socket stuff to Socket::?

i _AF_INET6     => $af_inet6;
#i AF_UNIX      => Socket::AF_UNIX ();
#i SOCK_STREAM  => Socket::SOCK_STREAM ();
#i SOCK_DGRAM   => Socket::SOCK_DGRAM ();
#i SOL_SOCKET   => Socket::SOL_SOCKET ();
#i SO_REUSEADDR => Socket::SO_REUSEADDR ();
#i SO_KEEPALIVE => Socket::SO_KEEPALIVE ();
#i SO_OOBINLINE => Socket::SO_OOBINLINE ();
#i IPPROTO_TCP  => Socket::IPPROTO_TCP ();

print "package AnyEvent::Socket;\n";

# more hardcoded os-specific constants - none
# of these are available via any known module, but we
# are forward-looking and try Socket:: anyways.
my %const;

while (<DATA>) {
   my ($os, $name, $default) = split /\s+/;

   $const{$name} ||= undef; # make sure it exists

   next unless $os eq $^O;

   my $value = eval "Socket::$name ()";
   $value = eval $default unless defined $value;

   $const{$name} = $value;
}

for my $k (sort keys %const) {
   n $k, $const{$k};
}

print "1;\n";

close $fh;
select $oldstdout;

1

__DATA__
linux	TCP_MAXSEG	2
linux	TCP_CORK	3
linux	TCP_KEEPIDLE	4
linux	TCP_KEEPINTVL	5
linux	TCP_KEEPCNT	6
linux	TCP_SYNCNT	7
linux	TCP_LINGER2	8
linux	TCP_DEFER_ACCEPT	9
linux	TCP_WINDOW_CLAMP	10
linux	TCP_INFO	11
linux	TCP_QUICKACK	12
linux	TCP_CONGESTION	13
linux	TCP_MD5SIG	14
netbsd	TCP_MAXSEG	2
netbsd	TCP_KEEPIDLE	3
netbsd	TCP_NOPUSH	4
netbsd	TCP_KEEPINTVL	5
netbsd	TCP_KEEPCNT	6
netbsd	TCP_KEEPINIT	7
netbsd	TCP_NOOPT	8
netbsd	TCP_MD5SIG	0x10
netbsd	TCP_CONGESTION	0x20
cygwin  TCP_MAXSEG      0x02
cygwin  TCP_NOPUSH      0x04
cygwin  TCP_NOOPT       0x08
freebsd	TCP_MAXSEG	0x02
freebsd	TCP_NOPUSH	0x04
freebsd	TCP_NOOPT	0x08
freebsd	TCP_MD5SIG	0x10
freebsd	TCP_INFO	0x20
freebsd	TCP_CONGESTION	0x40
solaris	TCP_CORK	0x18
solaris	TCP_LINGER2	0x1C
solaris	TCP_INIT_CWND	0x15
solaris	TCP_KEEPALIVE	0x8
solaris	TCP_MAXSEG	0x02
openbsd	TCP_MAXSEG	0x02
openbsd	TCP_MD5SIG	0x04
openbsd	TCP_SACK_ENABLE	0x08
darwin	TCP_MAXSEG	0x02
darwin	TCP_NOPUSH	0x04
darwin	TCP_NOOPT	0x08
darwin	TCP_KEEPALIVE	0x10
darwin	TCP_CONNECTIONTIMEOUT	0x20
