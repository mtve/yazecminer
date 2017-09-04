# automatically generated from constants.pl.PL
sub AnyEvent::common_sense {
   local $^W;
   ${^WARNING_BITS} ^= ${^WARNING_BITS} ^ "\x3c\x3f\x33\x00\x0f\xf0\x0f\xc0\xf0\xfc\x33\x00\x00\x00\x0c\x00\x00";
   $^H |= 0x7c0;
}
# generated for perl 5.024002 built for amd64-freebsd
package AnyEvent;
sub CYGWIN(){0}
sub WIN32(){0}
sub F_SETFD(){2}
sub F_SETFL(){4}
sub O_NONBLOCK(){4}
sub FD_CLOEXEC(){1}
package AnyEvent::Base;
sub WNOHANG(){1}
package AnyEvent::IO;
sub O_RDONLY(){0}
sub O_WRONLY(){1}
sub O_RDWR(){2}
sub O_CREAT(){512}
sub O_EXCL(){2048}
sub O_TRUNC(){1024}
sub O_APPEND(){8}
package AnyEvent::Util;
sub WSAEINVAL(){-1e+99}
sub WSAEWOULDBLOCK(){-1e+99}
sub WSAEINPROGRESS(){-1e+99}
sub _AF_INET6(){28}
package AnyEvent::Socket;
sub TCP_CONGESTION(){64}
sub TCP_CONNECTIONTIMEOUT(){undef}
sub TCP_CORK(){undef}
sub TCP_DEFER_ACCEPT(){undef}
sub TCP_INFO(){32}
sub TCP_INIT_CWND(){undef}
sub TCP_KEEPALIVE(){undef}
sub TCP_KEEPCNT(){undef}
sub TCP_KEEPIDLE(){undef}
sub TCP_KEEPINIT(){undef}
sub TCP_KEEPINTVL(){undef}
sub TCP_LINGER2(){undef}
sub TCP_MAXSEG(){2}
sub TCP_MD5SIG(){16}
sub TCP_NOOPT(){8}
sub TCP_NOPUSH(){4}
sub TCP_QUICKACK(){undef}
sub TCP_SACK_ENABLE(){undef}
sub TCP_SYNCNT(){undef}
sub TCP_WINDOW_CLAMP(){undef}
1;
