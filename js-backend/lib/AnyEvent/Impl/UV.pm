=head1 NAME

AnyEvent::Impl::UV - AnyEvent adaptor for UV

=head1 SYNOPSIS

   use AnyEvent;
   use UV;
  
   # this module gets loaded automatically as required

=head1 DESCRIPTION

This module provides transparent support for AnyEvent. You don't have to
do anything to make UV work with AnyEvent except by loading UV before
creating the first AnyEvent watcher.

=cut

package AnyEvent::Impl::UV;

use AnyEvent (); BEGIN { AnyEvent::common_sense }
use UV 0.24;
use Scalar::Util qw(weaken);

sub warnlog {
   my $err = UV::last_error;

   AnyEvent::log warn => "returned $_[0]: "
                         . UV::err_name ($err) . "($err): "
                         . UV::strerror ($err);

   @_
}

# https://github.com/joyent/libuv/issues/680
# https://github.com/joyent/libuv/blob/dc1ea27c736f0d21c7160c790bcd1b113d20abd9/include/uv.h#L1277
my %io_watchers;

sub io_watcher_cb {
   my $slaves = shift;
   my (undef, $events) = @_;
   return unless defined $slaves;

   foreach my $entry (keys %$slaves) {
      my $slave = $slaves->{$entry};
      $slave->{cb}(@_) if $slave->{mode} & $events;
   }
}

sub AnyEvent::Impl::UV::io_slave::new {
   bless { parent => $_[1] }, $_[0]
}

sub AnyEvent::Impl::UV::io_slave::DESTROY {
   my $self   = $_[0];
   my $master = $self->{parent};

   delete $master->{slaves}{$self};
   if (keys %{$master->{slaves}} == 0) {
      if (defined $master->{w}) {
         my $rc = UV::poll_stop $master->{w};
         warnlog $rc if $rc;
      }
      delete $io_watchers{$master->{fd}};
      return;
   }

   my $mode = 0;
   foreach my $entry (keys %{$master->{slaves}}) {
      $mode |= $master->{slaves}{$entry}{mode};
   }

   if ($master->{mode} != $mode) {
      $master->{mode} = $mode;
      my $rc = UV::poll_start $master->{w}, $master->{mode}, sub {
         io_watcher_cb $master->{slaves}, @_;
      };
      warnlog $rc if $rc;
   }
}

sub io {
   my ($class, %arg) = @_;
   my $fd = fileno $arg{fh};
   defined $fd or $fd = $arg{fh};

   my $master = $io_watchers{$fd} ||= { fd => $fd };

   unless (defined $master->{w}) {
      $master->{w} = UV::poll_init $fd;
      return warnlog $master->{w} unless defined $master->{w};
      $master->{slaves} = {};
   }

   my $slave = AnyEvent::Impl::UV::io_slave->new ($master);
   weaken ($master->{slaves}->{$slave} = $slave);

   $slave->{mode}  = $arg{poll} eq "r" ? UV::READABLE : UV::WRITABLE;
   $master->{mode} = 0 unless defined $master->{mode};
   $slave->{cb}    = $arg{cb};

   unless ($master->{mode} & $slave->{mode}) {
      $master->{mode} |= $slave->{mode};
      my $rc = UV::poll_start $master->{w}, $master->{mode}, sub {
         io_watcher_cb $master->{slaves}, @_;
      };
      warnlog $rc if $rc;
   }

   $slave
}

sub AnyEvent::Impl::UV::handle::new {
   my ($class, $w, $start, $stop, @args) = @_;
   return warnlog $w unless defined $w;

   my $rc = $start->($w, @args);
   warnlog $rc if $rc;

   bless { w => $w, stop => $stop }, $class
}

sub AnyEvent::Impl::UV::handle::DESTROY {
   my $h  = $_[0];
   return unless $h->{w};
   my $rc = $h->{stop}($h->{w});
   warnlog $rc if $rc;
   UV::close $h->{w};
}

sub idle {
   my ($class, %arg) = @_;

   AnyEvent::Impl::UV::handle->new (
      UV::timer_init,
      \&UV::idle_start,
      \&UV::idle_stop,
      $arg{cb}
   );
}

sub timer {
   my ($class, %arg) = @_;

   AnyEvent::Impl::UV::handle->new (
      UV::timer_init,
      \&UV::timer_start,
      \&UV::timer_stop,
      $arg{after} * 1000, $arg{interval} * 1000, $arg{cb}
   );
}

sub now { UV::now }

sub _poll {
   UV::run UV::RUN_ONCE;
}

sub AnyEvent::CondVar::Base::_wait {
   UV::run UV::RUN_NOWAIT until exists $_[0]{_ae_sent};
}

=head1 SEE ALSO

L<AnyEvent>, L<UV>.

=head1 AUTHOR

 Mike Lowell <mikedotlowell@gmail.com>

=cut

1

