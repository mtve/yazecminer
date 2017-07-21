=head1 NAME

AnyEvent::Impl::Glib - AnyEvent adaptor for Glib

=head1 SYNOPSIS

   use AnyEvent;
   use Glib;
  
   # this module gets loaded automatically as required

=head1 DESCRIPTION

This module provides transparent support for AnyEvent. You don't have to
do anything to make Glib work with AnyEvent except by loading Glib before
creating the first AnyEvent watcher.

Glib is probably the most inefficient event loop that has ever seen the
light of the world: Glib not only scans all its watchers (really, ALL of
them, whether I/O-related, timer-related or what not) during each loop
iteration, it also does so multiple times and rebuilds the poll list for
the kernel each time again, dynamically even. Newer versions of libglib
fortunately do not call malloc/free on every single watcher invocation,
though.

Glib also enforces certain undocumented behaviours, for example, you
cannot always remove active child watchers, and the conditions on when
it is valid to do so are not documented. Of course, if you get it wrong,
you get "GLib-CRITICAL" messages. This makes it extremely hard to write
"correct" glib programs, as you have to study the source code to get it
right, and hope future versions don't change any internals.

AnyEvent implements the necessary workarounds, at a small performance
cost.

On the positive side, and most importantly, when it works, Glib generally
works correctly, no quarrels there.

If you create many watchers (as in: more than two), you might consider one
of the L<Glib::EV>, L<EV::Glib> or L<Glib::Event> modules that map Glib to
other, more efficient, event loops.

This module uses the default Glib main context for all its watchers.

=cut

package AnyEvent::Impl::Glib;

use AnyEvent (); BEGIN { AnyEvent::common_sense }
use Glib 1.210 (); # (stable 1.220 2009, also Glib 2.4+ required, 2004)

our $mainloop = Glib::MainContext->default;

my %io_cond = (
   r => ["in" , "hup"],
   w => ["out", "hup"],
);

sub io {
   my ($class, %arg) = @_;
   
   my $cb = $arg{cb};
   my $fd = fileno $arg{fh};
   defined $fd or $fd = $arg{fh};

   my $source = add_watch Glib::IO
      $fd,
      $io_cond{$arg{poll}},
      sub { &$cb; 1 };

   bless \\$source, $class
}

sub timer {
   my ($class, %arg) = @_;
   
   my $cb   = $arg{cb};
   my $ival = $arg{interval} * 1000;

   my $source; $source = add Glib::Timeout $arg{after} < 0 ? 0 : $arg{after} * 1000,
      $ival ? sub {
                remove Glib::Source $source;
                $source = add Glib::Timeout $ival, sub { &$cb; 1 };
                &$cb;
                1 # already removed, should be a nop
              }
            : sub {
               # due to the braindamaged libglib API (it manages
               # removed-but-active watchers internally, but forces
               # users to # manage the same externally as well),
               # we have to go through these contortions.
               remove Glib::Source $source;
               undef $source;
               &$cb;
               1 # already removed, should be a nop
            };

   bless \\$source, $class
}

sub idle {
   my ($class, %arg) = @_;
   
   my $cb = $arg{cb};
   my $source = add Glib::Idle sub { &$cb; 1 };

   bless \\$source, $class
}

sub DESTROY {
   remove Glib::Source $${$_[0]}
      if defined $${$_[0]};
}

our %pid_w;
our %pid_cb;

sub child {
   my ($class, %arg) = @_;

   $arg{pid} > 0
      or Carp::croak "Glib does not support watching for all pids (pid == 0) as attempted";

   my $pid = $arg{pid};
   my $cb  = $arg{cb};

   $pid_cb{$pid}{$cb+0} = $cb;

   $pid_w{$pid} ||= Glib::Child->watch_add ($pid, sub {
      # the unbelievably braindamaged glib api ignores the return
      # value and always removes the watcher (this is of course
      # undocumented), so we need to go through these contortions to
      # work around this, here and in DESTROY.
      undef $pid_w{$pid};

      $_->($_[0], $_[1])
         for values %{ $pid_cb{$pid} };

      1 # gets ignored
   });

   bless [$pid, $cb+0], "AnyEvent::Impl::Glib::child"
}

sub AnyEvent::Impl::Glib::child::DESTROY {
   my ($pid, $icb) = @{ $_[0] };

   delete $pid_cb{$pid}{$icb};
   unless (%{ $pid_cb{$pid} }) {
      delete $pid_cb{$pid};
      my $source = delete $pid_w{$pid};
      remove Glib::Source if defined $source;
   }
}

#sub loop {
#   # hackish, but we do not have a mainloop, just a maincontext
#   $mainloop->iteration (1) while 1;
#}

sub _poll {
   $mainloop->iteration (1);
}

sub AnyEvent::CondVar::Base::_wait {
   $mainloop->iteration (1) until exists $_[0]{_ae_sent};
}

=head1 SEE ALSO

L<AnyEvent>, L<Glib>.

=head1 AUTHOR

 Marc Lehmann <schmorp@schmorp.de>
 http://anyevent.schmorp.de

=cut

1

