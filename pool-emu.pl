#! /usr/bin/perl

use warnings;
use strict;
use IO::Socket::INET;
use Socket;

my $PORT	= 3333;
my $NONCE_1	= "00";
my $VERSION	= "04000000";

my $TARGET	= "ff" x 32;
my $PREVHASH	= "00" x 32;
my $MERKLEROOT	= "00" x 32;
my $RESERVED	= "00" x 32;
my $TIME	= "00" x 4;
my $BITS	= "00" x 4;

my $q_el  = qr/"[^"]*"|\d+|true|false|null/;
my $q_els = qr/$q_el(,$q_el)*/;

my ($srv, $cli, $id, $method, $params);

sub rx_method() {
	$_ = <$cli>;
	die "disconnected\n" if !defined;
	print "got $_";
	s/\s//g;
	($id, $method, $params) =
	    /^{"id":(\d+),"method":"([^"]+)","params":\[$q_els?\]}\z/
		or die "bad json rpc\n$_\n";
	return $method;
}

sub tx($) {
	my ($str) = @_;

	$str =~ s/\s//g;
	print "sending $str\n";
	print $cli "$str\n";
}

sub tx_result($) {
	my ($result) = @_;

	tx qq<
		{
			"id": $id,
			"result": $result,
			"error": null
		}
	>;
}

sub client {
	$cli = undef;
	$cli = $srv->accept;

	my @addr = sockaddr_in ($cli->peername);
	my $addr = inet_ntoa ($addr[1]) . ":$addr[0]";
	print "connected from $addr\n";

	rx_method eq 'mining.subscribe' or die;
	tx_result qq<
		[ "s$$-${\time}-$addr", "$NONCE_1" ]
	>;

	rx_method eq 'mining.authorize' or die;
	tx_result 'true';

	sleep 1;
	tx qq<
		{
			"id": null,
			"method": "mining.target",
			"params": ["$TARGET"]
		}
	>;

	rx_method eq 'mining.extranonce.subscribe' or die;

	sleep 1;
	tx qq<
		{
			"id": null,
			"method": "mining.notify",
			"params": [
				"j$$-${\time}", "$VERSION", "$PREVHASH",
				"$MERKLEROOT", "$RESERVED", "$TIME", "$BITS",
				true
			]
		}
	>;

	while (1) {
		rx_method eq 'mining.submit' or die;
		tx_result 'true';
	}
}

$srv = IO::Socket::INET->new (Listen => 1, LocalPort => $PORT);
print "listening\n";
print eval { client () } || $@ while 1;
