#! /usr/bin/perl

use warnings;
use strict;
use IO::Socket::INET;
use Socket;

use equihash;

my $PORT	= 3333;
my $NONCE_1	= "00";
my $VERSION	= "04000000";

my $TARGET	= "ff" x 32;
my $PREVHASH	= "00" x 32;
my $MERKLEROOT	= "00" x 32;
my $RESERVED	= "00" x 32;
my $TIME	= "00" x 4;
my $BITS	= "00" x 4;

#$TARGET=	'7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
#$PREVHASH =	'20d6248dde17eb4d7663a055c4a972706547440bdceafb47ff05511900000000';
#$MERKLEROOT =	'a3f34f8722f0af6fc0f0d0271533de88eb4fe27d99d843128306d6d285b404f4';
#$TIME = '7da0bf58';
#$BITS = 'c19d001d';

$TARGET = "00083126e978d4fdf3b645a1cac083126e978d4fdf3b645a1cac083126e978d4";

$PREVHASH	= "361b2757e8ca6adbc90ff2965580545dc749a9dbf731d50f6517af1f00000000";
$MERKLEROOT	= "c0be5cdab2a7678a9401f2014f92b9bc395fd4559a66b72d45303fe50bacdc22";
$TIME = "22dc7059";
$BITS = "8280291c";
$NONCE_1 = "0159f1901f" . "b22da6ddc113";

my $q_el  = qr/"[^"]*"|\d+|true|false|null/;
my $q_els = qr/$q_el(,$q_el)*/;

my ($srv, $cli, $id, $method, $params);

sub rx_method($) {
	my ($expected) = @_;

	$_ = <$cli>;
	die "disconnected\n" if !defined;
	print "got $_";
	s/\s//g;
	($id, $method, $params) =
	    /^{"id":(\d+),"method":"([^"]+)","params":\[($q_els?)\]}\z/
		or die "bad json rpc\n$_\n";
	$method eq $expected
		or die "expected method $expected got $method";
	return $params;
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

	rx_method 'mining.subscribe';
	tx_result qq<
		[ "s$$-${\time}-$addr", "$NONCE_1" ]
	>;

	rx_method 'mining.authorize';
	tx_result 'true';

	sleep 1;
	tx qq<
		{
			"id": null,
			"method": "mining.target",
			"params": ["$TARGET"]
		}
	>;

	rx_method 'mining.extranonce.subscribe';

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
		my @param = map /"(.*)"/, split ',', rx_method 'mining.submit';
		@param == 5 or die @param;
		$param[2] eq $TIME or die;
		my $block = $VERSION . $PREVHASH . $MERKLEROOT . $RESERVED .
			$TIME . $BITS . $NONCE_1 . $param[3] . $param[4];
		equihash::verify (pack 'H*', $block);
		tx_result 'true';
	}
}

$srv = IO::Socket::INET->new (Listen => 1, LocalPort => $PORT, ReuseAddr => 1)
	or die $!;
print "listening\n";
print eval { client () } || $@ while 1;
