package blake2b;

# RFC 7693, https://en.wikipedia.org/wiki/BLAKE_(hash_function)

use warnings;
use strict;

#use Carp; $SIG{__WARN__} = sub { confess "@_" };

~0 == 18446744073709551615 or die "no 64 bit";

my @IV = do { no warnings 'portable';
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
	0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f,
	0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
};

my @sigma = (
	[  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ],
	[ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ],
	[ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 ],
	[  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 ],
	[  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 ],
	[  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 ],
	[ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 ],
	[ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 ],
	[  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 ],
	[ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 ],
	[  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ],
	[ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ],
);

sub ror64 {
	my ($x, $n) = @_;

	$x >> $n | ($x & (1 << $n) - 1) << 64 - $n;
}

sub add64 {
	my ($a, $b) = @_;

	my $f = (1 << 32) - 1;
	my $l = ($a & $f) + ($b & $f);
	my $h = ($a >> 32) + ($b >> 32) + ($l > $f ? 1 : 0);

	($h & $f) << 32 | $l & $f;
}

my (@m, @v);

sub G {
	my $r = $_[0];
	my $i = $_[1];
	our $a; local *a = \$_[2];
	our $b; local *b = \$_[3];
	our $c; local *c = \$_[4];
	our $d; local *d = \$_[5];

	$a = add64 (add64 ($a, $b), $m[ $sigma[$r][2*$i+0] ]);
	$d = ror64 ($d ^ $a, 32);
	$c = add64 ($c, $d);
	$b = ror64 ($b ^ $c, 24);
	$a = add64 (add64 ($a, $b), $m[ $sigma[$r][2*$i+1] ]);
	$d = ror64 ($d ^ $a, 16);
	$c = add64 ($c, $d);
	$b = ror64 ($b ^ $c, 63);
}

sub ROUND {
	my ($r) = @_;

	G ($r, 0, $v[ 0], $v[ 4], $v[ 8], $v[12]);
	G ($r, 1, $v[ 1], $v[ 5], $v[ 9], $v[13]);
	G ($r, 2, $v[ 2], $v[ 6], $v[10], $v[14]);
	G ($r, 3, $v[ 3], $v[ 7], $v[11], $v[15]);
	G ($r, 4, $v[ 0], $v[ 5], $v[10], $v[15]);
	G ($r, 5, $v[ 1], $v[ 6], $v[11], $v[12]);
	G ($r, 6, $v[ 2], $v[ 7], $v[ 8], $v[13]);
	G ($r, 7, $v[ 3], $v[ 4], $v[ 9], $v[14]);
}

sub block {
	my ($h, $chunk, $last) = @_;

	length $chunk == 128 or die;

	@m = unpack 'Q<*', $chunk;

	@v = (@{ $h->{Sh} }, @IV);
	$v[12] ^= $h->{len}; # XXX len128
	$v[14] ^= ~0 if $last;

	ROUND ($_) for 0..11;

	$h->{Sh}[$_] ^= $v[$_] ^ $v[$_ + 8] for 0..7;
}

my $PAD = "\0" x 128;

sub new {
	my $h = bless {
		hashlen		=> 256/8,
		key		=> '',
		salt		=> '',
		personal	=> '',
		buf		=> '',
		len		=> 0,
		@_
	};

	die "bad hash len"	if $h->{hashlen} > 512/8;
	die "bad key len"	if length $h->{key} > 128;
	die "bad personal len"	if length $h->{personal} > 16;

	$h->{Sh} = [ unpack 'Q<*', pack ('Q<*', @IV) ^
		pack ('C C C C @32 a16 a16', $h->{hashlen}, length $h->{key},
		1, 1, $h->{salt}, $h->{personal}) ];

	$h->update ($h->{key} | $PAD) if length $h->{key};

	return $h;
}

sub update {
	my ($h, $buf) = @_;

	$h->{buf} .= $buf;
	while (length ($h->{buf}) > 128) {
		(my $chunk, $h->{buf}) = unpack 'a128 a*', $h->{buf};
		$h->{len} += length $chunk; # XXX len128
		$h->block ($chunk, 0);
	}
	return $h;
}

sub final {
	my ($h, $buf) = @_;

	$h->update ($buf);
	length $h->{buf} <= 128 or die;
	$h->{len} += length $h->{buf};
	$h->block ($h->{buf} | $PAD, 1);
	return unpack "a$h->{hashlen}", pack 'Q<*', @{ $h->{Sh} };
}

sub copy { my ($h) = @_; bless { %$h, Sh => [ @{ $h->{Sh} } ] } }

sub blake2b { my ($buf) = @_; new ()->final ($buf) }

my %test = (
"" =>
	"0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
"The quick brown fox jumps over the lazy dog" =>
	"01718cec35cd3d796dd00020e0bfecb473ad23457d063b75eff29c0ffa2e58a9",
);

for (sort keys %test) {
	my $x = blake2b ($_);
	$x eq pack 'H*', $test{$_}
		or die "$_: ${\unpack 'H*', $x} != $test{$_}";
}

1;
