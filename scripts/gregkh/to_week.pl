#!/usr/bin/perl -w

use strict;
use Time::Piece;

my $indata = $ARGV[0];
my $date = Time::Piece->strptime($indata, '%Y-%m-%d');
print $date->week;
print "\n";
