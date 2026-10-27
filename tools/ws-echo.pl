#!/usr/bin/env perl
# Minimal RFC6455 echo server used by tests/integration/ws-echo.sh.
# No CPAN deps: Digest::SHA / MIME::Base64 are core Perl modules.
use strict;
use warnings;
use IO::Socket::INET;
use Digest::SHA qw(sha1);
use MIME::Base64 qw(encode_base64);

$| = 1;
my $port = shift @ARGV // 19660;
my $listener = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1',
    LocalPort => $port,
    Proto     => 'tcp',
    Listen    => 16,
    ReuseAddr => 1,
) or die "listen $port: $!\n";
print "ws echo listening on 127.0.0.1:$port\n";
$SIG{CHLD} = 'IGNORE';

while (my $client = $listener->accept) {
    my $pid = fork();
    if (!defined $pid) { close $client; next; }
    if ($pid == 0) {
        close $listener;
        eval { handle($client) };
        close $client;
        exit 0;
    }
    close $client;
}

sub handle {
    my ($c) = @_;
    $c->autoflush(1);
    my $buf = '';
    while (index($buf, "\r\n\r\n") < 0) {
        my $n = sysread($c, my $chunk, 4096);
        return unless $n;
        $buf .= $chunk;
        return if length($buf) > 65536;
    }
    my ($head) = split(/\r\n\r\n/, $buf, 2);
    my ($key) = $head =~ /^Sec-WebSocket-Key:\s*(\S+)/mi;
    return unless $key;
    my $accept = encode_base64(
        sha1($key . "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"), ''
    );
    syswrite($c, "HTTP/1.1 101 Switching Protocols\r\n"
        . "Upgrade: websocket\r\n"
        . "Connection: Upgrade\r\n"
        . "Sec-WebSocket-Accept: $accept\r\n\r\n");

    while (1) {
        my $hdr = read_exact($c, 2);
        last unless defined $hdr;
        my ($b1, $b2) = unpack('CC', $hdr);
        my $opcode = $b1 & 0x0f;
        my $masked = $b2 & 0x80;
        my $len = $b2 & 0x7f;
        if ($len == 126) {
            my $ext = read_exact($c, 2);
            last unless defined $ext;
            $len = unpack('n', $ext);
        } elsif ($len == 127) {
            my $ext = read_exact($c, 8);
            last unless defined $ext;
            $len = unpack('Q>', $ext);
        }
        my $mask = $masked ? read_exact($c, 4) : '';
        last if $masked && !defined $mask;
        my $payload = $len ? read_exact($c, $len) : '';
        last if $len && !defined $payload;
        $payload = unmask($payload, $mask) if $masked;

        if ($opcode == 8) { # close
            syswrite($c, frame(8, $payload));
            last;
        } elsif ($opcode == 9) { # ping -> pong
            syswrite($c, frame(10, $payload));
        } elsif ($opcode == 10) { # pong: ignore
            next;
        } elsif ($opcode == 1 || $opcode == 2) { # text/binary
            syswrite($c, frame($opcode, $payload));
        }
    }
}

sub unmask {
    my ($payload, $mask) = @_;
    return '' unless length($payload);
    my $out = '';
    for my $i (0 .. length($payload) - 1) {
        $out .= chr(ord(substr($payload, $i, 1)) ^ ord(substr($mask, $i % 4, 1)));
    }
    return $out;
}

sub frame {
    my ($opcode, $payload) = @_;
    my $len = length($payload);
    my $head;
    if ($len < 126) {
        $head = pack('CC', 0x80 | $opcode, $len);
    } elsif ($len < 65536) {
        $head = pack('CCn', 0x80 | $opcode, 126, $len);
    } else {
        $head = pack('CCQ>', 0x80 | $opcode, 127, $len);
    }
    return $head . $payload;
}

sub read_exact {
    my ($c, $need) = @_;
    my $out = '';
    while (length($out) < $need) {
        my $n = sysread($c, my $chunk, $need - length($out));
        return undef unless $n;
        $out .= $chunk;
    }
    return $out;
}
