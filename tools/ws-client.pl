#!/usr/bin/env perl
# Minimal RFC6455 client: verifies text, binary, ping/pong and close through edge.
use strict;
use warnings;
use IO::Socket::INET;
use Digest::SHA qw(sha1);
use MIME::Base64 qw(encode_base64);

$| = 1;
my ($host, $port, $domain, $path) = @ARGV;
$host //= '127.0.0.1';
$port //= 18542;
$domain //= 'ws.test';
$path //= '/';

my $sock = IO::Socket::INET->new(
    PeerAddr => $host,
    PeerPort => $port,
    Proto    => 'tcp',
    Timeout  => 5,
) or die "connect $host:$port: $!\n";
$sock->autoflush(1);
binmode($sock);

my $key = encode_base64(join('', map { chr(int(rand(256))) } 1 .. 16), '');
syswrite($sock, "GET $path HTTP/1.1\r\n"
    . "Host: $domain\r\n"
    . "Upgrade: websocket\r\n"
    . "Connection: Upgrade\r\n"
    . "Sec-WebSocket-Key: $key\r\n"
    . "Sec-WebSocket-Version: 13\r\n\r\n");

my $head = '';
while (index($head, "\r\n\r\n") < 0) {
    my $n = sysread($sock, my $chunk, 4096);
    die "handshake closed\n" unless $n;
    $head .= $chunk;
    die "handshake too large\n" if length($head) > 65536;
}
die "handshake not 101:\n$head" unless $head =~ m{^HTTP/1\.1 101};
my ($accept) = $head =~ /^Sec-WebSocket-Accept:\s*(\S+)/mi;
my $want = encode_base64(sha1($key . "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"), '');
die "bad accept: got='$accept' want='$want'\n" unless defined $accept && $accept eq $want;

sub send_frame {
    my ($opcode, $payload) = @_;
    my $mask = join('', map { chr(int(rand(256))) } 1 .. 4);
    my $masked = '';
    for my $i (0 .. length($payload) - 1) {
        $masked .= chr(ord(substr($payload, $i, 1)) ^ ord(substr($mask, $i % 4, 1)));
    }
    my $len = length($payload);
    my $head;
    if ($len < 126) {
        $head = pack('CC', 0x80 | $opcode, 0x80 | $len);
    } elsif ($len < 65536) {
        $head = pack('CCn', 0x80 | $opcode, 0x80 | 126, $len);
    } else {
        $head = pack('CCQ>', 0x80 | $opcode, 0x80 | 127, $len);
    }
    syswrite($sock, $head . $mask . $masked);
}

sub read_exact {
    my ($need) = @_;
    my $out = '';
    while (length($out) < $need) {
        my $n = sysread($sock, my $chunk, $need - length($out));
        die "socket closed\n" unless $n;
        $out .= $chunk;
    }
    return $out;
}

sub read_frame {
    my $h = read_exact(2);
    my ($b1, $b2) = unpack('CC', $h);
    my $opcode = $b1 & 0x0f;
    my $len = $b2 & 0x7f;
    if ($len == 126) {
        $len = unpack('n', read_exact(2));
    } elsif ($len == 127) {
        $len = unpack('Q>', read_exact(8));
    }
    my $mask = ($b2 & 0x80) ? read_exact(4) : '';
    my $payload = $len ? read_exact($len) : '';
    if ($b2 & 0x80) {
        my $out = '';
        for my $i (0 .. length($payload) - 1) {
            $out .= chr(ord(substr($payload, $i, 1)) ^ ord(substr($mask, $i % 4, 1)));
        }
        $payload = $out;
    }
    return ($opcode, $payload);
}

sub expect {
    my ($want_op, $want_payload, $label) = @_;
    my ($op, $payload) = read_frame();
    die "$label: opcode $op, expected $want_op\n" unless $op == $want_op;
    die "$label: payload mismatch\n" unless $payload eq $want_payload;
    print "ok   $label\n";
}

send_frame(1, 'hello over websocket');
expect(1, 'hello over websocket', 'text echo');

my $binary = "\x00\x01\x02binary\xff";
send_frame(2, $binary);
expect(2, $binary, 'binary echo');

send_frame(9, 'ping-data');
expect(10, 'ping-data', 'ping/pong');

send_frame(8, '');
my ($op) = read_frame();
die "close: opcode $op\n" unless $op == 8;
print "ok   close handshake\n";
print "WS_ECHO_OK\n";
