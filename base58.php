<?php
namespace libmona;

use Exception;
use Throwable;

const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58_encode(string $bin): string {
    $alphabet = B58_ALPHABET;
    $x = gmp_init(bin2hex($bin), 16);
    $out = "";
    while (gmp_cmp($x, 0) > 0) {
        [$x, $rem] = [gmp_div_q($x, 58), gmp_intval(gmp_mod($x, 58))];
        $out = $alphabet[$rem] . $out;
    }

    for ($i = 0; $i < strlen($bin) && $bin[$i] === "\x00"; $i++) {
        $out = "1" . $out;
    }

    return $out === "" ? "1" : $out;
}

function base58_decode(string $s): string {
    $alphabet = B58_ALPHABET;
    $map = array_flip(str_split($alphabet));
    $x = gmp_init(0, 10);
    $chars = str_split($s);

    foreach ($chars as $c) {
        if (!isset($map[$c])) {
            throw new Exception("invalid base58 char");
        }
        $x = gmp_add(gmp_mul($x, 58), $map[$c]);
    }

    $hex = gmp_strval($x, 16);
    if (strlen($hex) % 2) {
        $hex = "0" . $hex;
    }
    $bin = hex2bin_safe($hex);

    $nLeading = 0;
    for ($i = 0; $i < strlen($s) && $s[$i] === "1"; $i++) {
        $nLeading++;
    }
    return str_repeat("\x00", $nLeading) . $bin;
}

function base58check_encode(string $payload): string {
    $cs = substr(sha256d($payload), 0, 4);
    return base58_encode($payload . $cs);
}

function base58check_decode(string $s): string {
    $raw = base58_decode($s);
    if (strlen($raw) < 5) {
        throw new Exception("too short");
    }

    $payload = substr($raw, 0, -4);
    $cs = substr($raw, -4);
    $calc = substr(sha256d($payload), 0, 4);

    if (!hash_equals($cs, $calc)) {
        throw new Exception("bad checksum");
    }

    return $payload;
}
