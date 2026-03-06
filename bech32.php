<?php
namespace libmona;

use Exception;
use Throwable;
function bech32_polymod(array $values): int {
    $gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    $chk = 1;
    foreach ($values as $v) {
        $top = $chk >> 25;
        $chk = (($chk & 0x1ffffff) << 5) ^ $v;
        for ($i = 0; $i < 5; $i++) {
            if (($top >> $i) & 1) {
                $chk ^= $gen[$i];
            }
        }
    }
    return $chk;
}

function bech32_hrp_expand(string $hrp): array {
    $out = [];
    $len = strlen($hrp);
    for ($i = 0; $i < $len; $i++) {
        $out[] = ord($hrp[$i]) >> 5;
    }
    $out[] = 0;
    for ($i = 0; $i < $len; $i++) {
        $out[] = ord($hrp[$i]) & 31;
    }
    return $out;
}

function bech32_create_checksum(string $hrp, array $data): array {
    $values = array_merge(bech32_hrp_expand($hrp), $data, [0, 0, 0, 0, 0, 0]);
    $pm = bech32_polymod($values) ^ 1;
    $ret = [];
    for ($i = 0; $i < 6; $i++) {
        $ret[] = ($pm >> (5 * (5 - $i))) & 31;
    }
    return $ret;
}

function bech32_encode(string $hrp, array $data): string {
    $charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    $combined = array_merge($data, bech32_create_checksum($hrp, $data));
    $out = $hrp . "1";

    foreach ($combined as $d) {
        if ($d < 0 || $d > 31) {
            throw new Exception("bech32 data out of range");
        }
        $out .= $charset[$d];
    }

    return $out;
}

function convertbits(array $data, int $from, int $to, bool $pad = true): array {
    $acc = 0;
    $bits = 0;
    $ret = [];
    $maxv = (1 << $to) - 1;

    foreach ($data as $value) {
        if ($value < 0 || ($value >> $from) !== 0) {
            throw new Exception("convertbits invalid value");
        }
        $acc = ($acc << $from) | $value;
        $bits += $from;
        while ($bits >= $to) {
            $bits -= $to;
            $ret[] = ($acc >> $bits) & $maxv;
        }
    }

    if ($pad) {
        if ($bits) {
            $ret[] = ($acc << ($to - $bits)) & $maxv;
        }
    } else {
        if ($bits >= $from) {
            throw new Exception("convertbits excess padding");
        }
        if ((($acc << ($to - $bits)) & $maxv) !== 0) {
            throw new Exception("convertbits non-zero padding");
        }
    }

    return $ret;
}

function bech32_segwit_address(string $hrp, int $witver, string $witprog): string {
    if ($witver < 0 || $witver > 16) {
        throw new Exception("witver out of range");
    }

    $prog = array_values(unpack('C*', $witprog));

    if (strlen($witprog) < 2 || strlen($witprog) > 40) {
        throw new Exception("witprog bad length");
    }
    if ($witver === 0 && (strlen($witprog) !== 20 && strlen($witprog) !== 32)) {
        throw new Exception("witprog bad length for v0");
    }

    $data = array_merge([$witver], convertbits($prog, 8, 5, true));
    return bech32_encode($hrp, $data);
}
