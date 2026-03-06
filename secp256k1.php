<?php
namespace libmona;

use Exception;
use Throwable;

function gmp_mod_n($x, $m) {
    $r = gmp_mod($x, $m);
    if (gmp_cmp($r, 0) < 0) {
        $r = gmp_add($r, $m);
    }
    return $r;
}

function gmp_inv($a, $n) {
    $a = gmp_mod_n($a, $n);
    $inv = gmp_invert($a, $n);
    if ($inv === false) {
        throw new Exception('no inverse');
    }
    return $inv;
}

function secp_p() { return gmp_init('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F'); }
function secp_n() { return gmp_init('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'); }
function secp_Gx() { return gmp_init('0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798'); }
function secp_Gy() { return gmp_init('0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8'); }

function point_inf() { return [null, null, true]; }
function point_is_inf($P): bool { return $P[2] === true; }

function point_add($P, $Q) {
    $p = secp_p();
    if (point_is_inf($P)) {
        return $Q;
    }
    if (point_is_inf($Q)) {
        return $P;
    }
    [$x1, $y1] = [$P[0], $P[1]];
    [$x2, $y2] = [$Q[0], $Q[1]];

    if (gmp_cmp($x1, $x2) == 0) {
        if (gmp_cmp(gmp_mod_n(gmp_add($y1, $y2), $p), 0) == 0) {
            return point_inf();
        }
        return point_double($P);
    }

    $lambda = gmp_mod_n(gmp_mul(gmp_sub($y2, $y1), gmp_inv(gmp_sub($x2, $x1), $p)), $p);
    $x3 = gmp_mod_n(gmp_sub(gmp_sub(gmp_pow($lambda, 2), $x1), $x2), $p);
    $y3 = gmp_mod_n(gmp_sub(gmp_mul($lambda, gmp_sub($x1, $x3)), $y1), $p);

    return [$x3, $y3, false];
}

function point_double($P) {
    $p = secp_p();
    if (point_is_inf($P)) {
        return $P;
    }
    [$x1, $y1] = [$P[0], $P[1]];
    if (gmp_cmp($y1, 0) == 0) {
        return point_inf();
    }

    $lambda = gmp_mod_n(gmp_mul(gmp_mul(3, gmp_pow($x1, 2)), gmp_inv(gmp_mul(2, $y1), $p)), $p);
    $x3 = gmp_mod_n(gmp_sub(gmp_pow($lambda, 2), gmp_mul(2, $x1)), $p);
    $y3 = gmp_mod_n(gmp_sub(gmp_mul($lambda, gmp_sub($x1, $x3)), $y1), $p);
    return [$x3, $y3, false];
}

function point_mul($k, $P) {
    $k = gmp_mod_n($k, secp_n());
    if (gmp_cmp($k, 0) == 0 || point_is_inf($P)) {
        return point_inf();
    }
    $R = point_inf();
    $addend = $P;

    while (gmp_cmp($k, 0) > 0) {
        if (gmp_testbit($k, 0)) {
            $R = point_add($R, $addend);
        }
        $addend = point_double($addend);
        $k = gmp_div_q($k, 2);
    }

    return $R;
}

function pubkey_compress($P): string {
    if (point_is_inf($P)) {
        throw new Exception('inf pubkey');
    }
    $x = $P[0];
    $y = $P[1];
    $prefix = gmp_intval(gmp_mod($y, 2)) ? "\x03" : "\x02";
    $xb = hex2bin_safe(str_pad(gmp_strval($x, 16), 64, '0', STR_PAD_LEFT));
    return $prefix . $xb;
}

function rfc6979_k(string $x32, string $h1_32): \GMP {
    $n = secp_n();
    $V = str_repeat("\x01", 32);
    $K = str_repeat("\x00", 32);

    $K = hmac_sha256($K, $V . "\x00" . $x32 . $h1_32);
    $V = hmac_sha256($K, $V);
    $K = hmac_sha256($K, $V . "\x01" . $x32 . $h1_32);
    $V = hmac_sha256($K, $V);

    while (true) {
        $T = '';
        while (strlen($T) < 32) {
            $V = hmac_sha256($K, $V);
            $T .= $V;
        }
        $k = gmp_init('0x' . bin2hex(substr($T, 0, 32)));
        if (gmp_cmp($k, 1) >= 0 && gmp_cmp($k, gmp_sub($n, 1)) <= 0) {
            return $k;
        }

        $K = hmac_sha256($K, $V . "\x00");
        $V = hmac_sha256($K, $V);
    }
}

function ecdsa_sign_rfc6979(string $msg32, string $priv32): array {
    $n = secp_n();
    $G = [secp_Gx(), secp_Gy(), false];

    $d = gmp_init('0x' . bin2hex($priv32));
    if (gmp_cmp($d, 1) < 0 || gmp_cmp($d, gmp_sub($n, 1)) > 0) {
        throw new Exception('bad privkey range');
    }

    $z = gmp_init('0x' . bin2hex($msg32));
    $k = rfc6979_k($priv32, $msg32);

    $R = point_mul($k, $G);
    $r = gmp_mod_n($R[0], $n);
    if (gmp_cmp($r, 0) == 0) {
        throw new Exception('r=0');
    }

    $kInv = gmp_inv($k, $n);
    $s = gmp_mod_n(gmp_mul($kInv, gmp_add($z, gmp_mul($r, $d))), $n);
    if (gmp_cmp($s, 0) == 0) {
        throw new Exception('s=0');
    }

    $halfN = gmp_div_q($n, 2);
    if (gmp_cmp($s, $halfN) > 0) {
        $s = gmp_sub($n, $s);
    }

    return [$r, $s];
}

function mod_sqrt_secp($a) {
    $p = secp_p();
    $exp = gmp_div_q(gmp_add($p, 1), 4);
    return gmp_powm($a, $exp, $p);
}

function recover_pubkey_from_sig($r, $s, string $msg32, int $recid) {
    $p = secp_p();
    $n = secp_n();
    $G = [secp_Gx(), secp_Gy(), false];

    $z = gmp_init('0x' . bin2hex($msg32));
    $j = intdiv($recid, 2);
    $yParity = $recid % 2;

    $x = gmp_add($r, gmp_mul($j, $n));
    if (gmp_cmp($x, $p) >= 0) {
        return null;
    }

    $x3 = gmp_mod_n(gmp_pow($x, 3), $p);
    $alpha = gmp_mod_n(gmp_add($x3, 7), $p);
    $beta = mod_sqrt_secp($alpha);
    if ($beta === null) {
        return null;
    }

    $isOdd = gmp_intval(gmp_mod($beta, 2));
    $y = ($isOdd === $yParity) ? $beta : gmp_mod_n(gmp_sub($p, $beta), $p);
    $R = [$x, $y, false];

    $rInv = gmp_inv($r, $n);
    $sR = point_mul($s, $R);
    $zG = point_mul($z, $G);
    $neg_zG = [$zG[0], gmp_mod_n(gmp_sub($p, $zG[1]), $p), point_is_inf($zG)];
    $Q = point_mul($rInv, point_add($sR, $neg_zG));

    if (point_is_inf($Q)) {
        return null;
    }
    return $Q;
}

function compute_recid($r, $s, string $msg32, $pubPoint): int {
    for ($recid = 0; $recid < 4; $recid++) {
        $Q = recover_pubkey_from_sig($r, $s, $msg32, $recid);
        if ($Q === null) {
            continue;
        }
        if (gmp_cmp($Q[0], $pubPoint[0]) === 0 && gmp_cmp($Q[1], $pubPoint[1]) === 0) {
            return $recid;
        }
    }
    throw new Exception('cannot find recid');
}

function ecdsa_verify_compact(string $msg32, $r, $s, $Q): bool {
    if ($Q === null || point_is_inf($Q)) {
        return false;
    }

    $n = secp_n();
    $G = [secp_Gx(), secp_Gy(), false];

    if (gmp_cmp($r, 1) < 0 || gmp_cmp($r, gmp_sub($n, 1)) > 0) {
        return false;
    }
    if (gmp_cmp($s, 1) < 0 || gmp_cmp($s, gmp_sub($n, 1)) > 0) {
        return false;
    }

    $z = gmp_init('0x' . bin2hex($msg32));
    $w = gmp_inv($s, $n);
    $u1 = gmp_mod_n(gmp_mul($z, $w), $n);
    $u2 = gmp_mod_n(gmp_mul($r, $w), $n);

    $P1 = point_mul($u1, $G);
    $P2 = point_mul($u2, $Q);
    $X = point_add($P1, $P2);
    if (point_is_inf($X)) {
        return false;
    }

    $xModN = gmp_mod_n($X[0], $n);
    return gmp_cmp($xModN, $r) === 0;
}
