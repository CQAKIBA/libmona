<?php
/**
 * Electrum-Mona compatible signmessage (message signing) in pure PHP + GMP.
 *
 * Requirements:
 *   - PHP with GMP extension enabled
 *
 * Usage:
 *   $message = "こんにちは";
 *   $privkey = "p2wpkh:T9QtawEWtVZP2uUmmqxuuvLzjWaN6rpDYvdEkSLs1yzBmRtGt27x";
 *   $data = signmessage($message, $privkey);
 *   var_dump($data);
 */

/* ===========================
 * Utilities: bytes/hex/base64
 * =========================== */

function bin2hex_lc(string $b): string { return strtolower(bin2hex($b)); }

function hex2bin_safe(string $hex): string {
    if (strlen($hex) % 2 !== 0) throw new Exception("hex length must be even");
    $b = hex2bin($hex);
    if ($b === false) throw new Exception("invalid hex");
    return $b;
}

function sha256(string $b): string { return hash('sha256', $b, true); }
function sha256d(string $b): string { return sha256(sha256($b)); }

function hash160(string $b): string {
    return hash('ripemd160', sha256($b), true);
}

function hmac_sha256(string $key, string $data): string {
    return hash_hmac('sha256', $data, $key, true);
}

function bytes_pad_left(string $b, int $len): string {
    if (strlen($b) > $len) throw new Exception("too long");
    return str_repeat("\x00", $len - strlen($b)) . $b;
}

/* ===========================
 * Base58Check (Bitcoin style)
 * =========================== */

const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58_encode(string $bin): string {
    $alphabet = B58_ALPHABET;
    $x = gmp_init(bin2hex($bin), 16);
    $out = "";
    while (gmp_cmp($x, 0) > 0) {
        [$x, $rem] = [gmp_div_q($x, 58), gmp_intval(gmp_mod($x, 58))];
        $out = $alphabet[$rem] . $out;
    }
    // leading zeros
    for ($i=0; $i<strlen($bin) && $bin[$i] === "\x00"; $i++) {
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
        if (!isset($map[$c])) throw new Exception("invalid base58 char");
        $x = gmp_add(gmp_mul($x, 58), $map[$c]);
    }
    $hex = gmp_strval($x, 16);
    if (strlen($hex) % 2) $hex = "0".$hex;
    $bin = hex2bin_safe($hex);

    // restore leading zeros
    $nLeading = 0;
    for ($i=0; $i<strlen($s) && $s[$i] === "1"; $i++) $nLeading++;
    return str_repeat("\x00", $nLeading) . $bin;
}

function base58check_encode(string $payload): string {
    $cs = substr(sha256d($payload), 0, 4);
    return base58_encode($payload . $cs);
}

function base58check_decode(string $s): string {
    $raw = base58_decode($s);
    if (strlen($raw) < 5) throw new Exception("too short");
    $payload = substr($raw, 0, -4);
    $cs = substr($raw, -4);
    $calc = substr(sha256d($payload), 0, 4);
    if (!hash_equals($cs, $calc)) throw new Exception("bad checksum");
    return $payload;
}

/* ===========================
 * Bech32 (BIP173) for mona1...
 * =========================== */

function bech32_polymod(array $values): int {
    $GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    $chk = 1;
    foreach ($values as $v) {
        $top = $chk >> 25;
        $chk = (($chk & 0x1ffffff) << 5) ^ $v;
        for ($i=0; $i<5; $i++) {
            if (($top >> $i) & 1) $chk ^= $GEN[$i];
        }
    }
    return $chk;
}

function bech32_hrp_expand(string $hrp): array {
    $out = [];
    $len = strlen($hrp);
    for ($i=0; $i<$len; $i++) $out[] = ord($hrp[$i]) >> 5;
    $out[] = 0;
    for ($i=0; $i<$len; $i++) $out[] = ord($hrp[$i]) & 31;
    return $out;
}

function bech32_create_checksum(string $hrp, array $data): array {
    $values = array_merge(bech32_hrp_expand($hrp), $data, [0,0,0,0,0,0]);
    $pm = bech32_polymod($values) ^ 1;
    $ret = [];
    for ($i=0; $i<6; $i++) $ret[] = ($pm >> (5*(5-$i))) & 31;
    return $ret;
}

function bech32_encode(string $hrp, array $data): string {
    $charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    $combined = array_merge($data, bech32_create_checksum($hrp, $data));
    $out = $hrp . "1";
    foreach ($combined as $d) {
        if ($d < 0 || $d > 31) throw new Exception("bech32 data out of range");
        $out .= $charset[$d];
    }
    return $out;
}

function convertbits(array $data, int $from, int $to, bool $pad=true): array {
    $acc = 0; $bits = 0; $ret = [];
    $maxv = (1 << $to) - 1;
    foreach ($data as $value) {
        if ($value < 0 || ($value >> $from) !== 0) throw new Exception("convertbits invalid value");
        $acc = ($acc << $from) | $value;
        $bits += $from;
        while ($bits >= $to) {
            $bits -= $to;
            $ret[] = ($acc >> $bits) & $maxv;
        }
    }
    if ($pad) {
        if ($bits) $ret[] = ($acc << ($to - $bits)) & $maxv;
    } else {
        if ($bits >= $from) throw new Exception("convertbits excess padding");
        if ((($acc << ($to - $bits)) & $maxv) !== 0) throw new Exception("convertbits non-zero padding");
    }
    return $ret;
}

function bech32_segwit_address(string $hrp, int $witver, string $witprog): string {
    if ($witver < 0 || $witver > 16) throw new Exception("witver out of range");
    $prog = array_values(unpack('C*', $witprog));
    if (strlen($witprog) < 2 || strlen($witprog) > 40) throw new Exception("witprog bad length");
    if ($witver === 0 && (strlen($witprog) !== 20 && strlen($witprog) !== 32)) throw new Exception("witprog bad length for v0");
    $data = array_merge([$witver], convertbits($prog, 8, 5, true));
    return bech32_encode($hrp, $data);
}

/* ===========================
 * Electrum-Mona message hash
 *  msg_magic = "\x19Monacoin Signed Message:\n" + var_int(len(msg)) + msg
 *  hash = sha256d(msg_magic)
 * =========================== */

function int_to_le_bytes(int $i, int $len): string {
    $out = "";
    for ($k=0; $k<$len; $k++) {
        $out .= chr($i & 0xff);
        $i >>= 8;
    }
    return $out;
}

function var_int_bytes(int $i): string {
    if ($i < 0xfd) {
        return chr($i);
    } elseif ($i <= 0xffff) {
        return "\xfd" . int_to_le_bytes($i, 2);
    } elseif ($i <= 0xffffffff) {
        return "\xfe" . int_to_le_bytes($i, 4);
    } else {
        // PHP int is signed; for huge sizes you'd want GMP. For messages this is fine.
        return "\xff" . int_to_le_bytes($i, 8);
    }
}

function msg_magic(string $message_utf8_bytes): string {
    $prefix = "\x19" . "Monacoin Signed Message:\n";
    return $prefix . var_int_bytes(strlen($message_utf8_bytes)) . $message_utf8_bytes;
}

function electrum_mona_message_hash(string $message_utf8_bytes): string {
    return sha256d(msg_magic($message_utf8_bytes));
}

/* ===========================
 * secp256k1 math (GMP)
 * =========================== */

function gmp_mod_n($x, $m) {
    $r = gmp_mod($x, $m);
    if (gmp_cmp($r, 0) < 0) $r = gmp_add($r, $m);
    return $r;
}

function gmp_inv($a, $n) {
    $a = gmp_mod_n($a, $n);
    $inv = gmp_invert($a, $n);
    if ($inv === false) throw new Exception("no inverse");
    return $inv;
}

// curve constants
function secp_p() { return gmp_init("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"); }
function secp_n() { return gmp_init("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"); }
function secp_Gx(){ return gmp_init("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"); }
function secp_Gy(){ return gmp_init("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"); }

function point_inf() { return [null, null, true]; } // (x,y,inf)
function point_is_inf($P): bool { return $P[2] === true; }

function point_add($P, $Q) {
    $p = secp_p();
    if (point_is_inf($P)) return $Q;
    if (point_is_inf($Q)) return $P;
    [$x1,$y1] = [$P[0],$P[1]];
    [$x2,$y2] = [$Q[0],$Q[1]];

    if (gmp_cmp($x1, $x2) == 0) {
        if (gmp_cmp(gmp_mod_n(gmp_add($y1, $y2), $p), 0) == 0) return point_inf();
        // P == Q => double
        return point_double($P);
    }

    $lambda = gmp_mod_n(gmp_mul(gmp_sub($y2,$y1), gmp_inv(gmp_sub($x2,$x1), $p)), $p);
    $x3 = gmp_mod_n(gmp_sub(gmp_sub(gmp_pow($lambda,2), $x1), $x2), $p);
    $y3 = gmp_mod_n(gmp_sub(gmp_mul($lambda, gmp_sub($x1,$x3)), $y1), $p);
    return [$x3, $y3, false];
}

function point_double($P) {
    $p = secp_p();
    if (point_is_inf($P)) return $P;
    [$x1,$y1] = [$P[0],$P[1]];
    if (gmp_cmp($y1, 0) == 0) return point_inf();

    // lambda = (3*x^2) / (2*y)
    $lambda = gmp_mod_n(gmp_mul(gmp_mul(3, gmp_pow($x1,2)), gmp_inv(gmp_mul(2,$y1), $p)), $p);
    $x3 = gmp_mod_n(gmp_sub(gmp_pow($lambda,2), gmp_mul(2,$x1)), $p);
    $y3 = gmp_mod_n(gmp_sub(gmp_mul($lambda, gmp_sub($x1,$x3)), $y1), $p);
    return [$x3, $y3, false];
}

function point_mul($k, $P) {
    $k = gmp_mod_n($k, secp_n());
    if (gmp_cmp($k, 0) == 0 || point_is_inf($P)) return point_inf();
    $R = point_inf();
    $addend = $P;
    while (gmp_cmp($k, 0) > 0) {
        if (gmp_testbit($k, 0)) $R = point_add($R, $addend);
        $addend = point_double($addend);
        $k = gmp_div_q($k, 2);
    }
    return $R;
}

function pubkey_compress($P): string {
    if (point_is_inf($P)) throw new Exception("inf pubkey");
    $x = $P[0]; $y = $P[1];
    $prefix = gmp_intval(gmp_mod($y, 2)) ? "\x03" : "\x02";
    $xb = hex2bin_safe(str_pad(gmp_strval($x, 16), 64, "0", STR_PAD_LEFT));
    return $prefix . $xb;
}

/* ===========================
 * RFC6979 deterministic k (HMAC-SHA256)
 * =========================== */

function rfc6979_k(string $x32, string $h1_32): \GMP {
    // Implements RFC6979 for secp256k1 using HMAC-SHA256
    $n = secp_n();

    $V = str_repeat("\x01", 32);
    $K = str_repeat("\x00", 32);

    $K = hmac_sha256($K, $V . "\x00" . $x32 . $h1_32);
    $V = hmac_sha256($K, $V);
    $K = hmac_sha256($K, $V . "\x01" . $x32 . $h1_32);
    $V = hmac_sha256($K, $V);

    while (true) {
        $T = "";
        while (strlen($T) < 32) {
            $V = hmac_sha256($K, $V);
            $T .= $V;
        }
        $k = gmp_init("0x" . bin2hex(substr($T, 0, 32)));
        if (gmp_cmp($k, 1) >= 0 && gmp_cmp($k, gmp_sub($n, 1)) <= 0) return $k;

        $K = hmac_sha256($K, $V . "\x00");
        $V = hmac_sha256($K, $V);
    }
}

/* ===========================
 * ECDSA sign + public key recovery to get recid
 * =========================== */

function ecdsa_sign_rfc6979(string $msg32, string $priv32): array {
    $n = secp_n();
    $p = secp_p();
    $G = [secp_Gx(), secp_Gy(), false];

    $d = gmp_init("0x" . bin2hex($priv32));
    if (gmp_cmp($d, 1) < 0 || gmp_cmp($d, gmp_sub($n, 1)) > 0) throw new Exception("bad privkey range");

    $z = gmp_init("0x" . bin2hex($msg32)); // 256-bit
    $k = rfc6979_k($priv32, $msg32);

    $R = point_mul($k, $G);
    $r = gmp_mod_n($R[0], $n);
    if (gmp_cmp($r, 0) == 0) throw new Exception("r=0");

    $kInv = gmp_inv($k, $n);
    $s = gmp_mod_n(gmp_mul($kInv, gmp_add($z, gmp_mul($r, $d))), $n);
    if (gmp_cmp($s, 0) == 0) throw new Exception("s=0");

    // low-S (recommended; Electrum verify normalizes anyway)
    $halfN = gmp_div_q($n, 2);
    if (gmp_cmp($s, $halfN) > 0) $s = gmp_sub($n, $s);

    return [$r, $s];
}

// sqrt mod p, since p % 4 == 3 for secp256k1
function mod_sqrt_secp($a) {
    $p = secp_p();
    $exp = gmp_div_q(gmp_add($p, 1), 4);
    return gmp_powm($a, $exp, $p);
}

function recover_pubkey_from_sig($r, $s, string $msg32, int $recid) {
    $p = secp_p();
    $n = secp_n();
    $G = [secp_Gx(), secp_Gy(), false];

    $z = gmp_init("0x" . bin2hex($msg32));
    $j = intdiv($recid, 2);
    $yParity = $recid % 2;

    $x = gmp_add($r, gmp_mul($j, $n));
    if (gmp_cmp($x, $p) >= 0) return null;

    // y^2 = x^3 + 7
    $x3 = gmp_mod_n(gmp_pow($x, 3), $p);
    $alpha = gmp_mod_n(gmp_add($x3, 7), $p);
    $beta = mod_sqrt_secp($alpha);
    if ($beta === null) return null;

    $isOdd = gmp_intval(gmp_mod($beta, 2));
    $y = ($isOdd === $yParity) ? $beta : gmp_mod_n(gmp_sub($p, $beta), $p);
    $R = [$x, $y, false];

    // Q = r^{-1} (s*R - z*G)
    $rInv = gmp_inv($r, $n);
    $sR = point_mul($s, $R);
    $zG = point_mul($z, $G);
    $neg_zG = [$zG[0], gmp_mod_n(gmp_sub($p, $zG[1]), $p), point_is_inf($zG)];
    $Q = point_mul($rInv, point_add($sR, $neg_zG));
    if (point_is_inf($Q)) return null;
    return $Q;
}

function compute_recid($r, $s, string $msg32, $pubPoint): int {
    for ($recid=0; $recid<4; $recid++) {
        $Q = recover_pubkey_from_sig($r, $s, $msg32, $recid);
        if ($Q === null) continue;
        if (gmp_cmp($Q[0], $pubPoint[0]) === 0 && gmp_cmp($Q[1], $pubPoint[1]) === 0) {
            return $recid;
        }
    }
    throw new Exception("cannot find recid");
}

/* ===========================
 * Monacoin address derivation
 * =========================== */

// Monacoin mainnet prefixes (widely used):
//  - P2PKH: 0x32 => 'M...'
//  - P2SH : 0x37 => 'P...'
//  - WIF  : 0xB0 => 'T...'
//  - bech32 HRP: 'mona'
const MONA_P2PKH = 0x32;
const MONA_P2SH  = 0x37;
const MONA_WIF   = 0xB0;
const MONA_HRP   = "mona";

function pubkey_to_addr_M(string $pubkey_compressed): string {
    $h160 = hash160($pubkey_compressed);
    return base58check_encode(chr(MONA_P2PKH) . $h160);
}

function pubkey_to_addr_mona1(string $pubkey_compressed): string {
    $h160 = hash160($pubkey_compressed);
    return bech32_segwit_address(MONA_HRP, 0, $h160); // P2WPKH
}

function pubkey_to_addr_P(string $pubkey_compressed): string {
    // P2SH-P2WPKH: redeem = 0x0014{h160(pub)}
    $h160 = hash160($pubkey_compressed);
    $redeem = "\x00\x14" . $h160;
    $redeem_h160 = hash160($redeem);
    return base58check_encode(chr(MONA_P2SH) . $redeem_h160);
}

/* ===========================
 * Electrum-style privkey parsing: "txin_type:base58WIF"
 * =========================== */

function deserialize_privkey_electrum(string $key): array {
    $txin_type = null;
    $wif = $key;
    if (strpos($key, ':') !== false) {
        [$txin_type, $wif] = explode(':', $key, 2);
    } else {
        $txin_type = 'p2pkh';
    }
    $payload = base58check_decode($wif);
    if (strlen($payload) !== 33 && strlen($payload) !== 34) {
        throw new Exception("invalid WIF payload length");
    }
    $prefix = ord($payload[0]);
    if ($prefix !== MONA_WIF) {
        throw new Exception("invalid WIF prefix: 0x" . dechex($prefix));
    }
    $secret = substr($payload, 1, 32);
    $compressed = false;
    if (strlen($payload) === 34) {
        if (ord($payload[33]) !== 0x01) throw new Exception("invalid compressed flag");
        $compressed = true;
    }
    // Electrum rules: segwit scripts require compressed pubkey
    if (in_array($txin_type, ['p2wpkh','p2wpkh-p2sh','p2wsh','p2wsh-p2sh'], true) && !$compressed) {
        throw new Exception("segwit script types require compressed pubkey");
    }
    return [$txin_type, $secret, $compressed, $wif];
}

/* ===========================
 * Main: signmessage()
 * =========================== */

function signmessage(string $message, string $privkey): array {
    // message bytes: Electrum uses utf8 bytes
    $msg_bytes = $message; // assume UTF-8 already
    $h32 = electrum_mona_message_hash($msg_bytes);

    [$txin_type, $secret32, $compressed, $wif_only] = deserialize_privkey_electrum($privkey);

    // public key
    $G = [secp_Gx(), secp_Gy(), false];
    $d = gmp_init("0x" . bin2hex($secret32));
    $pubPoint = point_mul($d, $G);
    $pubCompressed = pubkey_compress($pubPoint);

    // ECDSA sign (RFC6979 deterministic)
    [$r, $s] = ecdsa_sign_rfc6979($h32, $secret32);
    $recid = compute_recid($r, $s, $h32, $pubPoint);

    // Electrum-style header: 27 + recid + (compressed ? 4 : 0)
    $header = 27 + $recid + ($compressed ? 4 : 0);

    $rbin = hex2bin_safe(str_pad(gmp_strval($r, 16), 64, "0", STR_PAD_LEFT));
    $sbin = hex2bin_safe(str_pad(gmp_strval($s, 16), 64, "0", STR_PAD_LEFT));
    $sig65 = chr($header) . $rbin . $sbin;
    $sig_b64 = base64_encode($sig65);

    // addresses from same pubkey
    $addr_mona1 = pubkey_to_addr_mona1($pubCompressed);
    $addr_M     = pubkey_to_addr_M($pubCompressed);
    $addr_P     = pubkey_to_addr_P($pubCompressed);

    return [
        'message'      => $message,
        'privkey_wif'  => $privkey,
        'privkey_raw'  => bin2hex_lc($secret32),
        'sign'         => $sig_b64,
        'addr_mona1'   => $addr_mona1,
        'addr_M'       => $addr_M,
        'addr_P'       => $addr_P,
    ];
}

/**
 * ECDSA verify
 *   verifies compact signature (r,s) against public key point Q and msg hash
 */
function ecdsa_verify_compact(string $msg32, $r, $s, $Q): bool {
    if ($Q === null || point_is_inf($Q)) return false;

    $n = secp_n();
    $G = [secp_Gx(), secp_Gy(), false];

    if (gmp_cmp($r, 1) < 0 || gmp_cmp($r, gmp_sub($n, 1)) > 0) return false;
    if (gmp_cmp($s, 1) < 0 || gmp_cmp($s, gmp_sub($n, 1)) > 0) return false;

    $z = gmp_init("0x" . bin2hex($msg32));
    $w = gmp_inv($s, $n);
    $u1 = gmp_mod_n(gmp_mul($z, $w), $n);
    $u2 = gmp_mod_n(gmp_mul($r, $w), $n);

    $P1 = point_mul($u1, $G);
    $P2 = point_mul($u2, $Q);
    $X = point_add($P1, $P2);
    if (point_is_inf($X)) return false;

    $xModN = gmp_mod_n($X[0], $n);
    return gmp_cmp($xModN, $r) === 0;
}

/**
 * Decode Electrum/Bitcoin-style signature header byte.
 *
 * Electrum verify accepts:
 *   27-30: p2pkh (uncompressed)
 *   31-34: p2pkh (compressed)
 *   35-38: p2wpkh-p2sh
 *   39-42: p2wpkh
 *
 * returns [recid, compressed, txin_type_guess]
 */
function decode_sig_header(int $header): array {
    if ($header < 27 || $header > 42) {
        throw new Exception("Bad encoding");
    }

    $nV = $header;
    $txinTypeGuess = null;
    $compressed = true;

    if ($nV >= 39) {
        $nV -= 12;
        $txinTypeGuess = 'p2wpkh';
    } elseif ($nV >= 35) {
        $nV -= 8;
        $txinTypeGuess = 'p2wpkh-p2sh';
    } elseif ($nV >= 31) {
        $nV -= 4;
    } else {
        $compressed = false;
    }

    $recid = $nV - 27;
    if ($recid < 0 || $recid > 3) {
        throw new Exception("Bad recid");
    }

    return [$recid, $compressed, $txinTypeGuess];
}

/**
 * Verify message signature against an address (Electrum-mona compatible)
 *
 * @param string $address   mona1... / M... / P...
 * @param string $message   original UTF-8 message
 * @param string $signature base64(header+r+s)
 * @return array
 */
function verifymessage(string $address, string $message, string $signature): array {
    $result = [
        'address'         => $address,
        'message'         => $message,
        'signature'       => $signature,
        'valid'           => false,
        'error'           => null,
        'header'          => null,
        'recid'           => null,
        'compressed'      => null,
        'txin_type_guess' => null,
        'pubkey_compressed' => null,
        'addr_mona1'      => null,
        'addr_M'          => null,
        'addr_P'          => null,
    ];

    try {
        $sig65 = base64_decode($signature, true);
        if ($sig65 === false || strlen($sig65) !== 65) {
            throw new Exception("signature must be valid base64 of 65 bytes");
        }

        $header = ord($sig65[0]);
        [$recid, $compressed, $txinTypeGuess] = decode_sig_header($header);

        $r = gmp_init("0x" . bin2hex(substr($sig65, 1, 32)));
        $s = gmp_init("0x" . bin2hex(substr($sig65, 33, 32)));

        $msgBytes = $message; // UTF-8 bytes assumed
        $h32 = electrum_mona_message_hash($msgBytes);

        $Q = recover_pubkey_from_sig($r, $s, $h32, $recid);
        if ($Q === null || point_is_inf($Q)) {
            throw new Exception("public key recovery failed");
        }

        $pubCompressed = pubkey_compress($Q);

        $addrMona1 = pubkey_to_addr_mona1($pubCompressed);
        $addrM     = pubkey_to_addr_M($pubCompressed);
        $addrP     = pubkey_to_addr_P($pubCompressed);

        $result['header']            = $header;
        $result['recid']             = $recid;
        $result['compressed']        = $compressed;
        $result['txin_type_guess']   = $txinTypeGuess;
        $result['pubkey_compressed'] = bin2hex_lc($pubCompressed);
        $result['addr_mona1']        = $addrMona1;
        $result['addr_M']            = $addrM;
        $result['addr_P']            = $addrP;

        // Electrum verify logic:
        // if header hints a type, check only that;
        // otherwise check p2pkh, p2wpkh, p2wpkh-p2sh
        if ($txinTypeGuess !== null) {
            $candidateAddrs = [];
            if ($txinTypeGuess === 'p2wpkh') {
                $candidateAddrs[] = $addrMona1;
            } elseif ($txinTypeGuess === 'p2wpkh-p2sh') {
                $candidateAddrs[] = $addrP;
            } elseif ($txinTypeGuess === 'p2pkh') {
                $candidateAddrs[] = $addrM;
            }
        } else {
            $candidateAddrs = [$addrM, $addrMona1, $addrP];
        }

        $addrMatched = false;
        foreach ($candidateAddrs as $cand) {
            if (hash_equals($cand, $address)) {
                $addrMatched = true;
                break;
            }
        }
        if (!$addrMatched) {
            throw new Exception("address mismatch");
        }

        // Final ECDSA verification
        if (!ecdsa_verify_compact($h32, $r, $s, $Q)) {
            throw new Exception("ecdsa verify failed");
        }

        $result['valid'] = true;
        return $result;

    } catch (Throwable $e) {
        $result['error'] = $e->getMessage();
        return $result;
    }
}

/* =========================================================
 * 使用例
 * ========================================================= */
/*
$message = "こんにちは";
$privkey = "p2wpkh:T9QtawEWtVZP2uUmmqxuuvLzjWaN6rpDYvdEkSLs1yzBmRtGt27x";

$data = signmessage($message, $privkey);
var_dump($data);

$verify = verifymessage($data['addr_mona1'], $message, $data['sign']);
var_dump($verify);

// 既知テストベクトルでもOK
$verify2 = verifymessage(
    "mona1qp900aghcwzuqhcyjxyd3rd323avucz3908xv5n",
    "こんにちは",
    "IG5XdJOscA+7SlQECQfFjT11n3Nvv1LjShlMmcRc3jKgEnPmG0MBSHDj8n5sRsnQmlZ4Ir4DCx/xnLFycdJEPlA="
);
var_dump($verify2);
*/

/* ===========================
 * Example (uncomment to run)
 * =========================== */

$message = trim($argv[1]);
$privkey = "p2wpkh:T9QtawEWtVZP2uUmmqxuuvLzjWaN6rpDYvdEkSLs1yzBmRtGt27x";
$signature = signmessage($message, $privkey);
printf("\n署名:\n%s\n", json_encode($signature, JSON_PRETTY_PRINT + JSON_UNESCAPED_UNICODE + JSON_UNESCAPED_SLASHES));
printf("\nJSON送信形式:\n%s\n", json_encode(array($signature["message"], $signature["addr_M"], $signature["sign"], )));
$verify = verifymessage($signature['addr_M'], $message, $signature['sign']);
printf("\n検証:\n%s\n", json_encode($verify, JSON_PRETTY_PRINT + JSON_UNESCAPED_UNICODE + JSON_UNESCAPED_SLASHES));




$verify2 = verifymessage(
    "mona1qczzz0sjsx8n98tstmy6jr0r8dvxl0g8s87ggk8",
    "本日は荒天なり",
    "IELZ4JknRGm4rEgtxXgYWLVC26nlVXOqdtHoOUSz9RJQSUgOkt+y3He4gwZoex3EgP1ZXGEUP4WQqcog9kbMBWY="
);
printf("\n外部検証:\n%s\n", json_encode($verify2, JSON_PRETTY_PRINT + JSON_UNESCAPED_UNICODE + JSON_UNESCAPED_SLASHES));
