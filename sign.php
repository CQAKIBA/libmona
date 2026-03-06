<?php
namespace libmona;

use Exception;
use Throwable;

function signmessage(string $message, string $privkey): array {
    $msg_bytes = $message;
    $h32 = electrum_mona_message_hash($msg_bytes);

    [$txin_type, $secret32, $compressed, $wif_only] = deserialize_privkey_electrum($privkey);

    $G = [secp_Gx(), secp_Gy(), false];
    $d = gmp_init('0x' . bin2hex($secret32));
    $pubPoint = point_mul($d, $G);
    $pubCompressed = pubkey_compress($pubPoint);

    [$r, $s] = ecdsa_sign_rfc6979($h32, $secret32);
    $recid = compute_recid($r, $s, $h32, $pubPoint);

    $header = 27 + $recid + ($compressed ? 4 : 0);

    $rbin = hex2bin_safe(str_pad(gmp_strval($r, 16), 64, '0', STR_PAD_LEFT));
    $sbin = hex2bin_safe(str_pad(gmp_strval($s, 16), 64, '0', STR_PAD_LEFT));
    $sig65 = chr($header) . $rbin . $sbin;
    $sig_b64 = base64_encode($sig65);

    $addr_mona1 = pubkey_to_addr_mona1($pubCompressed);
    $addr_M = pubkey_to_addr_M($pubCompressed);
    $addr_P = pubkey_to_addr_P($pubCompressed);

    return [
        'message' => $message,
        'privkey_wif' => $privkey,
        'privkey_raw' => bin2hex_lc($secret32),
        'sign' => $sig_b64,
        'addr_mona1' => $addr_mona1,
        'addr_M' => $addr_M,
        'addr_P' => $addr_P,
    ];
}
