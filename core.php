<?php
/*
This file is licensed under the MIT License.
Copyright (c) 2026 Daisuke JA1UMW / CQAKIBA.TOKYO
このファイルはMITライセンスです。利用・改変・再配布・商用利用が可能ですが、作者は一切の責任を負いません。詳細は LICENSE ファイルを参照してください。
*/

namespace libmona;

use Exception;

function bin2hex_lc(string $b): string {
    return strtolower(bin2hex($b));
}

function hex2bin_safe(string $hex): string {
    if (strlen($hex) % 2 !== 0) {
        throw new Exception('hex length must be even');
    }
    $b = hex2bin($hex);
    if ($b === false) {
        throw new Exception('invalid hex');
    }
    return $b;
}

function sha256(string $b): string {
    return hash('sha256', $b, true);
}

function sha256d(string $b): string {
    return sha256(sha256($b));
}

function hash160(string $b): string {
    return hash('ripemd160', sha256($b), true);
}

function hmac_sha256(string $key, string $data): string {
    return hash_hmac('sha256', $data, $key, true);
}

function int_to_le_bytes(int $i, int $len): string {
    $out = '';
    for ($k = 0; $k < $len; $k++) {
        $out .= chr($i & 0xff);
        $i >>= 8;
    }
    return $out;
}

function var_int_bytes(int $i): string {
    if ($i < 0xfd) {
        return chr($i);
    }
    if ($i <= 0xffff) {
        return "\xfd" . int_to_le_bytes($i, 2);
    }
    if ($i <= 0xffffffff) {
        return "\xfe" . int_to_le_bytes($i, 4);
    }
    return "\xff" . int_to_le_bytes($i, 8);
}

function msg_magic(string $message_utf8_bytes): string {
    $prefix = "\x19" . "Monacoin Signed Message:\n";
    return $prefix . var_int_bytes(strlen($message_utf8_bytes)) . $message_utf8_bytes;
}

function electrum_mona_message_hash(string $message_utf8_bytes): string {
    return sha256d(msg_magic($message_utf8_bytes));
}

const MONA_P2PKH = 0x32;
const MONA_P2SH = 0x37;
const MONA_WIF = 0xB0;
const MONA_HRP = 'mona';

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
        throw new Exception('invalid WIF payload length');
    }

    $prefix = ord($payload[0]);
    if ($prefix !== MONA_WIF) {
        throw new Exception('invalid WIF prefix: 0x' . dechex($prefix));
    }

    $secret = substr($payload, 1, 32);
    $compressed = false;

    if (strlen($payload) === 34) {
        if (ord($payload[33]) !== 0x01) {
            throw new Exception('invalid compressed flag');
        }
        $compressed = true;
    }

    if (in_array($txin_type, ['p2wpkh', 'p2wpkh-p2sh', 'p2wsh', 'p2wsh-p2sh'], true) && !$compressed) {
        throw new Exception('segwit script types require compressed pubkey');
    }

    return [$txin_type, $secret, $compressed, $wif];
}
