<?php
namespace libmona;

use Exception;

function pubkey_to_addr_M(string $pubkey_compressed): string {
    $h160 = hash160($pubkey_compressed);
    return base58check_encode(chr(MONA_P2PKH) . $h160);
}

function pubkey_to_addr_mona1(string $pubkey_compressed): string {
    $h160 = hash160($pubkey_compressed);
    return bech32_segwit_address(MONA_HRP, 0, $h160);
}

function pubkey_to_addr_P(string $pubkey_compressed): string {
    $h160 = hash160($pubkey_compressed);
    $redeem = "\x00\x14" . $h160;
    $redeem_h160 = hash160($redeem);
    return base58check_encode(chr(MONA_P2SH) . $redeem_h160);
}

function pubkey_to_wif(string $secret32, bool $compressed = true): string {
    $payload = chr(MONA_WIF) . $secret32 . ($compressed ? "\x01" : '');
    return base58check_encode($payload);
}

function createnewaddress(bool $save = false, string $label = ''): array {
    $n = secp_n();
    $G = [secp_Gx(), secp_Gy(), false];

    do {
        $secret32 = random_bytes(32);
        $d = gmp_init('0x' . bin2hex($secret32));
    } while (gmp_cmp($d, 1) < 0 || gmp_cmp($d, gmp_sub($n, 1)) > 0);

    $pubPoint = point_mul($d, $G);
    $pubCompressed = pubkey_compress($pubPoint);
    $result = [
        'privkey_wif' => pubkey_to_wif($secret32, true),
        'privkey_raw' => bin2hex_lc($secret32),
        'addr_mona1' => pubkey_to_addr_mona1($pubCompressed),
        'addr_M' => pubkey_to_addr_M($pubCompressed),
        'addr_P' => pubkey_to_addr_P($pubCompressed),
    ];

    if ($save) {
        $path = __DIR__ . '/privkeys.php';
        $rows = [];
        if (is_file($path)) {
            $json = file_get_contents($path);
            if ($json === false) {
                throw new Exception('failed to read existing privkeys.php');
            }
            $decoded = json_decode($json, true);
            if ($decoded !== null && !is_array($decoded)) {
                throw new Exception('existing privkeys.php is not a JSON array');
            }
            if (is_array($decoded)) {
                $rows = $decoded;
            }
        }
        $rows[] = [
            'create' => gmdate('c'),
            'label' => $label,
            'privkey_wif' => $result['privkey_wif'],
            'privkey_raw' => $result['privkey_raw'],
            'addr_mona1' => $result['addr_mona1'],
            'addr_M' => $result['addr_M'],
            'addr_P' => $result['addr_P'],
        ];
        $ok = file_put_contents($path, json_encode($rows, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        if ($ok === false) {
            throw new Exception('failed to write privkeys.php');
        }
    }

    return $result;
}
