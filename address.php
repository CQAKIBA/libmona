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

function keypair_from_secret32(string $secret32): array {
    if (strlen($secret32) !== 32) {
        throw new Exception('private key must be 32 bytes');
    }

    $n = secp_n();
    $d = gmp_init('0x' . bin2hex($secret32));
    if (gmp_cmp($d, 1) < 0 || gmp_cmp($d, gmp_sub($n, 1)) > 0) {
        throw new Exception('bad privkey range');
    }

    $G = [secp_Gx(), secp_Gy(), false];
    $pubPoint = point_mul($d, $G);
    $pubCompressed = pubkey_compress($pubPoint);

    return [
        'privkey_wif' => pubkey_to_wif($secret32, true),
        'privkey_raw' => bin2hex_lc($secret32),
        'addr_mona1' => pubkey_to_addr_mona1($pubCompressed),
        'addr_M' => pubkey_to_addr_M($pubCompressed),
        'addr_P' => pubkey_to_addr_P($pubCompressed),
    ];
}

function append_keypair_to_keystore(array $row, string $label = '', ?string $path = null): void {
    $path = $path ?? (__DIR__ . '/privkeys.php');
    $line = json_encode([
        'create' => gmdate('c'),
        'label' => $label,
        'privkey_wif' => $row['privkey_wif'],
        'privkey_raw' => $row['privkey_raw'],
        'addr_mona1' => $row['addr_mona1'],
        'addr_M' => $row['addr_M'],
        'addr_P' => $row['addr_P'],
    ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

    if ($line === false) {
        throw new Exception('failed to encode key row as JSON');
    }
    $ok = file_put_contents($path, $line . PHP_EOL, FILE_APPEND | LOCK_EX);
    if ($ok === false) {
        throw new Exception('failed to append privkeys.php');
    }
}

function load_keystore_rows(?string $path = null): array {
    $path = $path ?? (__DIR__ . '/privkeys.php');
    if (!file_exists($path)) {
        return [];
    }

    $lines = file($path, FILE_IGNORE_NEW_LINES);
    if ($lines === false) {
        throw new Exception('failed to read privkeys.php');
    }

    $rows = [];
    foreach ($lines as $index => $line) {
        $lineNo = $index + 1;
        $trimmed = trim($line);
        if ($trimmed === '') {
            continue;
        }
        $decoded = json_decode($trimmed, true);
        if (!is_array($decoded)) {
            throw new Exception('line ' . $lineNo . ': invalid JSON record in privkeys.php');
        }
        $rows[] = [
            'line' => $lineNo,
            'row' => $decoded,
        ];
    }

    return $rows;
}

function validate_existing_keystore_row(array $expected, array $existing): array {
    $fields = ['privkey_raw', 'privkey_wif', 'addr_mona1', 'addr_M', 'addr_P'];
    $mismatch = [];
    foreach ($fields as $field) {
        $existingValue = isset($existing[$field]) ? (string)$existing[$field] : '';
        if ($existingValue !== (string)$expected[$field]) {
            $mismatch[] = $field;
        }
    }
    return $mismatch;
}

function createnewaddress(bool $save = false, string $label = ''): array {
    do {
        $secret32 = random_bytes(32);
        $d = gmp_init('0x' . bin2hex($secret32));
        $n = secp_n();
    } while (gmp_cmp($d, 1) < 0 || gmp_cmp($d, gmp_sub($n, 1)) > 0);

    $result = keypair_from_secret32($secret32);

    if ($save) {
        append_keypair_to_keystore($result, $label);
    }

    return $result;
}

function importprivrawkey(string $rawkey, string $label = ''): array {
    $secret32 = hex2bin_safe(str_pad(strtolower(trim($rawkey)), 64, '0', STR_PAD_LEFT));
    if ($secret32 === false || strlen($secret32) !== 32) {
        throw new Exception('privkey_raw must be 32 bytes hex');
    }
    $row = keypair_from_secret32($secret32);
    append_keypair_to_keystore($row, $label);
    return $row;
}

function importprivwifkey(string $wifkey, string $label = ''): array {
    [, $secret32, , ] = deserialize_privkey_electrum($wifkey);
    $row = keypair_from_secret32($secret32);
    append_keypair_to_keystore($row, $label);
    return $row;
}

function importprivkey(string $key, string $label = ''): array {
    $trimmed = trim($key);
    if (preg_match('/^[0-9a-fA-F]{64}$/', $trimmed)) {
        $secret32 = hex2bin_safe(str_pad(strtolower($trimmed), 64, '0', STR_PAD_LEFT));
        if ($secret32 === false || strlen($secret32) !== 32) {
            throw new Exception('privkey_raw must be 32 bytes hex');
        }
        $row = keypair_from_secret32($secret32);
    } else {
        [, $secret32, , ] = deserialize_privkey_electrum($trimmed);
        $row = keypair_from_secret32($secret32);
    }

    $keystoreRows = load_keystore_rows();
    foreach ($keystoreRows as $entry) {
        $existing = $entry['row'];
        $isSameRecord = (
            ((string)($existing['privkey_raw'] ?? '') === $row['privkey_raw']) ||
            ((string)($existing['privkey_wif'] ?? '') === $row['privkey_wif']) ||
            ((string)($existing['addr_mona1'] ?? '') === $row['addr_mona1']) ||
            ((string)($existing['addr_M'] ?? '') === $row['addr_M']) ||
            ((string)($existing['addr_P'] ?? '') === $row['addr_P'])
        );
        if (!$isSameRecord) {
            continue;
        }

        $mismatch = validate_existing_keystore_row($row, $existing);
        if (count($mismatch) === 0) {
            $row['message'] = 'line ' . $entry['line'] . ': 既に登録されています';
            $row['line'] = $entry['line'];
            return $row;
        }
        throw new Exception('line ' . $entry['line'] . ': キーストア不整合 [' . implode(', ', $mismatch) . ']');
    }

    append_keypair_to_keystore($row, $label);
    return $row;
}
