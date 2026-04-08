<?php
namespace libmona;

use Exception;
use Throwable;

function hex_rev_bytes(string $hex): string {
    return bin2hex_lc(strrev(hex2bin_safe($hex)));
}

function le_bytes_to_int(string $b): int {
    $v = 0;
    for ($i = strlen($b) - 1; $i >= 0; $i--) {
        $v = ($v << 8) | ord($b[$i]);
    }
    return $v;
}

function read_bytes(string $bin, int &$offset, int $len): string {
    if ($len < 0 || $offset + $len > strlen($bin)) {
        throw new Exception('unexpected EOF');
    }
    $out = substr($bin, $offset, $len);
    $offset += $len;
    return $out;
}

function read_var_int(string $bin, int &$offset): int {
    $first = ord(read_bytes($bin, $offset, 1));
    if ($first < 0xfd) {
        return $first;
    }
    if ($first === 0xfd) {
        return le_bytes_to_int(read_bytes($bin, $offset, 2));
    }
    if ($first === 0xfe) {
        return le_bytes_to_int(read_bytes($bin, $offset, 4));
    }
    $v = le_bytes_to_int(read_bytes($bin, $offset, 8));
    if ($v < 0) {
        throw new Exception('varint too large');
    }
    return $v;
}

function parse_transaction(string $rawtx_hex): array {
    $bin = hex2bin_safe($rawtx_hex);
    $offset = 0;

    $version = le_bytes_to_int(read_bytes($bin, $offset, 4));
    $isSegwit = false;

    if ($offset + 2 <= strlen($bin) && substr($bin, $offset, 2) === "\x00\x01") {
        $isSegwit = true;
        $offset += 2;
    }

    $vinCount = read_var_int($bin, $offset);
    $vin = [];
    for ($i = 0; $i < $vinCount; $i++) {
        $txidLe = read_bytes($bin, $offset, 32);
        $vout = le_bytes_to_int(read_bytes($bin, $offset, 4));
        $scriptLen = read_var_int($bin, $offset);
        $scriptSig = read_bytes($bin, $offset, $scriptLen);
        $sequence = le_bytes_to_int(read_bytes($bin, $offset, 4));
        $vin[] = [
            'txid' => bin2hex_lc(strrev($txidLe)),
            'vout' => $vout,
            'scriptSig' => $scriptSig,
            'sequence' => $sequence,
            'witness' => [],
        ];
    }

    $voutCount = read_var_int($bin, $offset);
    $vout = [];
    for ($i = 0; $i < $voutCount; $i++) {
        $amountSats = le_bytes_to_int(read_bytes($bin, $offset, 8));
        $pkLen = read_var_int($bin, $offset);
        $scriptPubKey = read_bytes($bin, $offset, $pkLen);
        $vout[] = [
            'amount_sats' => $amountSats,
            'scriptPubKey' => $scriptPubKey,
        ];
    }

    if ($isSegwit) {
        for ($i = 0; $i < $vinCount; $i++) {
            $n = read_var_int($bin, $offset);
            $items = [];
            for ($k = 0; $k < $n; $k++) {
                $len = read_var_int($bin, $offset);
                $items[] = read_bytes($bin, $offset, $len);
            }
            $vin[$i]['witness'] = $items;
        }
    }

    $locktime = le_bytes_to_int(read_bytes($bin, $offset, 4));
    if ($offset !== strlen($bin)) {
        throw new Exception('unexpected trailing bytes');
    }

    return [
        'version' => $version,
        'vin' => $vin,
        'vout' => $vout,
        'locktime' => $locktime,
    ];
}

function serialize_transaction(array $tx, bool $includeWitness = true): string {
    $bin = int_to_le_bytes((int)$tx['version'], 4);

    $hasWitness = false;
    if ($includeWitness) {
        foreach ($tx['vin'] as $in) {
            if (!empty($in['witness'])) {
                $hasWitness = true;
                break;
            }
        }
    }

    if ($hasWitness) {
        $bin .= "\x00\x01";
    }

    $bin .= var_int_bytes(count($tx['vin']));
    foreach ($tx['vin'] as $in) {
        $bin .= strrev(hex2bin_safe($in['txid']));
        $bin .= int_to_le_bytes((int)$in['vout'], 4);
        $scriptSig = $in['scriptSig'] ?? '';
        $bin .= var_int_bytes(strlen($scriptSig)) . $scriptSig;
        $bin .= int_to_le_bytes((int)$in['sequence'], 4);
    }

    $bin .= var_int_bytes(count($tx['vout']));
    foreach ($tx['vout'] as $out) {
        $bin .= int_to_le_bytes((int)$out['amount_sats'], 8);
        $spk = $out['scriptPubKey'];
        $bin .= var_int_bytes(strlen($spk)) . $spk;
    }

    if ($hasWitness) {
        foreach ($tx['vin'] as $in) {
            $witness = $in['witness'] ?? [];
            $bin .= var_int_bytes(count($witness));
            foreach ($witness as $item) {
                $bin .= var_int_bytes(strlen($item)) . $item;
            }
        }
    }

    $bin .= int_to_le_bytes((int)$tx['locktime'], 4);
    return $bin;
}

function encode_pushdata(string $data): string {
    $len = strlen($data);
    if ($len < 0x4c) {
        return chr($len) . $data;
    }
    if ($len <= 0xff) {
        return "\x4c" . chr($len) . $data;
    }
    if ($len <= 0xffff) {
        return "\x4d" . int_to_le_bytes($len, 2) . $data;
    }
    throw new Exception('pushdata too large');
}

function sats_from_amount($amount): int {
    if (is_int($amount)) {
        return $amount;
    }
    if (is_float($amount)) {
        return (int) round($amount * 100000000);
    }
    $s = trim((string)$amount);
    if ($s === '') {
        throw new Exception('empty amount');
    }
    if (!preg_match('/^-?\d+(?:\.\d{1,8})?$/', $s)) {
        throw new Exception('invalid amount format');
    }
    $neg = false;
    if ($s[0] === '-') {
        $neg = true;
        $s = substr($s, 1);
    }
    [$whole, $frac] = array_pad(explode('.', $s, 2), 2, '');
    $frac = str_pad($frac, 8, '0');
    $v = ((int)$whole * 100000000) + (int)$frac;
    return $neg ? -$v : $v;
}

function detect_script_type(string $scriptPubKey): ?string {
    $hex = bin2hex_lc($scriptPubKey);
    if (preg_match('/^76a914[0-9a-f]{40}88ac$/', $hex)) {
        return 'p2pkh';
    }
    if (preg_match('/^0014[0-9a-f]{40}$/', $hex)) {
        return 'p2wpkh';
    }
    if (preg_match('/^a914[0-9a-f]{40}87$/', $hex)) {
        return 'p2sh';
    }
    return null;
}

function p2pkh_scriptpubkey_from_pubkey_hash(string $h160): string {
    return "\x76\xa9\x14" . $h160 . "\x88\xac";
}

function p2wpkh_scriptpubkey_from_pubkey_hash(string $h160): string {
    return "\x00\x14" . $h160;
}

function p2sh_scriptpubkey_from_hash160(string $h160): string {
    return "\xa9\x14" . $h160 . "\x87";
}

function p2wpkh_scriptcode_from_pubkey_hash(string $h160): string {
    return p2pkh_scriptpubkey_from_pubkey_hash($h160);
}

function derive_key_material_from_raw(string $privkey_raw_hex): array {
    $secret32 = hex2bin_safe(str_pad(strtolower(trim($privkey_raw_hex)), 64, '0', STR_PAD_LEFT));
    if (strlen($secret32) !== 32) {
        throw new Exception('privkey_raw must be 32 bytes hex');
    }
    $n = secp_n();
    $d = gmp_init('0x' . bin2hex($secret32));
    if (gmp_cmp($d, 1) < 0 || gmp_cmp($d, gmp_sub($n, 1)) > 0) {
        throw new Exception('bad privkey range');
    }
    $G = [secp_Gx(), secp_Gy(), false];
    $pubPoint = point_mul($d, $G);
    $pubCompressed = pubkey_compress($pubPoint);
    $pubHash160 = hash160($pubCompressed);
    return [
        'secret32' => $secret32,
        'pubkey_compressed' => $pubCompressed,
        'pubkey_hash160' => $pubHash160,
        'privkey_raw' => bin2hex_lc($secret32),
        'privkey_wif' => pubkey_to_wif($secret32, true),
        'addr_mona1' => pubkey_to_addr_mona1($pubCompressed),
        'addr_M' => pubkey_to_addr_M($pubCompressed),
        'addr_P' => pubkey_to_addr_P($pubCompressed),
    ];
}

function derive_key_material_from_wif(string $privkey_wif): array {
    [, $secret32, $compressed, $wifOnly] = deserialize_privkey_electrum($privkey_wif);
    if (!$compressed) {
        throw new Exception('only compressed WIF is supported for raw transaction signing');
    }
    $km = derive_key_material_from_raw(bin2hex_lc($secret32));
    $km['privkey_wif'] = $wifOnly;
    return $km;
}

function decode_mona_address(string $address): array {
    if (str_starts_with(strtolower($address), MONA_HRP . '1')) {
        [$hrp, $witver, $witprog] = bech32_decode_segwit_address($address);
        if ($hrp !== MONA_HRP || $witver !== 0 || strlen($witprog) !== 20) {
            throw new Exception('unsupported bech32 address');
        }
        return [
            'type' => 'p2wpkh',
            'hash160' => $witprog,
            'scriptPubKey' => p2wpkh_scriptpubkey_from_pubkey_hash($witprog),
        ];
    }

    $payload = base58check_decode($address);
    if (strlen($payload) !== 21) {
        throw new Exception('invalid base58 address payload');
    }
    $version = ord($payload[0]);
    $h160 = substr($payload, 1);
    if ($version === MONA_P2PKH) {
        return [
            'type' => 'p2pkh',
            'hash160' => $h160,
            'scriptPubKey' => p2pkh_scriptpubkey_from_pubkey_hash($h160),
        ];
    }
    if ($version === MONA_P2SH) {
        return [
            'type' => 'p2sh',
            'hash160' => $h160,
            'scriptPubKey' => p2sh_scriptpubkey_from_hash160($h160),
        ];
    }
    throw new Exception('unsupported address version');
}


function validate_txid_hex(string $txid): string {
    $txid = strtolower(trim($txid));
    if (!preg_match('/^[0-9a-f]{64}$/', $txid)) {
        throw new Exception('txid must be 32-byte hex');
    }
    return $txid;
}

function normalize_createrawtransaction_input(array $input, bool $replaceable, int $locktime): array {
    if (!isset($input['txid'], $input['vout'])) {
        throw new Exception('each input must contain txid and vout');
    }
    $sequence = $input['sequence'] ?? null;
    if ($sequence === null) {
        if ($replaceable) {
            $sequence = 0xfffffffd;
        } elseif ($locktime !== 0) {
            $sequence = 0xfffffffe;
        } else {
            $sequence = 0xffffffff;
        }
    }
    if (!is_int($sequence) && !ctype_digit((string)$sequence)) {
        throw new Exception('input sequence must be integer');
    }
    $sequence = (int)$sequence;
    if ($sequence < 0 || $sequence > 0xffffffff) {
        throw new Exception('input sequence out of range');
    }
    if ($replaceable && $sequence >= 0xfffffffe) {
        throw new Exception('replaceable=true requires sequence < 0xfffffffe for every input');
    }
    return [
        'txid' => validate_txid_hex($input['txid']),
        'vout' => (int)$input['vout'],
        'scriptSig' => '',
        'sequence' => $sequence,
        'witness' => [],
    ];
}

function op_return_scriptpubkey(string $dataHex): string {
    $dataHex = strtolower(trim($dataHex));
    if ($dataHex === '' || !preg_match('/^[0-9a-f]*$/', $dataHex) || (strlen($dataHex) % 2) !== 0) {
        throw new Exception('data output must be even-length hex');
    }
    $data = hex2bin_safe($dataHex);
    if (strlen($data) > 80) {
        throw new Exception('data output too large; max 80 bytes');
    }
    return "j" . encode_pushdata($data);
}

function normalize_createrawtransaction_outputs($outputs): array {
    $result = [];
    $seenAddresses = [];

    $isAssoc = is_array($outputs) && array_keys($outputs) !== range(0, count($outputs) - 1);
    if ($isAssoc) {
        $tmp = [];
        foreach ($outputs as $k => $v) {
            $tmp[] = [$k => $v];
        }
        $outputs = $tmp;
    }

    if (!is_array($outputs)) {
        throw new Exception('outputs must be array');
    }

    foreach ($outputs as $entry) {
        if (!is_array($entry) || count($entry) !== 1) {
            throw new Exception('each output entry must be a single-key array');
        }
        $key = array_key_first($entry);
        $value = $entry[$key];

        if ($key === 'data') {
            $result[] = [
                'amount_sats' => 0,
                'scriptPubKey' => op_return_scriptpubkey((string)$value),
            ];
            continue;
        }

        $address = (string)$key;
        if (isset($seenAddresses[$address])) {
            throw new Exception('duplicate output address: ' . $address);
        }
        $seenAddresses[$address] = true;
        $decoded = decode_mona_address($address);
        $amountSats = sats_from_amount($value);
        if ($amountSats < 0) {
            throw new Exception('output amount must be non-negative');
        }
        $result[] = [
            'amount_sats' => $amountSats,
            'scriptPubKey' => $decoded['scriptPubKey'],
        ];
    }

    if ($result === []) {
        throw new Exception('at least one output is required');
    }

    return $result;
}

function createrawtransaction_decoded(array $inputs, $outputs, int $locktime = 0, bool $replaceable = false, int $version = 2): array {
    if ($locktime < 0 || $locktime > 0xffffffff) {
        throw new Exception('locktime out of range');
    }
    if ($version < 1 || $version > 0x7fffffff) {
        throw new Exception('version out of range');
    }
    if ($inputs === []) {
        throw new Exception('at least one input is required');
    }

    $vin = [];
    foreach ($inputs as $input) {
        if (!is_array($input)) {
            throw new Exception('each input must be array');
        }
        $normalized = normalize_createrawtransaction_input($input, $replaceable, $locktime);
        if ($normalized['vout'] < 0 || $normalized['vout'] > 0xffffffff) {
            throw new Exception('input vout out of range');
        }
        $vin[] = $normalized;
    }

    if ($locktime !== 0) {
        $allFinal = true;
        foreach ($vin as $in) {
            if ($in['sequence'] !== 0xffffffff) {
                $allFinal = false;
                break;
            }
        }
        if ($allFinal) {
            throw new Exception('locktime is non-zero but all input sequences are final');
        }
    }

    return [
        'version' => $version,
        'vin' => $vin,
        'vout' => normalize_createrawtransaction_outputs($outputs),
        'locktime' => $locktime,
    ];
}

function createrawtransaction(array $inputs, $outputs, int $locktime = 0, bool $replaceable = false, int $version = 2): string {
    return bin2hex_lc(serialize_transaction(createrawtransaction_decoded($inputs, $outputs, $locktime, $replaceable, $version), false));
}

function prevout_map(array $prevouts): array {
    $map = [];
    foreach ($prevouts as $p) {
        if (!isset($p['txid'], $p['vout'])) {
            throw new Exception('each prevout needs txid and vout');
        }
        $key = strtolower($p['txid']) . ':' . (int)$p['vout'];
        $map[$key] = $p;
    }
    return $map;
}

function normalize_prevout_with_key(array $prevout, array $km): array {
    $address = $prevout['address'] ?? null;
    $scriptPubKey = isset($prevout['scriptPubKey']) ? hex2bin_safe(strtolower($prevout['scriptPubKey'])) : null;
    $type = $prevout['type'] ?? null;

    if ($address !== null) {
        $decoded = decode_mona_address($address);
        $type = $type ?? $decoded['type'];
        if ($scriptPubKey === null) {
            $scriptPubKey = $decoded['scriptPubKey'];
        }
    }

    if ($scriptPubKey === null) {
        throw new Exception('prevout needs scriptPubKey or address');
    }
    $detected = detect_script_type($scriptPubKey);
    if ($type === null) {
        $type = $detected;
    }
    if ($type === 'p2sh' && $address === ($km['addr_P'] ?? null)) {
        $type = 'p2sh-p2wpkh';
    }
    if ($type === 'p2sh-p2wpkh' && $scriptPubKey !== p2sh_scriptpubkey_from_hash160(hash160(p2wpkh_scriptpubkey_from_pubkey_hash($km['pubkey_hash160'])))) {
        throw new Exception('p2sh-p2wpkh prevout does not match provided key');
    }

    if ($type === 'p2pkh') {
        if ($scriptPubKey !== p2pkh_scriptpubkey_from_pubkey_hash($km['pubkey_hash160'])) {
            throw new Exception('p2pkh prevout does not match provided key');
        }
        return [
            'type' => 'p2pkh',
            'scriptPubKey' => $scriptPubKey,
            'scriptCode' => $scriptPubKey,
            'amount_sats' => sats_from_amount($prevout['amount'] ?? $prevout['amount_sats'] ?? 0),
            'redeemScript' => '',
        ];
    }

    if ($type === 'p2wpkh') {
        $expected = p2wpkh_scriptpubkey_from_pubkey_hash($km['pubkey_hash160']);
        if ($scriptPubKey !== $expected) {
            throw new Exception('p2wpkh prevout does not match provided key');
        }
        $amount = sats_from_amount($prevout['amount'] ?? $prevout['amount_sats'] ?? null);
        return [
            'type' => 'p2wpkh',
            'scriptPubKey' => $scriptPubKey,
            'scriptCode' => p2wpkh_scriptcode_from_pubkey_hash($km['pubkey_hash160']),
            'amount_sats' => $amount,
            'redeemScript' => '',
        ];
    }

    if ($type === 'p2sh-p2wpkh' || ($type === 'p2sh' && $address === ($km['addr_P'] ?? null))) {
        $redeemScript = p2wpkh_scriptpubkey_from_pubkey_hash($km['pubkey_hash160']);
        $expected = p2sh_scriptpubkey_from_hash160(hash160($redeemScript));
        if ($scriptPubKey !== $expected) {
            throw new Exception('p2sh-p2wpkh prevout does not match provided key');
        }
        $amount = sats_from_amount($prevout['amount'] ?? $prevout['amount_sats'] ?? null);
        return [
            'type' => 'p2sh-p2wpkh',
            'scriptPubKey' => $scriptPubKey,
            'scriptCode' => p2wpkh_scriptcode_from_pubkey_hash($km['pubkey_hash160']),
            'amount_sats' => $amount,
            'redeemScript' => $redeemScript,
        ];
    }

    throw new Exception('unsupported prevout type');
}

function tx_legacy_sighash_all(array $tx, int $vinIndex, string $scriptCode): string {
    $tmp = $tx;
    foreach ($tmp['vin'] as $i => &$in) {
        $in['scriptSig'] = ($i === $vinIndex) ? $scriptCode : '';
        $in['witness'] = [];
    }
    unset($in);
    $ser = serialize_transaction($tmp, false) . int_to_le_bytes(1, 4);
    return sha256d($ser);
}

function bip143_hash_prevouts(array $tx): string {
    $buf = '';
    foreach ($tx['vin'] as $in) {
        $buf .= strrev(hex2bin_safe($in['txid']));
        $buf .= int_to_le_bytes((int)$in['vout'], 4);
    }
    return sha256d($buf);
}

function bip143_hash_sequence(array $tx): string {
    $buf = '';
    foreach ($tx['vin'] as $in) {
        $buf .= int_to_le_bytes((int)$in['sequence'], 4);
    }
    return sha256d($buf);
}

function bip143_hash_outputs(array $tx): string {
    $buf = '';
    foreach ($tx['vout'] as $out) {
        $buf .= int_to_le_bytes((int)$out['amount_sats'], 8);
        $buf .= var_int_bytes(strlen($out['scriptPubKey'])) . $out['scriptPubKey'];
    }
    return sha256d($buf);
}

function tx_segwit_v0_sighash_all(array $tx, int $vinIndex, string $scriptCode, int $amountSats): string {
    $preimage = '';
    $preimage .= int_to_le_bytes((int)$tx['version'], 4);
    $preimage .= bip143_hash_prevouts($tx);
    $preimage .= bip143_hash_sequence($tx);
    $preimage .= strrev(hex2bin_safe($tx['vin'][$vinIndex]['txid']));
    $preimage .= int_to_le_bytes((int)$tx['vin'][$vinIndex]['vout'], 4);
    $preimage .= var_int_bytes(strlen($scriptCode)) . $scriptCode;
    $preimage .= int_to_le_bytes($amountSats, 8);
    $preimage .= int_to_le_bytes((int)$tx['vin'][$vinIndex]['sequence'], 4);
    $preimage .= bip143_hash_outputs($tx);
    $preimage .= int_to_le_bytes((int)$tx['locktime'], 4);
    $preimage .= int_to_le_bytes(1, 4);
    return sha256d($preimage);
}

function der_encode_int(string $bin): string {
    $bin = ltrim($bin, "\x00");
    if ($bin === '') {
        $bin = "\x00";
    }
    if ((ord($bin[0]) & 0x80) !== 0) {
        $bin = "\x00" . $bin;
    }
    return "\x02" . chr(strlen($bin)) . $bin;
}

function der_encode_signature($r, $s): string {
    $rbin = hex2bin_safe(str_pad(gmp_strval($r, 16), 64, '0', STR_PAD_LEFT));
    $sbin = hex2bin_safe(str_pad(gmp_strval($s, 16), 64, '0', STR_PAD_LEFT));
    $body = der_encode_int($rbin) . der_encode_int($sbin);
    return "\x30" . chr(strlen($body)) . $body;
}

function sign_transaction_with_key_material(string $rawtx_hex, array $prevouts, array $km): array {
    $tx = parse_transaction($rawtx_hex);
    $prevoutMap = prevout_map($prevouts);
    $signedCount = 0;
    $errors = [];

    foreach ($tx['vin'] as $i => &$in) {
        $key = strtolower($in['txid']) . ':' . (int)$in['vout'];
        if (!isset($prevoutMap[$key])) {
            $errors[] = 'missing prevout for input #' . $i . ' (' . $key . ')';
            continue;
        }

        try {
            $p = normalize_prevout_with_key($prevoutMap[$key], $km);
            if ($p['type'] === 'p2pkh') {
                $hash32 = tx_legacy_sighash_all($tx, $i, $p['scriptCode']);
                [$r, $s] = ecdsa_sign_rfc6979($hash32, $km['secret32']);
                $sig = der_encode_signature($r, $s) . "\x01";
                $in['scriptSig'] = encode_pushdata($sig) . encode_pushdata($km['pubkey_compressed']);
                $in['witness'] = [];
                $signedCount++;
                continue;
            }

            if (!isset($prevoutMap[$key]['amount']) && !isset($prevoutMap[$key]['amount_sats'])) {
                throw new Exception('segwit input requires amount or amount_sats');
            }
            $hash32 = tx_segwit_v0_sighash_all($tx, $i, $p['scriptCode'], $p['amount_sats']);
            [$r, $s] = ecdsa_sign_rfc6979($hash32, $km['secret32']);
            $sig = der_encode_signature($r, $s) . "\x01";
            if ($p['type'] === 'p2wpkh') {
                $in['scriptSig'] = '';
                $in['witness'] = [$sig, $km['pubkey_compressed']];
                $signedCount++;
                continue;
            }
            if ($p['type'] === 'p2sh-p2wpkh') {
                $in['scriptSig'] = encode_pushdata($p['redeemScript']);
                $in['witness'] = [$sig, $km['pubkey_compressed']];
                $signedCount++;
                continue;
            }
            throw new Exception('unsupported normalized type');
        } catch (Throwable $e) {
            $errors[] = 'input #' . $i . ': ' . $e->getMessage();
        }
    }
    unset($in);

    return [
        'hex' => bin2hex_lc(serialize_transaction($tx, true)),
        'complete' => $signedCount === count($tx['vin']) && count($errors) === 0,
        'signed_inputs' => $signedCount,
        'total_inputs' => count($tx['vin']),
        'privkey_wif' => $km['privkey_wif'],
        'privkey_raw' => $km['privkey_raw'],
        'addr_mona1' => $km['addr_mona1'],
        'addr_M' => $km['addr_M'],
        'addr_P' => $km['addr_P'],
        'errors' => $errors,
    ];
}

function signrawtransactionwithrawkey(string $rawtx_hex, array $prevouts, string $privkey_raw_hex): array {
    return sign_transaction_with_key_material($rawtx_hex, $prevouts, derive_key_material_from_raw($privkey_raw_hex));
}

function signrawtransactionwithwifkey(string $rawtx_hex, array $prevouts, string $privkey_wif): array {
    return sign_transaction_with_key_material($rawtx_hex, $prevouts, derive_key_material_from_wif($privkey_wif));
}

function load_saved_privkeys(string $keyfile = null): array {
    $keyfile = $keyfile ?? (__DIR__ . '/privkeys.php');
    if (!is_file($keyfile)) {
        throw new Exception('key file not found: ' . $keyfile);
    }
    $json = file_get_contents($keyfile);
    if ($json === false) {
        throw new Exception('failed to read key file');
    }
    $data = json_decode($json, true);
    if (!is_array($data)) {
        throw new Exception('key file is not valid JSON array');
    }
    return $data;
}

function signrawtransactionwithaddress(string $rawtx_hex, array $prevouts, string $address, ?string $keyfile = null): array {
    $rows = load_saved_privkeys($keyfile);
    foreach ($rows as $row) {
        if (!is_array($row)) {
            continue;
        }
        foreach (['addr_mona1', 'addr_M', 'addr_P'] as $field) {
            if (isset($row[$field]) && is_string($row[$field]) && hash_equals($row[$field], $address)) {
                if (empty($row['privkey_raw']) && empty($row['privkey_wif'])) {
                    throw new Exception('matched address has no usable private key in key file');
                }
                if (!empty($row['privkey_raw'])) {
                    return signrawtransactionwithrawkey($rawtx_hex, $prevouts, $row['privkey_raw']);
                }
                return signrawtransactionwithwifkey($rawtx_hex, $prevouts, $row['privkey_wif']);
            }
        }
    }
    throw new Exception('address not found in key file');
}
