<?php

function decode_sig_header(int $header): array {
    if ($header < 27 || $header > 42) {
        throw new Exception('Bad encoding');
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
        throw new Exception('Bad recid');
    }

    return [$recid, $compressed, $txinTypeGuess];
}

function verifymessage(string $address, string $message, string $signature): array {
    $result = [
        'address' => $address,
        'message' => $message,
        'signature' => $signature,
        'valid' => false,
        'error' => null,
        'header' => null,
        'recid' => null,
        'compressed' => null,
        'txin_type_guess' => null,
        'pubkey_compressed' => null,
        'addr_mona1' => null,
        'addr_M' => null,
        'addr_P' => null,
    ];

    try {
        $sig65 = base64_decode($signature, true);
        if ($sig65 === false || strlen($sig65) !== 65) {
            throw new Exception('signature must be valid base64 of 65 bytes');
        }

        $header = ord($sig65[0]);
        [$recid, $compressed, $txinTypeGuess] = decode_sig_header($header);

        $r = gmp_init('0x' . bin2hex(substr($sig65, 1, 32)));
        $s = gmp_init('0x' . bin2hex(substr($sig65, 33, 32)));

        $msgBytes = $message;
        $h32 = electrum_mona_message_hash($msgBytes);

        $Q = recover_pubkey_from_sig($r, $s, $h32, $recid);
        if ($Q === null || point_is_inf($Q)) {
            throw new Exception('public key recovery failed');
        }

        $pubCompressed = pubkey_compress($Q);

        $addrMona1 = pubkey_to_addr_mona1($pubCompressed);
        $addrM = pubkey_to_addr_M($pubCompressed);
        $addrP = pubkey_to_addr_P($pubCompressed);

        $result['header'] = $header;
        $result['recid'] = $recid;
        $result['compressed'] = $compressed;
        $result['txin_type_guess'] = $txinTypeGuess;
        $result['pubkey_compressed'] = bin2hex_lc($pubCompressed);
        $result['addr_mona1'] = $addrMona1;
        $result['addr_M'] = $addrM;
        $result['addr_P'] = $addrP;

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
            throw new Exception('address mismatch');
        }

        if (!ecdsa_verify_compact($h32, $r, $s, $Q)) {
            throw new Exception('ecdsa verify failed');
        }

        $result['valid'] = true;
        return $result;
    } catch (Throwable $e) {
        $result['error'] = $e->getMessage();
        return $result;
    }
}
