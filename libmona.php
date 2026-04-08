<?php
namespace libmona;

require_once __DIR__ . '/base58.php';
require_once __DIR__ . '/bech32.php';
require_once __DIR__ . '/secp256k1.php';
require_once __DIR__ . '/core.php';
require_once __DIR__ . '/address.php';
require_once __DIR__ . '/rawtx.php';
require_once __DIR__ . '/sign.php';
require_once __DIR__ . '/verify.php';

if (PHP_SAPI === 'cli' && realpath($_SERVER['SCRIPT_FILENAME']) === __FILE__) {
    try {
        $command = $argv[1] ?? null;
        if ($command === null) {
            throw new \InvalidArgumentException('command is required');
        }

        switch ($command) {
            case 'createnewaddress':
                $save = isset($argv[2]) ? filter_var($argv[2], FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE) : false;
                if ($save === null) {
                    throw new \InvalidArgumentException('save must be boolean');
                }
                $label = $argv[3] ?? '';
                $result = \libmona\createnewaddress($save, $label);
                break;

            case 'signmessage':
                if (!isset($argv[2], $argv[3])) {
                    throw new \InvalidArgumentException('usage: signmessage <message> <privkey>');
                }
                $result = \libmona\signmessage($argv[2], $argv[3]);
                break;

            case 'verifymessage':
                if (!isset($argv[2], $argv[3], $argv[4])) {
                    throw new \InvalidArgumentException('usage: verifymessage <address> <message> <signature>');
                }
                $result = \libmona\verifymessage($argv[2], $argv[3], $argv[4]);
                break;

            case 'createrawtransaction':
                if (!isset($argv[2], $argv[3])) {
                    throw new \InvalidArgumentException('usage: createrawtransaction <inputs_json> <outputs_json> [locktime] [replaceable] [version]');
                }
                $inputs = json_decode($argv[2], true, 512, JSON_THROW_ON_ERROR);
                $outputs = json_decode($argv[3], true, 512, JSON_THROW_ON_ERROR);
                $locktime = isset($argv[4]) ? (int)$argv[4] : 0;
                $replaceable = isset($argv[5])
                    ? filter_var($argv[5], FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE)
                    : false;
                if ($replaceable === null) {
                    throw new \InvalidArgumentException('replaceable must be boolean');
                }
                $version = isset($argv[6]) ? (int)$argv[6] : 2;
                $result = [
                    'hex' => \libmona\createrawtransaction($inputs, $outputs, $locktime, $replaceable, $version),
                ];
                break;

            case 'signrawtransactionwithrawkey':
                if (!isset($argv[2], $argv[3], $argv[4])) {
                    throw new \InvalidArgumentException('usage: signrawtransactionwithrawkey <rawtx_hex> <prevouts_json> <privkey_raw_hex>');
                }
                $prevouts = json_decode($argv[3], true, 512, JSON_THROW_ON_ERROR);
                $result = \libmona\signrawtransactionwithrawkey($argv[2], $prevouts, $argv[4]);
                break;

            case 'signrawtransactionwithwifkey':
                if (!isset($argv[2], $argv[3], $argv[4])) {
                    throw new \InvalidArgumentException('usage: signrawtransactionwithwifkey <rawtx_hex> <prevouts_json> <privkey_wif>');
                }
                $prevouts = json_decode($argv[3], true, 512, JSON_THROW_ON_ERROR);
                $result = \libmona\signrawtransactionwithwifkey($argv[2], $prevouts, $argv[4]);
                break;

            case 'signrawtransactionwithaddress':
                if (!isset($argv[2], $argv[3], $argv[4])) {
                    throw new \InvalidArgumentException('usage: signrawtransactionwithaddress <rawtx_hex> <prevouts_json> <address> [keyfile]');
                }
                $prevouts = json_decode($argv[3], true, 512, JSON_THROW_ON_ERROR);
                $keyfile = $argv[5] ?? null;
                $result = \libmona\signrawtransactionwithaddress($argv[2], $prevouts, $argv[4], $keyfile);
                break;

            default:
                throw new \InvalidArgumentException('unsupported command: ' . $command);
        }

        echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . PHP_EOL;
    } catch (\Throwable $e) {
        echo json_encode([
            'error' => $e->getMessage(),
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . PHP_EOL;
        exit(1);
    }
}
