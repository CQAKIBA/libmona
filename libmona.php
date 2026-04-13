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
    $commands = [
        'createnewaddress' => [
            'usage' => 'createnewaddress ( save label )',
            'required' => 0,
            'params' => ['save', 'label'],
            'example' => "php libmona.php createnewaddress true 'my_wallet_label'",
        ],
        'importprivrawkey' => [
            'usage' => 'importprivrawkey <rawkey> (label)',
            'required' => 1,
            'params' => ['rawkey', 'label'],
            'example' => "php libmona.php importprivrawkey '3af5a061be34179ec6608d4cd4eaaeb788cae8e1d862fa84288f56ff84beb8d4' 'imported_raw'",
        ],
        'importprivwifkey' => [
            'usage' => 'importprivwifkey <wifkey> (label)',
            'required' => 1,
            'params' => ['wifkey', 'label'],
            'example' => "php libmona.php importprivwifkey 'T52ayqQzJrzBDP5ok7KXe3cNFjf8qpvydDViKrVCpQncipHAyyyW' 'imported_wif'",
        ],
        'importprivkey' => [
            'usage' => 'importprivkey <raw_or_wif_key> (label)',
            'required' => 1,
            'params' => ['key', 'label'],
            'example' => "php libmona.php importprivkey 'T52ayqQzJrzBDP5ok7KXe3cNFjf8qpvydDViKrVCpQncipHAyyyW' 'auto_import'",
        ],
        'signmessage' => [
            'usage' => 'signmessage <message> <privkey>',
            'required' => 2,
            'params' => ['message', 'privkey'],
            'example' => "php libmona.php signmessage 'hello mona' 'L1aW4aubDFB7yfras2S1mN3bqg9w7j1Huxu6mA5fN2v9oQqv4nY2'",
        ],
        'verifymessage' => [
            'usage' => 'verifymessage <address> <signature> <message>',
            'required' => 3,
            'params' => ['address', 'signature', 'message'],
            'example' => "php libmona.php verifymessage 'PM9m3P4QvYpV4Yh6Yf8a8C7oD8uQn2fBvQ' 'H8zQ7z6...base64sig...' 'hello mona'",
        ],
        'createrawtransaction' => [
            'usage' => 'createrawtransaction [{"txid":"hex","vout":n,"sequence":n},...] [{"address":amount},{"data":"hex"},...] ( locktime replaceable version )',
            'required' => 2,
            'params' => ['inputs_json', 'outputs_json', 'locktime', 'replaceable', 'version'],
            'example' => "php libmona.php createrawtransaction '[{\"txid\":\"95a6a0fb469f83b2d135a5d43ab0642fc31217938a290e3e6e1832babff708f3\",\"vout\":0}]' '[{\"mona1qxc7zz03f4eqql4jgwf9pzcsw3h537c5axqervu\":\"0.01000000\"},{\"mona1qsja6dj05827d0htzavj0ygxw77qh0tc07yt2ka\":\"0.08997464\"}]'",
        ],
        'signrawtransactionwithkey' => [
            'usage' => 'signrawtransactionwithkey "hexstring" ["privatekey",...] ( [{"txid":"hex","vout":n,"scriptPubKey":"hex","redeemScript":"hex","witnessScript":"hex","amount":amount},...] "sighashtype" )',
            'required' => 2,
            'params' => ['rawtx_hex', 'privkeys_json', 'prevtxs_json', 'sighashtype'],
            'example' => "php libmona.php signrawtransactionwithkey '0200...0000' '[\"T8Q5...\"]' '[{\"txid\":\"95a6...\",\"vout\":0,\"address\":\"mona1q...\",\"amount\":\"0.10000000\"}]' 'ALL'",
        ],
        'signrawtransactionwithrawkey' => [
            'usage' => 'signrawtransactionwithrawkey <rawtx_hex> <prevouts_json> <privkey_raw_hex>',
            'required' => 3,
            'params' => ['rawtx_hex', 'prevouts_json', 'privkey_raw_hex'],
            'example' => "php libmona.php signrawtransactionwithrawkey '0200...0000' '[{\"txid\":\"95a6a0fb469f83b2d135a5d43ab0642fc31217938a290e3e6e1832babff708f3\",\"vout\":0,\"address\":\"mona1qxc7zz03f4eqql4jgwf9pzcsw3h537c5axqervu\",\"amount\":\"0.10000000\"}]' 'your_32byte_hex_privkey'",
        ],
        'signrawtransactionwithwifkey' => [
            'usage' => 'signrawtransactionwithwifkey <rawtx_hex> <prevouts_json> <privkey_wif>',
            'required' => 3,
            'params' => ['rawtx_hex', 'prevouts_json', 'privkey_wif'],
            'example' => "php libmona.php signrawtransactionwithwifkey '0200000001f308f7bfba32186e3e0e298a931712c32f64b03ad4a535d1b2839f46fba0a6950000000000ffffffff0240420f0000000000160014363c213e29ae400fd648724a11620e8de91f629d584a89000000000016001484bba6c9f43abcd7dd62eb24f220cef78177af0f00000000' '[{\"txid\":\"95a6a0fb469f83b2d135a5d43ab0642fc31217938a290e3e6e1832babff708f3\",\"vout\":0,\"address\":\"mona1qxc7zz03f4eqql4jgwf9pzcsw3h537c5axqervu\",\"amount\":\"0.10000000\"}]' 'T8Q5YNuVqzVkQSo8joGvjJciATWZw9AmDScoE3AWwWoF8p2ZYnKY'",
        ],
        'signrawtransactionwithaddress' => [
            'usage' => 'signrawtransactionwithaddress <rawtx_hex> <prevouts_json> <address> [keyfile]',
            'required' => 3,
            'params' => ['rawtx_hex', 'prevouts_json', 'address', 'keyfile'],
            'example' => "php libmona.php signrawtransactionwithaddress '0200...0000' '[{\"txid\":\"95a6a0fb469f83b2d135a5d43ab0642fc31217938a290e3e6e1832babff708f3\",\"vout\":0,\"address\":\"mona1qxc7zz03f4eqql4jgwf9pzcsw3h537c5axqervu\",\"amount\":\"0.10000000\"}]' 'mona1q...' '/path/to/address.json'",
        ],
    ];

    $printUsage = static function () use ($commands): void {
        echo "usage:\n";
        echo "  php libmona.php <command> [params...]\n";
        echo "  php libmona.php -json '{\"method\":\"<command>\",\"params\":[...]}'\n\n";
        echo "commands:\n";
        foreach ($commands as $name => $spec) {
            echo "  - {$name}: {$spec['usage']}\n";
        }
        echo "\nexamples:\n";
        foreach ($commands as $spec) {
            echo "  {$spec['example']}\n";
        }
    };

    try {
        $decodeJsonArg = static function ($json, string $name) {
            if (is_array($json)) {
                return $json;
            }
            $decoded = json_decode($json, true);
            if (json_last_error() !== JSON_ERROR_NONE || !is_array($decoded)) {
                $message = json_last_error() === JSON_ERROR_NONE ? 'JSON must decode to array/object' : json_last_error_msg();
                throw new \InvalidArgumentException($name . ' JSON不正: ' . $message);
            }

            return $decoded;
        };

        $parseBool01 = static function ($value, string $name): bool {
            if (is_bool($value)) {
                return $value;
            }
            if ($value === 1 || $value === '1' || $value === 'true' || $value === 'TRUE') {
                return true;
            }
            if ($value === 0 || $value === '0' || $value === 'false' || $value === 'FALSE') {
                return false;
            }

            throw new \InvalidArgumentException($name . ' must be true/false or 0/1');
        };

        $args = array_slice($argv, 1);
        $command = null;
        $argMap = [];

        if (($args[0] ?? null) === '-json') {
            if (!isset($args[1])) {
                throw new \InvalidArgumentException('usage: php libmona.php -json \'{"method":"<command>","params":[...]}\'');
            }
            $rpcLike = json_decode($args[1], true);
            if (!is_array($rpcLike) || json_last_error() !== JSON_ERROR_NONE) {
                $message = json_last_error() === JSON_ERROR_NONE ? 'JSON must decode to object/array' : json_last_error_msg();
                throw new \InvalidArgumentException('引数 JSON不正: ' . $message);
            }
            if (!isset($rpcLike['method']) || !is_string($rpcLike['method'])) {
                throw new \InvalidArgumentException('method is required in -json payload');
            }
            $command = $rpcLike['method'];
            if (!isset($commands[$command])) {
                throw new \InvalidArgumentException('unknown method: ' . $command);
            }
            $params = $rpcLike['params'] ?? [];
            if (!is_array($params)) {
                throw new \InvalidArgumentException('params must be array');
            }
            foreach ($commands[$command]['params'] as $index => $paramName) {
                if (array_key_exists($index, $params)) {
                    $argMap[$paramName] = $params[$index];
                } elseif (array_key_exists($paramName, $params)) {
                    $argMap[$paramName] = $params[$paramName];
                }
            }
            $requiredParams = array_slice($commands[$command]['params'], 0, $commands[$command]['required']);
            foreach ($requiredParams as $requiredParam) {
                if (!array_key_exists($requiredParam, $argMap)) {
                    throw new \InvalidArgumentException('usage: ' . $commands[$command]['usage']);
                }
            }
        } else {
            $command = $args[0] ?? null;
            if ($command === null || !isset($commands[$command])) {
                $printUsage();
                exit(1);
            }
            $usage = $commands[$command]['usage'];
            $args = array_slice($args, 1);
            if (count($args) < $commands[$command]['required']) {
                throw new \InvalidArgumentException('usage: ' . $usage);
            }
            foreach ($commands[$command]['params'] as $index => $paramName) {
                if (array_key_exists($index, $args)) {
                    $argMap[$paramName] = $args[$index];
                }
            }
        }

        switch ($command) {
            case 'createnewaddress':
                $save = array_key_exists('save', $argMap) ? $parseBool01($argMap['save'], 'save') : false;
                $label = $argMap['label'] ?? '';
                $result = \libmona\createnewaddress($save, (string)$label);
                break;

            case 'importprivrawkey':
                $label = $argMap['label'] ?? '';
                $result = \libmona\importprivrawkey((string)$argMap['rawkey'], (string)$label);
                break;

            case 'importprivwifkey':
                $label = $argMap['label'] ?? '';
                $result = \libmona\importprivwifkey((string)$argMap['wifkey'], (string)$label);
                break;

            case 'importprivkey':
                $label = $argMap['label'] ?? '';
                $result = \libmona\importprivkey((string)$argMap['key'], (string)$label);
                break;

            case 'signmessage':
                $result = \libmona\signmessage((string)$argMap['message'], (string)$argMap['privkey']);
                break;

            case 'verifymessage':
                $result = \libmona\verifymessage((string)$argMap['address'], (string)$argMap['message'], (string)$argMap['signature']);
                break;

            case 'createrawtransaction':
                $inputs = $decodeJsonArg($argMap['inputs_json'], 'inputs_json');
                $outputs = $decodeJsonArg($argMap['outputs_json'], 'outputs_json');
                $locktime = isset($argMap['locktime']) ? (int)$argMap['locktime'] : 0;
                $replaceable = array_key_exists('replaceable', $argMap) ? $parseBool01($argMap['replaceable'], 'replaceable') : false;
                $version = isset($argMap['version']) ? (int)$argMap['version'] : 2;
                $result = [
                    'hex' => \libmona\createrawtransaction($inputs, $outputs, $locktime, $replaceable, $version),
                ];
                break;

            case 'signrawtransactionwithkey':
                $privkeys = $decodeJsonArg($argMap['privkeys_json'], 'privkeys_json');
                if (count($privkeys) === 0) {
                    throw new \InvalidArgumentException('privkeys must not be empty');
                }
                $prevouts = isset($argMap['prevtxs_json'])
                    ? $decodeJsonArg($argMap['prevtxs_json'], 'prevtxs_json')
                    : [];
                $sighashtype = isset($argMap['sighashtype']) ? strtoupper((string)$argMap['sighashtype']) : 'ALL';
                if ($sighashtype !== 'ALL') {
                    throw new \InvalidArgumentException('unsupported sighashtype: ' . $sighashtype . ' (only ALL supported)');
                }
                $firstPrivkey = (string)$privkeys[0];
                if ($firstPrivkey === '') {
                    throw new \InvalidArgumentException('first private key must not be empty');
                }
                if (preg_match('/^[0-9a-fA-F]{64}$/', $firstPrivkey)) {
                    $result = \libmona\signrawtransactionwithrawkey((string)$argMap['rawtx_hex'], $prevouts, $firstPrivkey);
                } else {
                    $result = \libmona\signrawtransactionwithwifkey((string)$argMap['rawtx_hex'], $prevouts, $firstPrivkey);
                }
                break;

            case 'signrawtransactionwithrawkey':
                $prevouts = $decodeJsonArg($argMap['prevouts_json'], 'prevouts_json');
                $result = \libmona\signrawtransactionwithrawkey((string)$argMap['rawtx_hex'], $prevouts, (string)$argMap['privkey_raw_hex']);
                break;

            case 'signrawtransactionwithwifkey':
                $prevouts = $decodeJsonArg($argMap['prevouts_json'], 'prevouts_json');
                $result = \libmona\signrawtransactionwithwifkey((string)$argMap['rawtx_hex'], $prevouts, (string)$argMap['privkey_wif']);
                break;

            case 'signrawtransactionwithaddress':
                $prevouts = $decodeJsonArg($argMap['prevouts_json'], 'prevouts_json');
                $keyfile = isset($argMap['keyfile']) ? (string)$argMap['keyfile'] : null;
                $result = \libmona\signrawtransactionwithaddress((string)$argMap['rawtx_hex'], $prevouts, (string)$argMap['address'], $keyfile);
                break;
        }

        echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . PHP_EOL;
        exit(0);
    } catch (\Throwable $e) {
        fwrite(STDERR, json_encode([
            'error' => $e->getMessage(),
            'command' => (string)$command,
        ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . PHP_EOL);
        exit(1);
    }
}
