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
        $commands = [
            'createnewaddress' => [
                'usage' => 'createnewaddress [save(0|1)] [label]',
                'required' => 0,
                'params' => ['save', 'label'],
            ],
            'signmessage' => [
                'usage' => 'signmessage <message> <privkey>',
                'required' => 2,
                'params' => ['message', 'privkey'],
            ],
            'verifymessage' => [
                'usage' => 'verifymessage <address> <message> <signature>',
                'required' => 3,
                'params' => ['address', 'message', 'signature'],
            ],
            'createrawtransaction' => [
                'usage' => 'createrawtransaction <inputs_json> <outputs_json> [locktime] [replaceable(0|1)] [version]',
                'required' => 2,
                'params' => ['inputs_json', 'outputs_json', 'locktime', 'replaceable', 'version'],
            ],
            'signrawtransactionwithrawkey' => [
                'usage' => 'signrawtransactionwithrawkey <rawtx_hex> <prevouts_json> <privkey_raw_hex>',
                'required' => 3,
                'params' => ['rawtx_hex', 'prevouts_json', 'privkey_raw_hex'],
            ],
            'signrawtransactionwithwifkey' => [
                'usage' => 'signrawtransactionwithwifkey <rawtx_hex> <prevouts_json> <privkey_wif>',
                'required' => 3,
                'params' => ['rawtx_hex', 'prevouts_json', 'privkey_wif'],
            ],
            'signrawtransactionwithaddress' => [
                'usage' => 'signrawtransactionwithaddress <rawtx_hex> <prevouts_json> <address> [keyfile]',
                'required' => 3,
                'params' => ['rawtx_hex', 'prevouts_json', 'address', 'keyfile'],
            ],
        ];

        $command = $argv[1] ?? null;
        if ($command === null) {
            throw new \InvalidArgumentException('command is required');
        }
        if (!isset($commands[$command])) {
            throw new \InvalidArgumentException('unsupported command: ' . $command);
        }

        $decodeJsonArg = static function (string $json, string $name): array {
            $decoded = json_decode($json, true);
            if (!is_array($decoded) || json_last_error() !== JSON_ERROR_NONE) {
                $message = json_last_error() === JSON_ERROR_NONE ? 'JSON must decode to array' : json_last_error_msg();
                throw new \InvalidArgumentException($name . ' JSON不正: ' . $message);
            }

            return $decoded;
        };

        $parseBool01 = static function ($value, string $name): bool {
            if (is_bool($value)) {
                return $value;
            }
            if ($value === 1 || $value === '1') {
                return true;
            }
            if ($value === 0 || $value === '0') {
                return false;
            }

            throw new \InvalidArgumentException($name . ' must be 0 or 1');
        };

        $usage = $commands[$command]['usage'];
        $args = array_slice($argv, 2);
        $argMap = [];

        if (($args[0] ?? null) === '-json') {
            if (!isset($args[1])) {
                throw new \InvalidArgumentException('usage: ' . $usage);
            }
            $jsonArgs = json_decode($args[1], true);
            if (!is_array($jsonArgs) || json_last_error() !== JSON_ERROR_NONE) {
                $message = json_last_error() === JSON_ERROR_NONE ? 'JSON must decode to object/array' : json_last_error_msg();
                throw new \InvalidArgumentException('引数 JSON不正: ' . $message);
            }
            foreach ($commands[$command]['params'] as $paramName) {
                if (array_key_exists($paramName, $jsonArgs)) {
                    $argMap[$paramName] = $jsonArgs[$paramName];
                }
            }
            $requiredParams = array_slice($commands[$command]['params'], 0, $commands[$command]['required']);
            foreach ($requiredParams as $requiredParam) {
                if (!array_key_exists($requiredParam, $argMap)) {
                    throw new \InvalidArgumentException('usage: ' . $usage);
                }
            }
        } else {
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

            case 'signmessage':
                $result = \libmona\signmessage((string)$argMap['message'], (string)$argMap['privkey']);
                break;

            case 'verifymessage':
                $result = \libmona\verifymessage((string)$argMap['address'], (string)$argMap['message'], (string)$argMap['signature']);
                break;

            case 'createrawtransaction':
                $inputs = $decodeJsonArg((string)$argMap['inputs_json'], 'inputs_json');
                $outputs = $decodeJsonArg((string)$argMap['outputs_json'], 'outputs_json');
                $locktime = isset($argMap['locktime']) ? (int)$argMap['locktime'] : 0;
                $replaceable = array_key_exists('replaceable', $argMap) ? $parseBool01($argMap['replaceable'], 'replaceable') : false;
                $version = isset($argMap['version']) ? (int)$argMap['version'] : 2;
                $result = [
                    'hex' => \libmona\createrawtransaction($inputs, $outputs, $locktime, $replaceable, $version),
                ];
                break;

            case 'signrawtransactionwithrawkey':
                $prevouts = $decodeJsonArg((string)$argMap['prevouts_json'], 'prevouts_json');
                $result = \libmona\signrawtransactionwithrawkey((string)$argMap['rawtx_hex'], $prevouts, (string)$argMap['privkey_raw_hex']);
                break;

            case 'signrawtransactionwithwifkey':
                $prevouts = $decodeJsonArg((string)$argMap['prevouts_json'], 'prevouts_json');
                $result = \libmona\signrawtransactionwithwifkey((string)$argMap['rawtx_hex'], $prevouts, (string)$argMap['privkey_wif']);
                break;

            case 'signrawtransactionwithaddress':
                $prevouts = $decodeJsonArg((string)$argMap['prevouts_json'], 'prevouts_json');
                $keyfile = isset($argMap['keyfile']) ? (string)$argMap['keyfile'] : null;
                $result = \libmona\signrawtransactionwithaddress((string)$argMap['rawtx_hex'], $prevouts, (string)$argMap['address'], $keyfile);
                break;
        }

        echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . PHP_EOL;
    } catch (\Throwable $e) {
        echo json_encode([
            'error' => $e->getMessage(),
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . PHP_EOL;
        exit(1);
    }
}
