<?php

declare(strict_types=1);

require_once __DIR__ . '/libmona.php';

function print_json(string $title, $value): void
{
    echo "\n{$title}\n";

    if (is_string($value)) {
        echo $value . "\n";
        return;
    }

    echo json_encode($value, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n";
}

echo "ランダムアドレスの生成\n";
$generated = \libmona\createnewaddress(true, 'テスト');
print_json('createnewaddress 結果:', $generated);

echo "\nメッセージ電子署名の作成\n";
$message = 'ようこそモナコインの世界へ';
$signedMessage = \libmona\signmessage($message, $generated['privkey_wif']);
print_json('signmessage 結果:', $signedMessage);

echo "\nメッセージ電子署名の検証\n";
$verifiedMessage = \libmona\verifymessage($signedMessage['addr_M'], $signedMessage['sign'], $message);
print_json('verifymessage 結果:', $verifiedMessage);

echo "\n送金トランザクションの作成\n";
$txKeyPair = [
    'privkey_wif' => 'T52ayqQzJrzBDP5ok7KXe3cNFjf8qpvydDViKrVCpQncipHAyyyW',
    'privkey_raw' => '3af5a061be34179ec6608d4cd4eaaeb788cae8e1d862fa84288f56ff84beb8d4',
    'addr_M' => 'MHYwgLwFGNVwZ1PGD3Sg4YGGMYdPmLYaQy',
];

$inputs = [
    [
        'txid' => '95a6a0fb469f83b2d135a5d43ab0642fc31217938a290e3e6e1832babff708f3',
        'vout' => 0,
    ],
];

$outputs = [
    ['mona1qxc7zz03f4eqql4jgwf9pzcsw3h537c5axqervu' => '0.01000000'],
    ['mona1qsja6dj05827d0htzavj0ygxw77qh0tc07yt2ka' => '0.08997464'],
];

$rawtx = \libmona\createrawtransaction($inputs, $outputs);
print_json('createrawtransaction 結果:', $rawtx);

$prevouts = [
    [
        'txid' => '95a6a0fb469f83b2d135a5d43ab0642fc31217938a290e3e6e1832babff708f3',
        'vout' => 0,
        'address' => 'mona1qxc7zz03f4eqql4jgwf9pzcsw3h537c5axqervu',
        'amount' => '0.10000000',
    ],
];

echo "\n送金トランザクションをRAWキーで署名\n";
$signedRaw = \libmona\signrawtransactionwithrawkey($rawtx, $prevouts, $txKeyPair['privkey_raw']);
print_json('signrawtransactionwithrawkey 結果:', $signedRaw);

echo "\n送金トランザクションをWIFキーで署名\n";
$signedWif = \libmona\signrawtransactionwithwifkey($rawtx, $prevouts, $txKeyPair['privkey_wif']);
print_json('signrawtransactionwithwifkey 結果:', $signedWif);

echo "\n送金トランザクションを保存されているキーで署名\n";
$signedByAddress = \libmona\signrawtransactionwithaddress($rawtx, $prevouts, $txKeyPair['addr_M'], __DIR__ . '/privkeys.php');
print_json('signrawtransactionwithaddress 結果:', $signedByAddress);

echo "\nメッセージトランザクションの作成\n";
$opReturnMessage = '( ﾟ∀ﾟ)o彡ﾟようこそモナコインの世界へ！';
$messageOutputs = [
    [$txKeyPair['addr_M'] => '0.01000000'],
    ['mona1qsja6dj05827d0htzavj0ygxw77qh0tc07yt2ka' => '0.08997464'],
    ['data' => bin2hex($opReturnMessage)],
];

$messageRawtx = \libmona\createrawtransaction($inputs, $messageOutputs);
print_json('メッセージ createrawtransaction 結果:', $messageRawtx);

echo "\nメッセージトランザクションをRAWキーで署名\n";
$messageSignedRaw = \libmona\signrawtransactionwithrawkey($messageRawtx, $prevouts, $txKeyPair['privkey_raw']);
print_json('メッセージ signrawtransactionwithrawkey 結果:', $messageSignedRaw);

echo "\nメッセージトランザクションをWIFキーで署名\n";
$messageSignedWif = \libmona\signrawtransactionwithwifkey($messageRawtx, $prevouts, $txKeyPair['privkey_wif']);
print_json('メッセージ signrawtransactionwithwifkey 結果:', $messageSignedWif);

echo "\nメッセージトランザクションを保存されているキーで署名\n";
$messageSignedByAddress = \libmona\signrawtransactionwithaddress($messageRawtx, $prevouts, $txKeyPair['addr_M'], __DIR__ . '/privkeys.php');
print_json('メッセージ signrawtransactionwithaddress 結果:', $messageSignedByAddress);
