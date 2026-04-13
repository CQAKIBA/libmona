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

echo "\nランダムアドレスの生成\n";
$generated = \libmona\createnewaddress(true, 'テスト');
print_json('createnewaddress 結果:', $generated);

echo "\n既存のアドレスの登録\n";
$importkey = \libmona\importprivkey('T8Q5YNuVqzVkQSo8joGvjJciATWZw9AmDScoE3AWwWoF8p2ZYnKY', 'テスト');
print_json('importprivkey 結果:', $importkey);



echo "\nメッセージ電子署名の作成\n";
$message = 'ようこそモナコインの世界へ';
$signedMessage = \libmona\signmessage($message, $generated['privkey_wif']);
print_json('signmessage 結果:', $signedMessage);

echo "\nメッセージ電子署名の検証\n";
$verifiedMessage = \libmona\verifymessage($signedMessage['addr_M'], $message ,$signedMessage['sign']);
print_json('verifymessage 結果:', $verifiedMessage);



echo "\n送金トランザクションの作成\n";
$WIF_key = 'T8Q5YNuVqzVkQSo8joGvjJciATWZw9AmDScoE3AWwWoF8p2ZYnKY';
$Raw_key = '9f87376da2977f204f789ca059fb60149d3ae2cf3b9bef504c90cfaa79882225';
$address = 'mona1qxc7zz03f4eqql4jgwf9pzcsw3h537c5axqervu';

// 入力UTXO。listunspentで自分のアドレスの物を取得する。
$inputs = [
    [
        'txid' => '95a6a0fb469f83b2d135a5d43ab0642fc31217938a290e3e6e1832babff708f3',
        'vout' => '0',
        'address' => 'mona1qxc7zz03f4eqql4jgwf9pzcsw3h537c5axqervu',
        'amount' => '0.10000000',
    ],
];

// 入力の合計金額を計算
$input_amount = '0.00000000';
foreach ($inputs as $input) {
    $input_amount = mde('add', $input_amount, $input['amount']);
}

// 取引に必要な各金額を計算
$pay_amount = '0.01';
$transaction_fee = '0.00002536';	//kbyte単価。実運用では署名後のデータ長に合わせるアルゴリズムが必要です。
$change_amount = mde('sub', $input_amount, $pay_amount, $transaction_fee);	//釣銭
// マイニング手数料はestimatesmartfeeでネットワークから取得する。
// 計算を誤ると差額が全てマイナー手数料に行ってしまい取り戻すことは不可能です。

$outputs = [
    ['mona1qsja6dj05827d0htzavj0ygxw77qh0tc07yt2ka' => $pay_amount],
    ['mona1qxc7zz03f4eqql4jgwf9pzcsw3h537c5axqervu' => $change_amount],
];

$rawtx = \libmona\createrawtransaction($inputs, $outputs);
print_json('createrawtransaction 結果:', $rawtx);

echo "\n送金トランザクションをRAWキーで署名\n";
$signedRaw = \libmona\signrawtransactionwithrawkey($rawtx, $inputs, $Raw_key);
print_json('signrawtransactionwithrawkey 結果:', $signedRaw);

echo "\n送金トランザクションをWIFキーで署名\n";
$signedWif = \libmona\signrawtransactionwithwifkey($rawtx, $inputs, $WIF_key);
print_json('signrawtransactionwithwifkey 結果:', $signedWif);

echo "\n送金トランザクションを保存されているキーで署名\n";
$signedByAddress = \libmona\signrawtransactionwithaddress($rawtx, $inputs, $address, __DIR__ . '/privkeys.php');
print_json('signrawtransactionwithaddress 結果:', $signedByAddress);



echo "\nメッセージトランザクションの作成\n";
$transaction_fee = '0.00002536';	//kbyte単価。実運用では署名後のデータ長に合わせるアルゴリズムが必要です。
$change_amount = mde('sub', $input_amount, $transaction_fee);	//釣銭
$messageOutputs = [
    ['mona1qxc7zz03f4eqql4jgwf9pzcsw3h537c5axqervu' => $change_amount],
    ['data' => bin2hex('( ﾟ∀ﾟ)o彡ﾟようこそモナコインの世界へ！')],  //データ部分で80byte上限（オペコードは別）
];

$messageRawtx = \libmona\createrawtransaction($inputs, $messageOutputs);
print_json('メッセージ createrawtransaction 結果:', $messageRawtx);

echo "\nメッセージトランザクションをRAWキーで署名\n";
$messageSignedRaw = \libmona\signrawtransactionwithrawkey($messageRawtx, $inputs, $Raw_key);
print_json('メッセージ signrawtransactionwithrawkey 結果:', $messageSignedRaw);

echo "\nメッセージトランザクションをWIFキーで署名\n";
$messageSignedWif = \libmona\signrawtransactionwithwifkey($messageRawtx, $inputs, $WIF_key);
print_json('メッセージ signrawtransactionwithwifkey 結果:', $messageSignedWif);

echo "\nメッセージトランザクションを保存されているキーで署名\n";
$messageSignedByAddress = \libmona\signrawtransactionwithaddress($messageRawtx, $inputs, $address, __DIR__ . '/privkeys.php');
print_json('メッセージ signrawtransactionwithaddress 結果:', $messageSignedByAddress);





// 固定小数点演算補助関数 mona decimal
// オペコード, 数値1, 数値2, 数値3, ... 可変長引数を左から順番に計算
// 'add', 'sub', 'mul', 'div', 'mod'
//  引数は数値もしくは文字列。PHPでは浮動小数点にキャストされて演算誤差が発生するのを防ぐために文字列推奨。
function mde(string $op, ...$args): string
{
    $scale = 8;

    if (count($args) < 2) {
        throw new InvalidArgumentException('mde() requires at least 2 values.');
    }

    if (!in_array($op, ['add', 'sub', 'mul', 'div', 'mod'], true)) {
        throw new InvalidArgumentException('Operator must be one of: add, sub, mul, div, mod');
    }

    $base = gmp_pow(10, $scale);
    $values = [];

    foreach ($args as $arg) {
        if (is_int($arg)) {
            $arg = (string)$arg;
        } elseif (is_float($arg)) {
            $arg = sprintf('%.16F', $arg);
            $arg = rtrim(rtrim($arg, '0'), '.');
        } else {
            $arg = trim((string)$arg);
        }

        if (!preg_match('/^-?\d+(?:\.(\d+))?$/', $arg)) {
            throw new InvalidArgumentException('Invalid decimal: ' . $arg);
        }

        $negative = false;
        if ($arg[0] === '-') {
            $negative = true;
            $arg = substr($arg, 1);
        }

        [$int, $frac] = array_pad(explode('.', $arg, 2), 2, '');
        if (strlen($frac) > $scale) {
            throw new InvalidArgumentException('Too many decimal places: ' . $arg);
        }

        $frac = str_pad($frac, $scale, '0');
        $units = gmp_add(gmp_mul(gmp_init($int, 10), $base), gmp_init($frac, 10));

        if ($negative) {
            $units = gmp_neg($units);
        }

        $values[] = $units;
    }

    $result = array_shift($values);

    foreach ($values as $value) {
        switch ($op) {
            case 'add':
                $result = gmp_add($result, $value);
                break;

            case 'sub':
                $result = gmp_sub($result, $value);
                break;

            case 'mul':
                $result = gmp_div_q(gmp_mul($result, $value), $base);
                break;

            case 'div':
                if (gmp_cmp($value, 0) === 0) {
                    throw new InvalidArgumentException('Division by zero');
                }
                $result = gmp_div_q(gmp_mul($result, $base), $value);
                break;

            case 'mod':
                if (gmp_cmp($value, 0) === 0) {
                    throw new InvalidArgumentException('Modulo by zero');
                }
                $result = gmp_mod($result, $value);
                break;
        }
    }

    $negative = gmp_cmp($result, 0) < 0;
    if ($negative) {
        $result = gmp_abs($result);
    }

    $int  = gmp_strval(gmp_div_q($result, $base), 10);
    $frac = gmp_strval(gmp_mod($result, $base), 10);
    $frac = str_pad($frac, $scale, '0', STR_PAD_LEFT);

    return ($negative ? '-' : '') . $int . '.' . $frac;
}

