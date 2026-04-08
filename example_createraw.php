<?php
require_once __DIR__ . '/libmona.php';

use function libmona\createrawtransaction;

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

$rawtx = createrawtransaction($inputs, $outputs);

echo "Raw TX hex:
";
echo $rawtx . "

";
