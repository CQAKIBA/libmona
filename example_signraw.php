<?php
require_once __DIR__ . '/libmona.php';

$rawtx = '0200000001f308f7bfba32186e3e0e298a931712c32f64b03ad4a535d1b2839f46fba0a6950000000000ffffffff0240420f0000000000160014363c213e29ae400fd648724a11620e8de91f629d584a89000000000016001484bba6c9f43abcd7dd62eb24f220cef78177af0f00000000';
$prevouts = [
    [
        'txid' => '95a6a0fb469f83b2d135a5d43ab0642fc31217938a290e3e6e1832babff708f3',
        'vout' => 0,
        'address' => 'mona1qxc7zz03f4eqql4jgwf9pzcsw3h537c5axqervu',
        'amount' => '0.10000000',
        // 'scriptPubKey' => '0014....', // address があれば省略可
    ],
];

// raw key
// $signed = \libmona\signrawtransactionwithrawkey($rawtx, $prevouts, 'your_32byte_hex_privkey');

// wif key
$signed = \libmona\signrawtransactionwithwifkey($rawtx, $prevouts, 'T8Q5YNuVqzVkQSo8joGvjJciATWZw9AmDScoE3AWwWoF8p2ZYnKY');

// saved address
// $signed = \libmona\signrawtransactionwithaddress($rawtx, $prevouts, 'mona1...');

print_r($signed);


//0200000000010195ca2f1ac6990d31d65bd830496d7a90e25c6481cd6f4354b902a62500e4428c0000000000ffffffff0100e1f5050000000016001484bba6c9f43abcd7dd62eb24f220cef78177af0f0247304402206d544cdc940da82cb3037cb77962b2af355ccc67b0552c9dab226a072cd51b3202201fe9275ea90dcf55c154f68a0d72d1f2b150d562945f28d82536143c2ab62d55012102ba7e89505faceefab49a490aa015e892c91e720224c299fc4288429fc9650ae800000000
//0200000000010195ca2f1ac6990d31d65bd830496d7a90e25c6481cd6f4354b902a62500e4428c0000000000ffffffff0100e1f5050000000016001484bba6c9f43abcd7dd62eb24f220cef78177af0f0248304502210097be8c111774d6d540340e76232b40fefe67d59d9b8e60f9763f20eeafae6a8e02203f324ff02367b6afd5706c1f5fbfa6351bf2bcbcc4f033bc9e958ae06f7ba099012102ba7e89505faceefab49a490aa015e892c91e720224c299fc4288429fc9650ae800000000



