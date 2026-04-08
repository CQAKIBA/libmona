<?php

require_once __DIR__ . '/libmona.php';

$message = trim($argv[1] ?? '');
$privkey = 'p2wpkh:T9QtawEWtVZP2uUmmqxuuvLzjWaN6rpDYvdEkSLs1yzBmRtGt27x';

$signature = \libmona\signmessage($message, $privkey);
printf("\n署名:\n%s\n", json_encode($signature, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
printf("\nJSON送信形式:\n%s\n", json_encode([$signature['message'], $signature['addr_M'], $signature['sign']]));

$verify = \libmona\verifymessage($signature['addr_M'], $message, $signature['sign']);
printf("\n検証:\n%s\n", json_encode($verify, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));

$verify2 = \libmona\verifymessage(
    'mona1qczzz0sjsx8n98tstmy6jr0r8dvxl0g8s87ggk8',
    '本日は荒天なり',
    'IELZ4JknRGm4rEgtxXgYWLVC26nlVXOqdtHoOUSz9RJQSUgOkt+y3He4gwZoex3EgP1ZXGEUP4WQqcog9kbMBWY='
);
printf("\n外部検証:\n%s\n", json_encode($verify2, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));

printf("\n新規アドレス作成:\n%s\n", json_encode(\libmona\createnewaddress(true,"テスト"), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
