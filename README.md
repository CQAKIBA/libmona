# libmona

`libmona` は、Monacoin 向けのアドレス生成・メッセージ署名/検証・Raw Transaction 作成/署名を行うライブラリ兼 CLI ツールです。

Monacoin Core を常駐させない環境でも、オフラインで秘密鍵操作やトランザクション署名を実行できます。

---

## 前提

- CLI 実行環境が使えること
- 必要な拡張（例: `gmp`）が有効であること
- コマンドはリポジトリ直下で実行すること（`php libmona.php ...`）

---

## CLI の基本構文

### 1) 通常形式

```bash
php libmona.php <command> [params...]
```

### 2) JSON-RPC 風形式

```bash
php libmona.php -json '{"method":"<command>","params":[...]}'
```

- どちらも標準出力は JSON 形式です。
- エラー時は標準エラー出力に `{"error":...,"command":...}` 形式で出力されます。

---

## 実装済みコマンド一覧

> 以下は `libmona.php` に現在実装されている CLI コマンドです。

### 1. `createnewaddress`

新しい鍵ペアと Monacoin アドレスを生成します。

```bash
php libmona.php createnewaddress ( save label )
```

- `save`（任意）: `true/false` または `1/0`
  - `true` の場合、生成した情報を `privkeys.php` に追記保存
- `label`（任意）: 保存時のラベル文字列

**例**

```bash
php libmona.php createnewaddress true 'my_wallet_label'
```

**主な返却項目**

- `privkey_wif`
- `privkey_raw`
- `addr_mona1`（bech32）
- `addr_M`（P2PKH）
- `addr_P`（P2SH）

---

### 2. `signmessage`

メッセージに対して電子署名を生成します。

```bash
php libmona.php signmessage <message> <privkey>
```

- `message`: 署名対象の文字列
- `privkey`: WIF 形式秘密鍵（Electrum-mona 形式を含む）

**例**

```bash
php libmona.php signmessage 'hello mona' 'L1aW4aubDFB7yfras2S1mN3bqg9w7j1Huxu6mA5fN2v9oQqv4nY2'
```

**主な返却項目**

- `message`
- `sign`（base64 署名）
- 対応アドレス（`addr_mona1`, `addr_M`, `addr_P`）

---

### 3. `verifymessage`

署名の妥当性を検証します。

```bash
php libmona.php verifymessage <address> <signature> <message>
```

- `address`: 署名者アドレス
- `signature`: `signmessage` の `sign`（base64）
- `message`: 元メッセージ

**例**

```bash
php libmona.php verifymessage 'PM9m3P4QvYpV4Yh6Yf8a8C7oD8uQn2fBvQ' 'H8zQ7z6...base64sig...' 'hello mona'
```

**主な返却項目**

- `valid`（`true/false`）
- `error`（失敗時）
- 復元公開鍵情報、推定アドレスタイプなど

---

### 4. `createrawtransaction`

未署名 Raw Transaction を作成します。

```bash
php libmona.php createrawtransaction '[{"txid":"hex","vout":n,"sequence":n},...]' '[{"address":amount},{"data":"hex"},...]' ( locktime replaceable version )
```

- `inputs_json`（必須）: 入力UTXO配列
- `outputs_json`（必須）: 出力配列（アドレス送金 / OP_RETURN `data`）
- `locktime`（任意, 既定: `0`）
- `replaceable`（任意, 既定: `false`）
- `version`（任意, 既定: `2`）

**例**

```bash
php libmona.php createrawtransaction '[{"txid":"95a6a0fb469f83b2d135a5d43ab0642fc31217938a290e3e6e1832babff708f3","vout":0}]' '[{"mona1qxc7zz03f4eqql4jgwf9pzcsw3h537c5axqervu":"0.01000000"},{"mona1qsja6dj05827d0htzavj0ygxw77qh0tc07yt2ka":"0.08997464"}]'
```

**主な返却項目**

- `hex`（作成された Raw Transaction）

---

### 5. `signrawtransactionwithkey`

秘密鍵配列を受け取り、Raw Transaction に署名します。

```bash
php libmona.php signrawtransactionwithkey "<rawtx_hex>" '["<privatekey>",...]' ( '[{"txid":"hex","vout":n,"scriptPubKey":"hex","redeemScript":"hex","witnessScript":"hex","amount":amount},...]' "sighashtype" )
```

- `rawtx_hex`（必須）: 未署名RawTx
- `privkeys_json`（必須）: 秘密鍵配列（先頭鍵を使用）
  - 64桁hexなら raw key として扱う
  - それ以外は WIF として扱う
- `prevtxs_json`（任意）: 署名対象入力の参照情報
- `sighashtype`（任意）: 現在 `ALL` のみ対応

**例**

```bash
php libmona.php signrawtransactionwithkey '0200...0000' '["T8Q5..."]' '[{"txid":"95a6...","vout":0,"address":"mona1q...","amount":"0.10000000"}]' 'ALL'
```

---

### 6. `signrawtransactionwithrawkey`

32byte 生秘密鍵（hex）で Raw Transaction に署名します。

```bash
php libmona.php signrawtransactionwithrawkey <rawtx_hex> <prevouts_json> <privkey_raw_hex>
```

**例**

```bash
php libmona.php signrawtransactionwithrawkey '0200...0000' '[{"txid":"95a6a0fb469f83b2d135a5d43ab0642fc31217938a290e3e6e1832babff708f3","vout":0,"address":"mona1qxc7zz03f4eqql4jgwf9pzcsw3h537c5axqervu","amount":"0.10000000"}]' 'your_32byte_hex_privkey'
```

---

### 7. `signrawtransactionwithwifkey`

WIF 形式秘密鍵で Raw Transaction に署名します。

```bash
php libmona.php signrawtransactionwithwifkey <rawtx_hex> <prevouts_json> <privkey_wif>
```

**例**

```bash
php libmona.php signrawtransactionwithwifkey '0200000001f308f7bfba32186e3e0e298a931712c32f64b03ad4a535d1b2839f46fba0a6950000000000ffffffff0240420f0000000000160014363c213e29ae400fd648724a11620e8de91f629d584a89000000000016001484bba6c9f43abcd7dd62eb24f220cef78177af0f00000000' '[{"txid":"95a6a0fb469f83b2d135a5d43ab0642fc31217938a290e3e6e1832babff708f3","vout":0,"address":"mona1qxc7zz03f4eqql4jgwf9pzcsw3h537c5axqervu","amount":"0.10000000"}]' 'T8Q5YNuVqzVkQSo8joGvjJciATWZw9AmDScoE3AWwWoF8p2ZYnKY'
```

---

### 8. `signrawtransactionwithaddress`

保存済みアドレス情報を使って Raw Transaction に署名します。

```bash
php libmona.php signrawtransactionwithaddress <rawtx_hex> <prevouts_json> <address> [keyfile]
```

- `address`（必須）: 署名に使うアドレス
- `keyfile`（任意）: キーファイルパス（省略時は既定ファイルを参照）

**例**

```bash
php libmona.php signrawtransactionwithaddress '0200...0000' '[{"txid":"95a6a0fb469f83b2d135a5d43ab0642fc31217938a290e3e6e1832babff708f3","vout":0,"address":"mona1qxc7zz03f4eqql4jgwf9pzcsw3h537c5axqervu","amount":"0.10000000"}]' 'mona1q...' '/path/to/address.json'
```

---

## JSON 形式で実行する例

```bash
php libmona.php -json '{"method":"createnewaddress","params":[true,"cli_generated"]}'
```

```bash
php libmona.php -json '{"method":"signmessage","params":["hello mona","T8Q5..."]}'
```

```bash
php libmona.php -json '{"method":"createrawtransaction","params":[[{"txid":"95a6...","vout":0}],[{"mona1q...":"0.01"}],0,false,2]}'
```

---

## 補足

- この CLI の実装エントリは `libmona.php` です。
- ライブラリとして使う場合は、`example.php` / `example_createraw.php` / `example_signraw.php` も参照してください。

---

## 免責事項

このプログラムを使用したことによる取引の失敗、コインの紛失、その他いかなる損害についても、作者は一切の責任を負いません。
