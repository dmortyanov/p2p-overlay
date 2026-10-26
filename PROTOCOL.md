# Спецификация протокола оверлейной сети (PROTOCOL.md)

Данный документ является ссылочным индексом и краткой выжимкой спецификации протокола. Полная спецификация с бинарными структурами и CBOR-схемами доступна в документе [`docs/protocol_spec.md`](file:///c:/school/4cource/seti/p2p-overlay/docs/protocol_spec.md).

---

## 1. Заголовок кадра (версия 1)

Все межузловые сообщения передаются через 24-байтный заголовок:

| Поле | Размер | Описание |
|---|---|---|
| `version` | 1 байт | Версия протокола (`0x01`) |
| `type` | 1 байт | Код типа сообщения (`PING`, `FIND_NODE`, `STORE`, `FIND_VALUE`, etc.) |
| `flags` | 2 байта | Флаги (`IS_RESPONSE`, `IS_ERROR`, `IS_ENCRYPTED`, etc.) |
| `request_id` | 16 байт | 128-битный UUID запроса для корреляции ответа |
| `payload_length` | 4 байта | Длина полезной нагрузки в big-endian порядке |
| `payload` | перем. | CBOR-сериализованная нагрузка кадра |

---

## 2. Схема и пример записи `NodeRecord` (E3-1)

### Структура полей

| Поле | Тип | Описание |
|---|---|---|
| `node_id` | `byte[32]` | Идентификатор владельца ($\text{SHA-256}(\text{identity\_public\_key})$) |
| `identity_public_key` | `byte[32]` | Открытый ключ Ed25519 владельца |
| `addresses` | `Array<Address>` | Список адресов узла (`host`: string, `port`: uint16) |
| `alias` | `string` | Необязательный человекочитаемый псевдоним (Stage 3, E3-8) |
| `sequence_number` | `uint64` | Монотонно возрастающий номер версии для защиты от отката (E3-6) |
| `issued_at` | `uint64` | Временная метка выпуска (Unix seconds) |
| `expires_at` | `uint64` | Временная метка истечения срока жизни TTL (Unix seconds) |
| `signature` | `byte[64]` | Цифровая подпись Ed25519 по каноническому представлению |

### Пример записи (CBOR Diagnostic Notation)

```cbor
{
  "node_id": h'80480f1156aa7f60983f56bb6f1919fec4399aa4d6360881dab846e26031c5ab',
  "identity_public_key": h'3d49b068df4e0d6045454379374f684463414f644e45774e6452304d44517332',
  "addresses": [
    {
      "host": "127.0.0.1",
      "port": 9001
    }
  ],
  "alias": "alice-node",
  "sequence_number": 1,
  "issued_at": 1791800000,
  "expires_at": 1791800180,
  "signature": h'4f2b1a8c9e...<64 bytes>...d8e7f1a2'
}
```

### Каноническое представление для подписи

Подпись формируется по байтам `canonical_bytes()`, сформированным в строгом порядке:
`node_id` (32) || `identity_public_key` (32) || `sequence_number` (be64) || `issued_at` (be64) || `expires_at` (be64) || `alias_len` (be16) || `alias` || `addr_count` (be16) || `[host_len (be16) || host || port (be16)]...`

---

## 3. RPC-сообщения распределённого хранилища (Stage 3)

- `STORE_REQUEST` (`0x12`): передаёт целевой DHT-ключ, подписанный `NodeRecord` и реквизиты отправителя.
- `STORE_RESPONSE` (`0x13`): возвращает статус сохранения (`success`) и сообщение об ошибке валидации при отклонении.
- `FIND_VALUE_REQUEST` (`0x14`): запрашивает запись по 32-байтному ключу.
- `FIND_VALUE_RESPONSE` (`0x15`): возвращает найденную запись (`has_value = true, record`), либо список ближайших контактов (`has_value = false, closest_nodes`).

Детальное описание процедур валидации, репликации ($R=3$, кворум $Q \ge 2$), сценария отказа хранителей (E3-5) и разрешения конфликтов приведено в [`docs/protocol_spec.md`](file:///c:/school/4cource/seti/p2p-overlay/docs/protocol_spec.md).

---

## 4. Протокол AKE и защита сессий (Stage 4)

### Сообщения рукопожатия AKE
- `HANDSHAKE_INIT` (`0x50`): версия, `node_id`, долговременный `identity_public_key` (Ed25519, 32B), эфемерный `ephemeral_public_key` (X25519, 32B), случайный `nonce` (32B).
- `HANDSHAKE_RESPONSE` (`0x51`, flag `IS_RESPONSE`): `session_id` (16B UUID), `node_id`, `identity_public_key` (32B), `ephemeral_public_key` (32B), случайный `nonce` (32B), цифровая подпись `signature` (Ed25519, 64B) по транскрипту $T_B$.
- `HANDSHAKE_COMPLETE` (`0x52`): `session_id` (16B), цифровая подпись `signature` (Ed25519, 64B) по транскрипту $T_A$.

### Формат транскриптов для подписи Ed25519
1. **Транскрипт ответчика $T_B$** (287 байт):
   `"P2P-AKE-V1-RESP"` (15B) || `init.node_id` (32B) || `init.id_pk` (32B) || `init.eph_pk` (32B) || `init.nonce` (32B) || `resp.session_id` (16B) || `resp.node_id` (32B) || `resp.id_pk` (32B) || `resp.eph_pk` (32B) || `resp.nonce` (32B)
2. **Транскрипт инициатора $T_A$** (302 байта):
   `"P2P-AKE-V1-COMP"` (15B) || $T_B$ (287B)

### Деривация сессионных ключей (HKDF-SHA256, RFC 5869)
- Общий секрет Диффи-Хеллмана: $S = \text{X25519}(sk_{\text{eph}}, pk_{\text{peer\_eph}})$ (32 байта)
- Соль: $Salt = nonce_A \parallel nonce_B$ (64 байта)
- Псевдослучайный ключ: $PRK = \text{HMAC-SHA256}(Salt, S)$
- Выходной материал ключей: $OKM = \text{HKDF-Expand}(PRK, \text{"p2p-ake-session-keys-v1"}, 64)$
  - Первые 32 байта: `key_a_to_b` (симметричный ключ от Инициатора к Ответчику)
  - Вторые 32 байта: `key_b_to_a` (симметричный ключ от Ответчика к Инициатору)

### Шифрование кадров ChaCha20-Poly1305 (AEAD)
- Флаг в заголовке: `FrameFlags::IS_ENCRYPTED = 0x0004`
- Аутентифицированные дополнительные данные (AAD): 24 байта оригинального заголовка кадра (`version`, `type`, `flags`, `request_id`, `payload_length`)
- Формирование 12-байтного nonce: `0x00000000` (4B) || `sequence_number` (be64, 8B)
- Формат полезной нагрузки зашифрованного кадра:
  `sequence_number` (be64, 8B) || `ciphertext` || `Poly1305_tag` (16B)
- Защита от повторов: скользящее окно `ReplayCache` (размер 256 кадров) с автоматическим сбросом дубликатов и устаревших пакетов.
