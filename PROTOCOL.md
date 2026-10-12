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
