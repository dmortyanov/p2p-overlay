# Защищённая оверлейная P2P-сеть

Курсовая работа — «Защищённая оверлейная сеть передачи данных на основе пиринговых протоколов».

## Обзор

Децентрализованная P2P оверлейная сеть на C++20 с:
- **Kademlia DHT** — распределённая хеш-таблица для обнаружения узлов
- **Собственный AKE** — аутентифицированная установка сессии (Ed25519 + X25519)
- **Многопереходные туннели** — передача данных через цепочку ретрансляторов
- **End-to-End шифрование** — ChaCha20-Poly1305 / AES-256-GCM
- **Передача файлов** — блочная передача с контролем целостности

## Документация проекта

- [Архитектурная спецификация](docs/architecture.md) — детальное описание 7 подсистем, алгоритмов поиска, 4 графов сети, AKE, луковичной маршрутизации и фасада API
- [Спецификация протокола](docs/protocol_spec.md) — формат кадра, бинарные заголовки, типы сообщений и схемы CBOR
- [Сравнение форматов сериализации](docs/serialization_comparison.md) — обоснование выбора CBOR (RFC 8949) против MessagePack и JSON

## Требования

- Docker и Docker Compose
- Или: CMake ≥ 3.20, C++20 компилятор, vcpkg

## Быстрый старт (Docker)

```bash
# Собрать и запустить 2 узла для базового теста
docker compose up --build

# Запуск с N=21 узлом (после реализации этапа 6+)
# docker compose -f docker-compose.star.yml up --build
```

## Сборка из исходников

```bash
# Установить vcpkg (если не установлен)
git clone https://github.com/microsoft/vcpkg.git
./vcpkg/bootstrap-vcpkg.sh

# Сборка
cmake -B build \
  -DCMAKE_TOOLCHAIN_FILE=./vcpkg/scripts/buildsystems/vcpkg.cmake \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build

# Запуск тестов
cd build && ctest --output-on-failure

# Запуск узла
./build/p2p_node --port 9000 --log-level debug

# Запуск второго узла с подключением к первому
./build/p2p_node --port 9001 --bootstrap "127.0.0.1:9000" \
                 --data-dir ./node_state_2 --log-level debug
```

## Структура проекта

```
src/
├── common/types.hpp          # NodeID, RequestID, PeerAddress
├── transport/                # TCP, кадрирование, сериализация
├── identity/                 # Ed25519 ключи, NodeID, AKE
├── dht/                      # k-bucket, routing table, lookup
├── tunnel/                   # Туннели, пул, профилирование
├── app/                      # Сообщения, файлы, CLI
├── metrics/                  # Метрики, экспорт CSV/JSON
├── config/                   # TOML конфигурация
├── node.hpp/cpp              # Главный класс узла
└── main.cpp                  # Точка входа

tests/
├── unit/                     # Модульные тесты
├── integration/              # Интеграционные тесты
└── negative/                 # Отрицательные тесты безопасности

config/default.toml           # Все настраиваемые параметры
orchestrator/                 # Python-оркестратор экспериментов
```

## Конфигурация

Все параметры вынесены в `config/default.toml` — изменение не требует правки исходного кода. Ключевые параметры:

| Параметр | Значение | Описание |
|---|---|---|
| `dht.k_bucket_size` | 4 | Ёмкость k-bucket |
| `dht.alpha` | 3 | Параллельные запросы lookup |
| `dht.replication` | 3 | Фактор репликации |
| `tunnel.min_relay_hops` | 3 | Мин. ретрансляторов |
| `tunnel.pool_size` | 3 | Пул туннелей |

## Текущий статус

- [x] **Этап 1**: Transport + Frame + Identity
- [x] **Этап 2**: Kademlia DHT (K-Bucket LRU, RoutingTable 256 buckets, iterative lookup, FIND_NODE RPC)
- [ ] Этап 3: STORE, FIND_VALUE, записи
- [ ] Этап 4: AKE-протокол
- [ ] Этап 5: Туннели
- [ ] Этап 6: Масштабирование N=21
- [ ] Этап 7: Продвинутые функции
- [ ] Этап 8: Анализ
- [ ] Этап 9: Документация
- [ ] Этап 10: Защита

## Лицензия

Курсовая работа, 4 курс, Сети.
