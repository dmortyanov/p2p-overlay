# Архитектура защищённой P2P оверлейной сети

**Версия документа**: 1.0.0  
**Статус**: Утверждённая архитектурная спецификация  
**Проект**: Защищённая децентрализованная оверлейная сеть на базе P2P-протоколов (Курсовая работа, 4 курс)  
**Уровень реализации**: Продвинутый ($N = 20\text{--}21$ узлов, $k = 4$, $\alpha = 3$, собственный AKE, $\ge 3$ ретранслятора, передача файлов, профилирование ретрансляторов)

---

## 1. Назначение системы и архитектурные процессы поиска

### 1.1. Что ищет архитектура оверлейной сети?

В децентрализованной P2P-сети отсутствует центральный сервер каталогов или реестр соответствия имён. Для организации защищённого взаимодействия между узлами архитектура решает **четыре фундаментальные задачи поиска и маршрутизации**:

```mermaid
flowchart TD
    subgraph SEARCH_OBJECTS ["Что ищет архитектура оверлея?"]
        S1["1. Поиск узлов (Node Discovery)\nFIND_NODE(Target NodeID) -> k ближайших узлов"]
        S2["2. Поиск динамических записей и псевдонимов\nFIND_VALUE(Key) -> NodeRecord / AliasRecord"]
        S3["3. Поиск блоков файлов и контента\nFIND_VALUE(ChunkHash) -> ContentRecord"]
        S4["4. Поиск маршрутов для туннелей\nRelay Profiling & Selection -> Multi-Hop Circuit"]
    end

    S1 -->|Предоставляет топологические контакты| S4
    S1 -->|Обеспечивает сходимость DHT| S2
    S2 -->|Разрешает имя/ID в IP:Port и PubKey| S4
    S3 -->|Определяет держателей шардов данных| S4
```

1. **Поиск узлов по идентификатору (`Node Discovery` через `FIND_NODE`)**:
   - **Цель**: По заданному 256-битному `Target NodeID` найти $k$ топологически ближайших (в метрике XOR: $d(x,y) = x \oplus y$) активных узлов сети вместе с их сетевыми адресами (`IP:port`) и открытыми ключами Ed25519.
   - **Алгоритмическая сложность**: Итеративный параллельный поиск с параметром $\alpha = 3$ сходится за $O(\log N)$ шагов без полного знания топологии сети.
   - **Роль**: Формирует и актуализирует локальную таблицу маршрутизации ($256$ $k$-bucket'ов), позволяя узлу обнаруживать любых участников сети.

2. **Поиск криптографических записей адресации и псевдонимов (`FIND_VALUE` / `NodeRecord`)**:
   - **Цель**: По хэш-ключу записи найти и валидировать актуальный сетевой профиль узла или псевдонима:
     - Ключ узла: $Key = \text{SHA-256}(\text{"node:"} \parallel NodeID)$
     - Ключ псевдонима (alias): $Key = \text{SHA-256}(\text{"alias:"} \parallel \text{normalize}(alias))$
   - **Верификация**: Каждая запись подписана долговременным ключом Ed25519 владельца, имеет временную метку `issued_at`, срок действия `expires_at` (TTL) и монотонно возрастающий `sequence_number` (защита от replay и отката версий).
   - **Репликация**: Записи дублируются на $R = 3$ ближайших к ключу узлах.

3. **Поиск контента и блоков распределённых файлов (`FIND_VALUE` / `ContentRecord`)**:
   - **Цель**: Поиск узлов-хранителей блоков файлов по их криптографическому хэшу $\text{SHA-256}(ChunkBytes)$.
   - **Роль**: Обеспечивает децентрализованную передачу файлов между узлами, позволяя получателю запрашивать блоки у независимых участников оверлея.

4. **Поиск и оптимизация туннельных маршрутов (Relay Path Discovery)**:
   - **Цель**: Поиск последовательности из не менее чем $\ge 3$ независимых узлов-ретрансляторов для построения защищённого многозвенного туннеля (onion circuit).
   - **Критерии поиска ретрансляторов**:
     - Исключение повторов и циклов;
     - Разнообразие подсетей (IP/subnet diversity) для предотвращения компрометации туннеля одним провайдером/хостом;
     - Профилирование узлов: фильтрация по скользящему среднему (EMA) доступности и задержки (RTT);
     - Ротация ретрансляторов при отказах.

---

## 2. Разграничение четырёх графов сети

В соответствии с требованиями ТЗ (§4), в архитектуре строго разделены и не подменяют друг друга 4 независимых графа:

```mermaid
graph TD
    subgraph G1 ["1. Underlay-граф (L3 / IP)"]
        U1["Host 1: 172.20.0.2"] --- U2["Host 2: 172.20.0.3"]
        U2 --- U3["Host 3: 172.20.0.4"]
        U1 --- U4["Host N: 172.20.0.22"]
    end

    subgraph G2 ["2. Bootstrap-граф (Инициализация)"]
        BS["Seed Node\n(172.20.0.2:9000)"]
        N2["Node 2"] -->|join| BS
        N3["Node 3"] -->|join| BS
        N4["Node 4"] -->|join| BS
    end

    subgraph G3 ["3. DHT-Overlay граф (XOR-метрика)"]
        D1["Node 0010..."] <-->|k-bucket| D2["Node 0011..."]
        D1 <-->|k-bucket| D3["Node 1001..."]
        D2 <-->|k-bucket| D4["Node 0110..."]
    end

    subgraph G4 ["4. Туннельный маршрут (Onion Circuit)"]
        SRC["Initiator\n(Alice)"] -->|Encrypted Hop 1| R1["Relay 1"]
        R1 -->|Encrypted Hop 2| R2["Relay 2"]
        R2 -->|Encrypted Hop 3| R3["Relay 3"]
        R3 -->|Decrypted Payload| DST["Destination\n(Bob)"]
    end
```

| Характеристика | 1. Underlay-сеть | 2. Bootstrap-граф | 3. DHT-Overlay | 4. Туннельный маршрут |
|---|---|---|---|---|
| **Уровень** | Сетевой L3 (IP/TCP) | Процедурный (Join) | Логический оверлей (DHT) | Прикладной сквозной (Circuit) |
| **Узлы (вершины)** | IP-адреса и порты процессов | Адреса известных seed-узлов | $NodeID \in \{0,1\}^{256}$ | Инициатор, ретрансляторы, адресат |
| **Рёбра (связи)** | Физическая IP-достижимость | Первичные TCP-соединения | Контакты в $k$-bucket'ах | Согласованные сессии туннеля |
| **Метрика расстояния** | Сетевая задержка (RTT) | Статический список конфига | Метрика XOR: $d(x,y) = x \oplus y$ | Количество хопов ($\ge 3$ релея) |
| **Жизненный цикл** | Постоянный (инфраструктура) | Кратковременный (при старте) | Динамический (LRU, ping, refresh) | Временный (TTL туннеля, pool) |

> [!IMPORTANT]
> **Принципиальное различие**: Путь DHT-поиска (`FIND_NODE` / `FIND_VALUE`) **не является туннелем**. Туннель — это заранее построенный и подтверждённый криптографический виртуальный канал с луковичным шифрованием (Onion Routing) через выделенные узлы-ретрансляторы.

---

## 3. Общая компонентная архитектура узла

Каждый узел сети представляет собой автономную систему, состоящую из 7 логически изолированных подсистем (ТЗ §7), взаимодействующих через строгий фасад (`NodeFacade`):

```mermaid
flowchart TB
    UI["7. Подсистема интерфейса (CLI / Management / Web Visualizer)"]
    APP["5. Подсистема прикладных сервисов\n(End-to-End Messaging, Chunked File Transfer)"]
    METRICS["6. Подсистема метрик и телеметрии\n(Telemetry, Routing Profiler, JSON/CSV Export)"]
    
    subgraph NODE_FACADE ["Node Facade API"]
        F1["join(bootstrap_peers)"]
        F2["lookup_node(target_id)"]
        F3["put_record(key, record, ttl)"]
        F4["get_record(key)"]
        F5["build_tunnel(dest_id, policy)"]
        F6["send_via_tunnel(tunnel_id, data)"]
        F7["close_tunnel(tunnel_id)"]
        F8["get_network_state()"]
    end

    subgraph TUNNEL_SUB ["4. Подсистема управления туннелями"]
        TM["TunnelManager"]
        POOL["TunnelPool (>=3 активных)"]
        ROUTER["OnionForwarder (Hop-by-hop)"]
        PROFILER["RelayProfiler (EMA RTT / Loss)"]
    end

    subgraph DHT_SUB ["3. Подсистема оверлейной маршрутизации и DHT"]
        RT["RoutingTable (256 k-buckets, K=4, LRU)"]
        LOOKUP["LookupEngine (Iterative, Alpha=3)"]
        STORAGE["RecordStore (Replication R=3, TTL, SeqNo)"]
        REFRESH["RefreshController (Periodic, Anti-stale)"]
    end

    subgraph SECURITY_SUB ["2. Подсистема идентификации и безопасности"]
        ID["NodeIdentity (Ed25519 Keypair, NodeID=SHA256(Pub))"]
        AKE["AKE Handshake (X25519 + HKDF-SHA256)"]
        CIPHER["AEAD Engine (ChaCha20-Poly1305)"]
        REPLAY["ReplayCache (Sliding Window, Nonce/Seq)"]
    end

    subgraph TRANSPORT_SUB ["1. Подсистема сетевого транспорта"]
        TCP_L["TcpListener (Async Accept)"]
        TCP_C["TcpConnectionPool (Outbound/Inbound Async TCP)"]
        FRAMER["FrameParser & Serializer (24-byte Header + CBOR)"]
    end

    UI --> NODE_FACADE
    APP --> NODE_FACADE
    NODE_FACADE --> TUNNEL_SUB
    NODE_FACADE --> DHT_SUB
    TUNNEL_SUB --> DHT_SUB
    TUNNEL_SUB --> SECURITY_SUB
    DHT_SUB --> SECURITY_SUB
    DHT_SUB --> TRANSPORT_SUB
    TUNNEL_SUB --> TRANSPORT_SUB
    SECURITY_SUB --> TRANSPORT_SUB
    METRICS -.->|Сбор телеметрии| DHT_SUB
    METRICS -.->|Сбор телеметрии| TUNNEL_SUB
    METRICS -.->|Сбор телеметрии| TRANSPORT_SUB
```

---

## 4. Описание подсистем

### 4.1. Подсистема сетевого транспорта (Transport Subsystem)
- **Назначение**: Обеспечение надёжного асинхронного обмена кадрами по протоколу TCP без блокировок (на базе `boost::asio` / `asio standalone`).
- **Кадрирование**:
  - Бинарный заголовок фиксированного размера (24 байта): `version` (1B), `type` (1B), `flags` (2B), `request_id` (16B UUID/uint128), `payload_length` (4B).
  - Потоковый парсер `FrameParser` со скользящим буфером: корректная обработка фрагментации TCP, склейки кадров, частичных заголовков.
  - Жёсткий лимит `MAX_FRAME_PAYLOAD = 65 536` байт с предварительной валидацией до выделения памяти.
- **Сериализация**: Компактный двоичный формат CBOR (RFC 8949) через `nlohmann::json::to_cbor` / `from_cbor`.

### 4.2. Подсистема идентификации и безопасности (Identity & Security)
- **Долговременная идентичность**:
  - Пара ключей Ed25519 (генерация, безопасное хранение в файле состояния узла).
  - Детерминированный идентификатор узла:
    $$\text{NodeID} = \text{SHA-256}(\text{identity\_public\_key})$$
  - Запрет случайной смены `NodeID`; приём любого контакта сопровождается проверкой соответствия $\text{SHA-256}(pubkey) \stackrel{?}{=} NodeID$.
- **Учебный криптографический протокол AKE (Authenticated Key Exchange)**:
  - Эфемерный обмен Диффи-Хеллмана на кривой Curve25519 (X25519);
  - Взаимная аутентификация: подпись транскрипта рукопожатия ключами Ed25519;
  - Деривация сессионных ключей: HKDF-SHA-256 с раздельными ключами для направлений `A->B` и `B->A`;
  - Симметричное шифрование кадров: ChaCha20-Poly1305 (AEAD) с контролем монотонности счетчиков (защита от replay в сессии и между сессиями).

### 4.3. Подсистема оверлейной маршрутизации и DHT (DHT & Discovery)
- **Таблица маршрутизации (`RoutingTable`)**:
  - 256 списков $k$-bucket'ов для каждого бита XOR-расстояния;
  - Параметр $k = 4$ (для продвинутого уровня $N = 20\text{--}21$);
  - LRU-вытеснение: при заполнении бакета старейший контакт проверяется пингом (`PING`), заменяется только при отсутствии ответа.
- **Итеративный поиск (`LookupEngine`)**:
  - Параметр параллелизма $\alpha = 3$;
  - Параллельная отправка RPC `FIND_NODE` к 3 ближайшим известным узлам;
  - Динамическое обновление списка ближайших кандидатов, исключение дубликатов;
  - Остановка при отсутствии прогресса (новые контакты дальше текущих ближайших $k$).
- **Хранилище записей (`RecordStore`)**:
  - Подписанные записи `NodeRecord` и `ContentRecord`;
  - Репликация на $R = 3$ ближайших узла; подтверждение записи при успехе на $\ge 2$ узлах;
  - Контроль времени жизни (TTL = 120–300 с) и фоновое переопубликование каждые $\text{TTL}/2$.

### 4.4. Подсистема управления туннелями (Tunnel Management)
- **Архитектура луковичного канала**:
  - Построение цепочки через $\ge 3$ промежуточных узла: $\text{Src} \to R_1 \to R_2 \to R_3 \to \text{Dst}$.
  - Инициатор генерирует независимые сессионные симметричные ключи $K_1, K_2, K_3$ для каждого релея.
  - Пакет данных оборачивается слоями шифрования:
    $$\text{Layer}_1 = E_{K_1}(R_2 \parallel E_{K_2}(R_3 \parallel E_{K_3}(\text{Dst} \parallel \text{Payload})))$$
  - Каждый релей снимает свой слой и узнает адрес только следующего звена (forward secrecy hop-by-hop).
- **Пул туннелей (`TunnelPool`)**:
  - Поддержание не менее 3 активных/подготовленных туннелей;
  - Быстрое переключение при деградации или разрыве активного канала.
- **Профилирование ретрансляторов (`RelayProfiler`)**:
  - Расчёт экспоненциального скользящего среднего (EMA):
    $$\text{EMA}_{\text{RTT}} = (1 - \beta) \cdot \text{EMA}_{\text{prev}} + \beta \cdot \text{RTT}_{\text{sample}}$$
    $$\text{EMA}_{\text{success}} = (1 - \beta) \cdot \text{EMA}_{\text{prev}} + \beta \cdot (1 \text{ при успехе, } 0 \text{ при ошибке})$$
  - Исключение узлов из одной /24 подсети для обеспечения IP/subnet diversity.

### 4.5. Подсистема прикладных сервисов (Application Services)
- **Защищённый обмен сообщениями (End-to-End Encrypted Messaging)**:
  - Сквозное шифрование полезной нагрузки между отправителем и получателем (даже конечный ретранслятор $R_3$ не видит открытый текст);
  - Гарантированная доставка с квитированием `APP_ACK`.
- **Блочная передача файлов (Chunked File Transfer)**:
  - Разбиение файлов на блоки фиксированного размера 48–60 КиБ (гарантированное укладывание в `MAX_FRAME_PAYLOAD = 65 536` байт с учетом заголовков и AEAD-тегов);
  - Контроль целостности блоков и файла по хэшу SHA-256;
  - Скользящее окно передачи и восстановление пропущенных блоков.

### 4.6. Подсистема метрик и телеметрии (Metrics & Experimentation)
- Логирование каждого поискового запроса: `lookup_id`, число итераций, число отправленных RPC, задержка поиска, процент успешности.
- Мониторинг наполняемости $k$-bucket'ов для подтверждения невырожденности DHT.
- Экспорт телеметрии в машиночитаемые форматы JSON и CSV для построения графиков в отчете.

### 4.7. Подсистема интерфейса управления (User Interface & Node Facade)
- CLI-интерфейс для интерактивного управления узлом:
  - `lookup <node_id | alias>`
  - `send <dest_id> <message>`
  - `send-file <dest_id> <file_path>`
  - `show-dht`
  - `show-tunnels`
- Фасадный программный API для изоляции прикладного слоя от внутренней структуры таблиц маршрутизации.

---

## 5. Детальные диаграммы взаимодействия

### 5.1. Итеративный алгоритм DHT Lookup ($\alpha = 3$, $k = 4$)

Диаграмма иллюстрирует процесс поиска узла $TargetID$ в Kademlia DHT:

```mermaid
sequenceDiagram
    autonumber
    actor User as Прикладной уровень
    participant Engine as LookupEngine
    participant RT as RoutingTable
    participant N1 as Node 1 (ближайший 1)
    participant N2 as Node 2 (ближайший 2)
    participant N3 as Node 3 (ближайший 3)
    participant Target as Целевой узел

    User->>Engine: lookup_node(TargetID)
    Engine->>RT: find_closest(TargetID, count=4)
    RT-->>Engine: [Node 1, Node 2, Node 3]
    
    rect rgb(240, 248, 255)
        note over Engine, N3: Итерация 1: Параллельный опрос alpha=3 кандидатов
        par Запрос к Node 1
            Engine->>N1: FIND_NODE_REQUEST(TargetID)
            N1-->>Engine: FIND_NODE_RESPONSE([Node A, Node B, Node C, Node D])
        and Запрос к Node 2
            Engine->>N2: FIND_NODE_REQUEST(TargetID)
            N2-->>Engine: FIND_NODE_RESPONSE([Node B, Node E, Node F])
        and Запрос к Node 3
            Engine->>N3: FIND_NODE_REQUEST(TargetID)
            N3-->>Engine: FIND_NODE_RESPONSE(Timeout / Failure)
        end
    end

    Engine->>Engine: Объединение результатов, сортировка по XOR-расстоянию d(x, TargetID)
    Engine->>Engine: Обнаружен Node A, находящийся ближе всех к TargetID

    rect rgb(255, 250, 240)
        note over Engine, Target: Итерация 2: Опрос следующих ближайших неотвеченных узлов
        Engine->>N1: FIND_NODE_REQUEST(TargetID)
        N1-->>Engine: FIND_NODE_RESPONSE([Target, Node G])
    end

    rect rgb(240, 255, 240)
        note over Engine, Target: Итерация 3: Прямой запрос к целевому узлу
        Engine->>Target: FIND_NODE_REQUEST(TargetID)
        Target-->>Engine: FIND_NODE_RESPONSE(Self PeerInfo + k соседей)
    end

    Engine->>RT: Добавление валидированных узлов в k-bucket'ы
    Engine-->>User: Результат: Target PeerInfo (IP, Port, PubKey)
```

---

### 5.2. Учебный криптографический протокол AKE (Handshake)

Диаграмма установления защищённой сессии между двумя узлами без использования TLS:

```mermaid
sequenceDiagram
    autonumber
    participant Alice as Узел A (Инициатор)
    participant Bob as Узел B (Ответчик)

    Note over Alice: 1. Генерация эфемерного ключа X25519 (eph_priv_A, eph_pub_A)<br/>2. Генерация nonce_A (32 байта)
    Alice->>Bob: HANDSHAKE_INIT {<br/>  version: 1, node_id_A, pubkey_A (Ed25519),<br/>  eph_pub_A (X25519), nonce_A<br/>}

    Note over Bob: 1. Проверка SHA-256(pubkey_A) == node_id_A<br/>2. Генерация эфемерного ключа X25519 (eph_priv_B, eph_pub_B)<br/>3. Генерация nonce_B (32 байта)<br/>4. Вычисление общего секрета: S = X25519(eph_priv_B, eph_pub_A)<br/>5. Формирование транскрипта T_B = (Init || Response_fields)<br/>6. Подпись Sig_B = Ed25519_Sign(priv_B, T_B)
    Bob->>Alice: HANDSHAKE_RESPONSE {<br/>  node_id_B, pubkey_B, eph_pub_B, nonce_B,<br/>  signature_B, session_id<br/>}

    Note over Alice: 1. Проверка SHA-256(pubkey_B) == node_id_B<br/>2. Вычисление общего секрета: S = X25519(eph_priv_A, eph_pub_B)<br/>3. Проверка подписи Sig_B с помощью pubkey_B на транскрипте T_B<br/>4. Формирование транскрипта T_A = (T_B || Complete_fields)<br/>5. Подпись Sig_A = Ed25519_Sign(priv_A, T_A)<br/>6. Деривация ключей через HKDF-SHA-256(S, salt, info):<br/>   -> Key_A_to_B (ChaCha20), Key_B_to_A (ChaCha20)
    Alice->>Bob: HANDSHAKE_COMPLETE {<br/>  signature_A<br/>}

    Note over Bob: 1. Проверка Sig_A с помощью pubkey_A<br/>2. Деривация аналогичных ключей Key_A_to_B, Key_B_to_A<br/>3. Переход в статус сессии ACTIVE

    rect rgb(240, 255, 240)
        Note over Alice, Bob: Защищённый канал: кадры шифруются ChaCha20-Poly1305<br/>с монотонными счетчиками пакетов
        Alice->>Bob: ENCRYPTED_FRAME (AEAD Ciphertext + Poly1305 Auth Tag)
        Bob-->>Alice: ENCRYPTED_FRAME (AEAD Ciphertext + Poly1305 Auth Tag)
    end
```

---

### 5.3. Построение 3-звенного туннеля и луковичная передача

Диаграмма иллюстрирует процесс создания луковичного маршрута через 3 ретранслятора и доставку зашифрованного сообщения:

```mermaid
sequenceDiagram
    autonumber
    participant Src as Инициатор (Alice)
    participant R1 as Ретранслятор 1
    participant R2 as Ретранслятор 2
    participant R3 as Ретранслятор 3
    participant Dst as Получатель (Bob)

    Note over Src: Выбор R1, R2, R3 из DHT<br/>(разные подсети /24, высокий EMA-рейтинг)
    
    rect rgb(240, 248, 255)
        note over Src, R1: Шаг 1: Подключение к первому релею R1
        Src->>R1: TUNNEL_BUILD (TunnelID, NextHop=R2, OnionToken_R1)
        R1-->>Src: TUNNEL_BUILD_OK (TunnelID)
    end

    rect rgb(255, 250, 240)
        note over Src, R2: Шаг 2: Расширение туннеля до R2 через R1
        Src->>R1: TUNNEL_EXTEND (TunnelID, Encrypted_for_R1(NextHop=R3, OnionToken_R2))
        R1->>R2: TUNNEL_BUILD (TunnelID, NextHop=R3, OnionToken_R2)
        R2-->>R1: TUNNEL_BUILD_OK (TunnelID)
        R1-->>Src: TUNNEL_EXTEND_OK
    end

    rect rgb(240, 255, 240)
        note over Src, R3: Шаг 3: Расширение туннеля до R3 через R1, R2
        Src->>R1: TUNNEL_EXTEND (TunnelID, Encrypted_for_R1(Encrypted_for_R2(NextHop=Dst)))
        R1->>R2: TUNNEL_EXTEND (...)
        R2->>R3: TUNNEL_BUILD (TunnelID, NextHop=Dst, OnionToken_R3)
        R3-->>R2: TUNNEL_BUILD_OK
        R2-->>R1: TUNNEL_EXTEND_OK
        R1-->>Src: TUNNEL_EXTEND_OK
    end

    Note over Src: Туннель в состоянии ACTIVE.<br/>3 слоя шифрования: E_R1( E_R2( E_R3( E_E2E_Dst(Payload) ) ) )

    rect rgb(255, 245, 245)
        note over Src, Dst: Передача сообщения через луковичный маршрут
        Src->>R1: TUNNEL_DATA [Layer 1]
        Note over R1: Снятие слоя 1 (Key R1).<br/>Видит только адрес R2.
        R1->>R2: TUNNEL_DATA [Layer 2]
        Note over R2: Снятие слоя 2 (Key R2).<br/>Видит только адрес R3.
        R2->>R3: TUNNEL_DATA [Layer 3]
        Note over R3: Снятие слоя 3 (Key R3).<br/>Видит адрес получателя Dst.
        R3->>Dst: APP_MESSAGE [E2E Ciphertext]
        Note over Dst: Расшифрование сквозного E2E-слоя.<br/>Прочтение сообщения.
        Dst-->>R3: APP_ACK
        R3-->>R2: TUNNEL_ACK
        R2-->>R1: TUNNEL_ACK
        R1-->>Src: TUNNEL_ACK (Доставка подтверждена)
    end
```

---

## 6. Критерии невырожденности DHT (ТЗ §6)

В курсовой работе критически важно доказать работоспособность алгоритмов Kademlia и отсутствие скрытых упрощений. В соответствии с разделом 6 ТЗ, реализация строго удовлетворяет **шести критериям невырожденности**:

| № | Критерий ТЗ | Архитектурная реализация в проекте | Способ верификации в эксперименте |
|---|---|---|---|
| **1** | Запрет глобального реестра адресов | Узел хранит только свои $k$-bucket'ы. В коде отсутствует глобальная статическая мапа `NodeID -> Address`. | Инспекция памяти и кода; запуск узлов в изолированных контейнерах с разными томами. |
| **2** | Неполное знание сети ($\ge 80\%$ узлов знают $< N - 1$ контактов) | При $N = 21$ и $k = 4$, ёмкость бакетов ограничена, таблица содержит не более $12\text{--}15$ контактов. | Сбор метрики `routing_table_size` со всех узлов после завершения этапа bootstrap. |
| **3** | $\ge 30$ многошаговых контрольных поисков | Контрольный тест генерирует 30 пар $(S_i, D_i)$, где $D_i \notin \text{RoutingTable}(S_i)$ на момент старта. | Лог поиска фиксирует отсутствие $D_i$ в локальной таблице перед запуском `lookup_node()`. |
| **4** | Наличие промежуточных хопов | Каждый контрольный поиск обращается минимум к 1 промежуточному DHT-узлу (число RPC $\ge 2$, итераций $\ge 2$). | Журналирование трассы: список опрошенных узлов по итерациям с отметкой каждого хопа. |
| **5** | Живучесть при падении bootstrap-узла | После стабилизации сети $N = 21$ узел seed-bootstrap отключается (`SIGKILL`/`docker stop`). Сеть сохраняет связность. | Успешное выполнение `FIND_NODE` и `FIND_VALUE` между оставшимися 20 узлами после смерти bootstrap. |
| **6** | Полная фиксация телеметрии | Автоматический сбор и экспорт в CSV/JSON метрик заполнения бакетов, RTT, числа итераций и RPC. | Генерация артефактов `results/lookup_metrics.json` и `results/bucket_distribution.csv`. |

---

## 7. Модель угроз и механизмы защиты (Security Architecture)

### 7.1. Модель нарушителя
- **Внутренний пассивный нарушитель**: Узел-ретранслятор пытается анализировать проходящий трафик.
  - *Защита*: Луковичное шифрование промежуточных слоев и сквозное (End-to-End) шифрование полезной нагрузки. Релей $R_i$ знает только $R_{i-1}$ и $R_{i+1}$.
- **Активный нарушитель (MITM / Tampering)**: Попытка подмены сообщений на уровне TCP.
  - *Защита*: Аутентифицированное шифрование ChaCha20-Poly1305 каждого кадра; несовпадение тега аутентификации приводит к мгновенному разрыву сессии.
- **Replay-атаки**: Повторная отправка перехваченного валидного кадра в текущей или новой сессии.
  - *Защита*: Монотонные 64-битные счётчики пакетов внутри сессии + привязка к уникальному эфемерному `session_id`.
- **Подмена записей DHT / Откат версий (Rollback)**: Публикация устаревшей записи адреса жертвы.
  - *Защита*: Подпись записей ключом Ed25519 владельца; валидация монотонности `sequence_number` (записи со старым или равным номером отклоняются как атака).
- **Sybil и Eclipse атаки**: Попытка злоумышленника захватить окрестность определенного `NodeID`.
  - *Защита*:
    - Детерминированная привязка $NodeID = \text{SHA-256}(PubKey)$, делающая невозможной генерацию произвольного ID без подбора ключа;
    - Ограничение количества узлов из одной IP-подсети (/24) в одном $k$-bucket'е (IP/subnet diversity);
    - Независимые пути поиска ($\alpha = 3$).

---

## 8. Программные интерфейсы узла (Facade API)

В соответствии с требованиями ТЗ (§7), прикладной слой взаимодействует с оверлеем исключительно через класс-фасад:

```cpp
namespace p2p {

class NodeFacade {
public:
    virtual ~NodeFacade() = default;

    // Присоединение к сети через известные bootstrap-узлы
    virtual bool join(const std::vector<PeerAddress>& bootstrap_peers) = 0;

    // Итеративный поиск узла в Kademlia DHT
    virtual std::optional<PeerInfo> lookup_node(const NodeID& target_node_id) = 0;

    // Публикация подписанной записи в DHT (репликация на R=3 узла)
    virtual bool put_record(const std::string& key, 
                            const std::vector<uint8_t>& data, 
                            std::chrono::seconds ttl) = 0;

    // Поиск записи в DHT
    virtual std::optional<std::vector<uint8_t>> get_record(const std::string& key) = 0;

    // Построение луковичного туннеля через >= 3 ретранслятора
    virtual std::optional<uint32_t> build_tunnel(const NodeID& destination_node_id, 
                                                 const TunnelConstraints& constraints) = 0;

    // Отправка защищенных данных через активный туннель
    virtual bool send_via_tunnel(uint32_t tunnel_id, 
                                 const std::vector<uint8_t>& payload) = 0;

    // Закрытие туннеля и освобождение ресурсов
    virtual bool close_tunnel(uint32_t tunnel_id) = 0;

    // Получение текущего состояния сети и метрик
    virtual NetworkState get_network_state() const = 0;
};

} // namespace p2p
```

---

## 9. Дорожная карта реализации (Этапы разработки)

```mermaid
gantt
    title План реализации защищенной P2P оверлейной сети
    dateFormat  YYYY-MM-DD
    axisFormat  %d.%m
    section Базис
    Этап 1. Транспорт кадры идентичность CMake       :done, s1, 2026-09-14, 1d
    Архитектурная спецификация                      :done, s_arch, 2026-09-25, 1d
    section DHT и Маршрутизация
    Этап 2. Kademlia DHT k-bucket routing lookup    :active, s2, 2026-09-25, 3d
    Этап 3. Записи DHT репликация псевдонимы        :s3, 2026-09-28, 2d
    section Безопасность
    Этап 4. Протокол AKE и защита сессий            :s4, 2026-09-30, 3d
    section Туннели и Приложения
    Этап 5. Построение туннелей от 3 хопов          :s5, 2026-10-03, 3d
    Этап 6. Прикладной сервис сообщений и файлов    :s6, 2026-10-06, 3d
    section Тестирование и Анализ
    Этап 7. Развертывание сети N21 Docker           :s7, 2026-10-09, 2d
    Этап 8. Эксперименты сбор метрик netem отчет    :s8, 2026-10-11, 4d
```

| Этап | Название | Ключевые компоненты | Статус |
|---|---|---|:---:|
| **Этап 1** | Сетевой транспорт, кадры и идентичность | TCP-соединения, кадрирование 24B, FrameParser, Ed25519, NodeID, TOML-конфиг | **Выполнен** |
| **Документация** | Архитектурная спецификация | 7 подсистем, 4 графа, процессы поиска, AKE, луковичные туннели, фасад API | **Выполнен** |
| **Этап 2** | Kademlia DHT | KBucket LRU, RoutingTable 256, итеративный lookup $\alpha=3$, $k=4$, сетевой bootstrap, тесты E2-1..E2-8 | **В разработке** |
| **Этап 3** | Записи DHT и псевдонимы | `STORE`, `FIND_VALUE`, NodeRecord, репликация $R=3$, TTL, алиасы | Запланирован |
| **Этап 4** | Собственный AKE и защита сессий | Curve25519 (X25519), HKDF-SHA256, ChaCha20-Poly1305, replay-кэш | Запланирован |
| **Этап 5** | Многопереходные туннели ($\ge 3$ хопа) | Onion routing, пул $\ge 3$ туннелей, профилирование ретрансляторов (EMA) | Запланирован |
| **Этап 6** | Прикладные сервисы | Защищенные E2E сообщения, блочная передача файлов с SHA-256 | Запланирован |
| **Этап 7** | Развёртывание сети ($N = 21$) | Docker Compose, 4 схемы bootstrap (star, ring, tree, multi-seed) | Запланирован |
| **Этап 8** | Эксперименты и отчёт | Netem (задержки, потери), отказ узлов, экспорт CSV/JSON, графики | Запланирован |

