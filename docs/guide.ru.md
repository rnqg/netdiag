# Руководство по netdiag

[README](../README.ru.md) · [English](guide.md)

## Быстрый запуск

Нужен Go **1.27.4** или новее. В терминале на macOS или Linux:

```sh
git clone https://github.com/rnqg/netdiag.git
cd netdiag
go build -o netdiag ./cmd/netdiag
./netdiag check --mode direct --profile quick
```

<details>
<summary>Сборка и запуск в Windows PowerShell</summary>

```powershell
git clone https://github.com/rnqg/netdiag.git
cd netdiag
go build -o netdiag.exe ./cmd/netdiag
.\netdiag.exe check --mode direct --profile quick
```

В остальных примерах заменяйте `./netdiag` на `.\netdiag.exe`.

</details>

Обычная проверка работает без аккаунта и измерительного узла. Выберите `direct` без VPN или `vpn` при включённом VPN. В режиме `direct` проверяются, например, Яндекс и VK, а в `vpn` — YouTube, Discord и GitHub. Подключение переключается в VPN-клиенте.

| Задача | Команда |
| --- | --- |
| Проверить один сайт | `./netdiag check --mode direct --only-target --target example.org` |
| Измерить RTT, джиттер и потери | `./netdiag quality --mode direct --duration 60s` |
| Сохранить отчёт | `./netdiag check --mode direct --output direct.json` |
| Увидеть все команды и флаги | `./netdiag --help` |

По умолчанию `check` использует профиль `deep` (до 180 секунд). `quick` ограничен 60 секундами. Повторяйте `--target`, чтобы добавить адреса. `--only-target` убирает встроенный список, `--trace` добавляет трассировку.

## Что проверяет netdiag

- **Сеть и Wi-Fi.** Интерфейсы, шлюз, MTU, доступные радио-параметры и смена подключения.
- **DNS и доступность.** A/AAAA, DNS по UDP, TCP, DoH и DoT, IPv4/IPv6, TCP, TLS 1.2/1.3 и HTTP/1.1, HTTP/2, HTTP/3 при наличии Alt-Svc.
- **Качество.** RTT, потери и джиттер по ICMP. Со своим узлом добавляются UDP-пробы и проверка проходящего размера пакета.

Запросы идут по маршрутам ОС. Если браузер использует прокси, PAC или расширение, его результат может отличаться. Тайм-аут одной пробы показывает, на каком этапе не пришёл ответ. Чтобы установить причину, сравните результаты по другим протоколам и целям.

## Скорость и буферблоат

Со своим узлом можно измерить скорость загрузки, отдачи и обеих одновременно. В каждой фазе netdiag сравнивает p95 RTT без нагрузки, под нагрузкой и после неё.

Задайте на клиенте `NETDIAG_NODE_TOKEN` с токеном узла, затем запустите:

```sh
./netdiag speed --mode direct --node https://node.example.org:8443 --max-mib 1024
```

Для одного отчёта с доступностью, RTT и нагрузкой используйте `check --full`:

```sh
./netdiag check --mode direct --full --trace \
  --node https://node.example.org:8443 --output full.json
```

`--max-mib` ограничивает объём тестовых данных. Служебный трафик идёт сверх лимита. При исчерпании бюджета отчёт будет частичным. Если нужен больший лимит, увеличьте его и на клиенте, и на узле.

<details>
<summary>Как считаются RTT, потери и буферблоат</summary>

- Джиттер — средняя абсолютная разница RTT между соседними успешными пробами без пропусков. p99 появляется от 100 успешных проб.
- Проба считается потерянной, если ответ пропустил срок ожидания. Поздние ответы и ошибки отправки учитываются отдельно.
- Буферблоат — разница p95 UDP RTT до одного узла. Первые 5 секунд замеров до нагрузки и под нагрузкой исключаются. Нужны минимум 50 ответов в каждом сравниваемом интервале, непрерывная передача и проверка восстановления задержки.
- Если p95 вырос хотя бы на 20 мс и восстановился, netdiag может сравнить обычную нагрузку с ограниченной до 70% скорости и повторить обычный замер. Это испытание, настройки роутера и ОС остаются прежними.

</details>

### Скорость без своего узла

```sh
./netdiag speed --mode direct --accept-mlab-policy --max-mib 256
```

> [!IMPORTANT]
> M-Lab публикует результаты теста вместе с внешним IP. Этот режим измеряет скорость одним потоком в каждом направлении. Для буферблоата нужен свой узел. [Политика M-Lab](https://www.measurementlab.net/privacy/) · [Правила использования](https://www.measurementlab.net/aup/)

### Свой измерительный узел

Соберите `netdiag-node` на сервере и запустите его с TLS-сертификатом, которому доверяет клиент:

```sh
go build -o netdiag-node ./cmd/netdiag-node
export NETDIAG_NODE_TOKEN="$(openssl rand -hex 32)"
./netdiag-node --listen :8443 --udp :4444 \
  --cert /etc/netdiag/fullchain.pem --key /etc/netdiag/privkey.pem
```

Откройте **8443/TCP** для HTTPS, **8443/UDP** для HTTP/3 и **4444/UDP** для эхо-проб. HTTPS и UDP должны попадать на один узел с сохранением адреса клиента. Передайте клиенту тот же токен через `NETDIAG_NODE_TOKEN`. В PowerShell переменная задаётся как `$env:NETDIAG_NODE_TOKEN`.

<details>
<summary>Запуск узла в Docker</summary>

```sh
docker build -t netdiag-node .
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
  --env NETDIAG_NODE_TOKEN -p 8443:8443/tcp -p 8443:8443/udp -p 4444:4444/udp \
  -v /etc/netdiag:/certs:ro netdiag-node \
  --cert /certs/fullchain.pem --key /certs/privkey.pem
```

Сертификат и ключ должны быть доступны контейнеру с UID 65532.

</details>

## Отчёты

Сохраните замер без VPN, затем включите VPN и повторите проверку тех же сайтов:

```sh
./netdiag check --mode direct --output direct.json
./netdiag compare --baseline direct.json --mode vpn --output comparison.json
./netdiag report --input comparison.json --verbose
```

`compare` повторяет цели и профиль исходного отчёта. Для отчёта `check --full` повторяются проверки доступности. `--format json` выводит JSON в stdout, `--output` сохраняет файл без перезаписи.

netdiag не отправляет отчёты автоматически. Перед отправкой проверьте домены, адреса целей и своего узла. SSID, MAC и токен узла в отчёт не входят.

**Коды выхода:** `0` — проверка без ошибок, `1` — обнаружена ошибка, `2` — не удалось запустить команду или сохранить результат, `3` — измерение частичное.

## Исправления DNS

```sh
./netdiag fix --input direct.json
./netdiag fix --input direct.json --apply
./netdiag fix --flush-cache --input direct.json --apply
```

Первая команда выводит инструкцию. Для `--apply` нужны интерактивное подтверждение и права администратора. Смена DNS предлагается, когда свежий отчёт подтверждает рабочую альтернативу по UDP. При VPN, прокси или обнаруженном управлении сетью используйте инструкцию. На Linux смена DNS поддерживается через NetworkManager.

netdiag сохраняет исходные настройки, проверяет результат и откатывает изменение, если проверка или подтверждение не состоялись. Если откат не подтверждён, используйте выведенный путь с `./netdiag fix --recover <путь>`. После выключения питания автоматический откат не гарантирован.

`--flush-cache` с `--input` проверяет проблемный сайт до и после очистки. Чтобы указать сайт явно, передайте `--target example.org` вместо `--input`.

## Разработка

```sh
go test -race ./...
go vet ./...
```

[Протокол измерительного узла](../PROTOCOL.md) · [Лицензии зависимостей](../THIRD_PARTY_NOTICES.md)
