<h1 align="center"><img src="docs/netdiag.svg" width="34" alt="" /> netdiag</h1>

<p align="center"><strong>Проверьте, где обрывается соединение.</strong><br />
Проверка DNS, HTTPS и задержки для Windows, macOS и Linux.</p>

<p align="center">
  <a href="https://github.com/rnqg/netdiag/actions/workflows/ci.yml"><img src="https://github.com/rnqg/netdiag/actions/workflows/ci.yml/badge.svg?branch=main" alt="Тесты и сборки" /></a>
</p>

<p align="center">
  <a href="https://github.com/rnqg/netdiag/releases/latest">Скачать</a> · <a href="#установка">Установка</a> · <a href="#запуск">Запуск</a> · <a href="docs/guide.ru.md">Руководство</a> · <a href="README.md">English</a>
</p>

<p align="center">
  <img src="docs/demo.svg" width="680" alt="Пример проверки: example.org отвечает по HTTPS, но не на ICMP. Шлюз ответил на все три пробы, медиана RTT — 2,38 мс." />
</p>

В этом замере сайт открылся по HTTPS, хотя на пинг не ответил.
netdiag показывает эти результаты отдельно и измеряет RTT до шлюза.
Для обычной проверки не нужны аккаунт и измерительный сервер.

## Установка

Скачайте архив для своей системы и распакуйте его. Go нужен только для сборки из исходников.

| Система | x86-64 | ARM64 |
| --- | --- | --- |
| Windows | [.zip](https://github.com/rnqg/netdiag/releases/latest/download/netdiag-windows-amd64.zip) | [.zip](https://github.com/rnqg/netdiag/releases/latest/download/netdiag-windows-arm64.zip) |
| macOS | [Intel](https://github.com/rnqg/netdiag/releases/latest/download/netdiag-macos-amd64.tar.gz) | [Apple Silicon](https://github.com/rnqg/netdiag/releases/latest/download/netdiag-macos-arm64.tar.gz) |
| Linux | [.tar.gz](https://github.com/rnqg/netdiag/releases/latest/download/netdiag-linux-amd64.tar.gz) | [.tar.gz](https://github.com/rnqg/netdiag/releases/latest/download/netdiag-linux-arm64.tar.gz) |

В архиве есть клиент `netdiag` и измерительный узел `netdiag-node`. Откройте терминал в распакованной папке и выполните `./netdiag --help`. В PowerShell на Windows выполните `.\netdiag.exe --help`.

[Последний релиз](https://github.com/rnqg/netdiag/releases/latest) · [Контрольные суммы SHA-256](https://github.com/rnqg/netdiag/releases/latest/download/SHA256SUMS)

<details>
<summary>Сборка из исходников</summary>

Нужен Go 1.27.4 или новее.

```sh
git clone https://github.com/rnqg/netdiag.git
cd netdiag
go build -o netdiag ./cmd/netdiag
```

На Windows соберите через `go build -o netdiag.exe ./cmd/netdiag` и запускайте `.\netdiag.exe` в PowerShell.

</details>

## Запуск

**Проверить один сайт.** Увидеть, отвечает ли DNS и проходят ли TCP, TLS и HTTP.

```sh
./netdiag check --mode direct --profile quick \
  --only-target --target example.org
```

**Измерить качество связи.** Посмотреть перцентили RTT, джиттер и число проб без ответа.

```sh
./netdiag quality --mode direct --duration 60s
```

**Сравнить работу без VPN и с VPN.** Выполните первую команду без VPN, включите его и запустите вторую.

```sh
./netdiag check --mode direct --output direct.json
./netdiag compare --baseline direct.json --mode vpn
```

**Измерить скорость и буферблоат.** [Измерительный узел](docs/guide.ru.md#свой-измерительный-узел) нужен для замеров скорости и p95 RTT до, во время и после нагрузки. Перед запуском задайте токен узла в `NETDIAG_NODE_TOKEN`:

```sh
./netdiag speed --mode direct --node https://node.example.org:8443
```

## Документация

- [Команды, отчёты и исправления DNS](docs/guide.ru.md)
- [Настройка измерительного узла и Docker](docs/guide.ru.md#свой-измерительный-узел)
- [Протокол измерительного узла](PROTOCOL.md)

[Apache 2.0](LICENSE) · [Лицензии зависимостей](THIRD_PARTY_NOTICES.md)
