# Security Signature Utility

Инструмент командной строки на Go для генерации асимметричных ключей, создания цифровых подписей файлов и проверки целостности подписанных данных. Используются стандартные пакеты `crypto/rsa`, `crypto/ecdsa`, `crypto/sha256`.

## Возможности

- Генерация пары ключей RSA или ECDSA в формате PEM.
- Подпись содержимого файла с помощью SHA-256 и закрытого ключа.
- Верификация подписи файла с использованием открытого ключа.

## Установка

```bash
go install github.com/qyteboii/security-signature/cmd@latest
```

Либо клонируйте репозиторий и соберите бинарь вручную:

```bash
git clone https://github.com/qyteboii/security-signature.git
cd security-signature
go build -o security-signature ./cmd
```

После сборки бинарник появится в текущем каталоге. На Windows его можно запускать как `./security-signature.exe <команда>`, на Linux/macOS — `./security-signature <команда>`.

### Добавление в PATH

Чтобы вызывать утилиту из любого места:

1. Переместите бинарник в каталог, который уже в переменной среды `PATH` (например, `C:\Users\<пользователь>\go\bin` на Windows или `$HOME/go/bin` на Unix-системах).
2. Либо вручную добавьте папку с бинарником в `PATH`:
   - Windows (PowerShell):
     ```powershell
     [Environment]::SetEnvironmentVariable("Path", $Env:Path + ";C:\\path\\to\\folder", "User")
     ```
   - Linux/macOS (bash/zsh):
     ```bash
     export PATH="$PATH:/path/to/folder"
     ```
     Добавьте строку в `~/.bashrc`, `~/.zshrc` или другой профиль, чтобы сохранить изменение.

## Использование

Справка по общим командам:

```bash
security-signature help
```

### Генерация ключей

```bash
security-signature keygen -algo rsa -bits 3072 -out-priv private.pem -out-pub public.pem
security-signature keygen -algo ecdsa -curve p256 -out-priv ecdsa_priv.pem -out-pub ecdsa_pub.pem
```

### Подпись файла

```bash
security-signature sign -key private.pem -in document.pdf -out document.sig
```

### Проверка подписи

```bash
security-signature verify -key public.pem -in document.pdf -sig document.sig
```

Программа выводит понятные сообщения об ошибках, если обязательные аргументы не переданы или подпись некорректна.

## Тестирование

Все автотесты находятся в каталоге `tests/` и проверяют как криптографическое ядро, так и CLI-функциональность.

```bash
go test ./...
```

## Документация

Полная документация находится в каталоге `docs/`:

- [Спецификация системы](docs/01-specification.md) — техническая спецификация
- [Техническое задание](docs/02-requirements.md) — ТЗ на разработку
- [Руководство оператора](docs/03-operator-manual.md) — для пользователей
- [Руководство системного программиста](docs/04-system-programmer-manual.md) — для администраторов
- [Руководство программиста](docs/05-programmer-manual.md) — для разработчиков

См. также [README документации](docs/README.md) для обзора всех документов.