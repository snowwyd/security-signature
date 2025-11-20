# РУКОВОДСТВО ПРОГРАММИСТА СИСТЕМЫ ПОДПИСИ И ПРОВЕРКИ ЦЕЛОСТНОСТИ ФАЙЛОВ

**Версия:** 1.0  
**Дата:** 2025  
**Статус:** Действующее

---

## СОДЕРЖАНИЕ

1. [Общие сведения](#1-общие-сведения)
2. [Архитектура системы](#2-архитектура-системы)
3. [Описание модулей](#3-описание-модулей)
4. [Примеры использования API](#4-примеры-использования-api)
5. [Внутренние структуры данных](#5-внутренние-структуры-данных)
6. [Расширение функциональности](#6-расширение-функциональности)
7. [Тестирование](#7-тестирование)
8. [Отладка](#8-отладка)
9. [Стиль кода](#9-стиль-кода)
10. [Производительность](#10-производительность)
11. [Безопасность кода](#11-безопасность-кода)
12. [Справочная информация](#12-справочная-информация)

---

## 1. Общие сведения

### 1.1. Назначение документа
Настоящее руководство предназначено для программистов, занимающихся разработкой, модификацией и расширением функциональности системы. Документ содержит описание архитектуры, API, внутренних структур данных и примеров использования. Документ разработан в соответствии с требованиями ГОСТ 34.201-89 "Информационные технологии. Комплекс стандартов на автоматизированные системы. Виды, комплектность и обозначение документов при создании автоматизированных систем".

### 1.2. Краткая характеристика системы
Система реализована на языке Go версии 1.25.4, использует только стандартную библиотеку и предоставляет модульный API для работы с цифровыми подписями.

### 1.3. Состав системы
- `cmd/main.go` — CLI интерфейс
- `pkg/signature/key.go` — генерация ключей
- `pkg/signature/crypto.go` — криптографические операции
- `tests/signature_test.go` — автоматические тесты

## 2. Архитектура системы

### 2.1. Общая структура

```
┌─────────────────┐
│   cmd/main.go   │  CLI интерфейс
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ pkg/signature/  │  Криптографический модуль
│  - key.go       │  Генерация ключей
│  - crypto.go    │  Подпись/верификация
└─────────────────┘
```

### 2.2. Принципы проектирования
- **Модульность**: разделение на независимые модули
- **Инкапсуляция**: внутренние функции не экспортируются
- **Обработка ошибок**: все функции возвращают ошибки
- **Потоковая обработка**: работа с большими файлами без загрузки в память

## 3. Описание модулей

### 3.1. Модуль pkg/signature/key.go

#### 3.1.1. Назначение модуля
Генерация криптографических ключевых пар для алгоритмов RSA и ECDSA.

#### 3.1.2. Экспортируемые константы

```go
const (
    AlgorithmRSA   = "rsa"   // Идентификатор алгоритма RSA
    AlgorithmECDSA = "ecdsa" // Идентификатор алгоритма ECDSA
)
```

#### 3.1.3. Экспортируемые функции

**GenerateKeyPair**
```go
func GenerateKeyPair(algorithm string, rsaBits int, curveName string) (privPEM, pubPEM []byte, err error)
```

Генерирует пару ключей для указанного алгоритма.

**Параметры**:
- `algorithm` — алгоритм: `"rsa"` или `"ecdsa"`
- `rsaBits` — размер RSA ключа в битах (используется только для RSA)
- `curveName` — название кривой ECDSA: `"p256"`, `"p384"`, `"p521"` (используется только для ECDSA)

**Возвращаемые значения**:
- `privPEM` — закрытый ключ в формате PEM
- `pubPEM` — открытый ключ в формате PEM
- `err` — ошибка, если генерация не удалась

**Пример использования**:
```go
privPEM, pubPEM, err := signature.GenerateKeyPair(signature.AlgorithmRSA, 2048, "")
if err != nil {
    log.Fatal(err)
}
os.WriteFile("private.pem", privPEM, 0600)
os.WriteFile("public.pem", pubPEM, 0644)
```

#### 3.1.4. Внутренние функции

**generateRSAKeyPair**
```go
func generateRSAKeyPair(bits int) ([]byte, []byte, error)
```
Генерирует пару RSA ключей указанного размера.

**generateECDSAKeyPair**
```go
func generateECDSAKeyPair(curveName string) ([]byte, []byte, error)
```
Генерирует пару ECDSA ключей для указанной кривой.

**selectCurve**
```go
func selectCurve(name string) elliptic.Curve
```
Возвращает эллиптическую кривую по имени.

### 3.2. Модуль pkg/signature/crypto.go

#### 3.2.1. Назначение модуля
Криптографические операции: хеширование, подпись, верификация, работа с ключами.

#### 3.2.2. Экспортируемые функции

**HashFileSHA256**
```go
func HashFileSHA256(path string) ([]byte, error)
```
Вычисляет SHA-256 хеш файла с потоковым чтением.

**Параметры**:
- `path` — путь к файлу

**Возвращаемые значения**:
- `[]byte` — хеш-сумма (32 байта)
- `error` — ошибка при чтении файла

**Пример**:
```go
digest, err := signature.HashFileSHA256("document.pdf")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Hash: %x\n", digest)
```

**SignDigest**
```go
func SignDigest(privateKey crypto.PrivateKey, digest []byte) ([]byte, error)
```
Подписывает хеш-сумму закрытым ключом.

**Параметры**:
- `privateKey` — закрытый ключ (`*rsa.PrivateKey` или `*ecdsa.PrivateKey`)
- `digest` — хеш-сумма для подписания (32 байта для SHA-256)

**Возвращаемые значения**:
- `[]byte` — подпись
- `error` — ошибка при подписании

**Пример**:
```go
privKey, _ := signature.LoadPrivateKeyPEM(keyData)
digest, _ := signature.HashFileSHA256("file.txt")
signature, err := signature.SignDigest(privKey, digest)
```

**VerifyDigest**
```go
func VerifyDigest(publicKey crypto.PublicKey, digest, signature []byte) error
```
Проверяет подпись хеш-суммы открытым ключом.

**Параметры**:
- `publicKey` — открытый ключ (`*rsa.PublicKey` или `*ecdsa.PublicKey`)
- `digest` — хеш-сумма (32 байта)
- `signature` — подпись для проверки

**Возвращаемые значения**:
- `error` — `nil` если подпись верна, иначе ошибка

**Пример**:
```go
pubKey, _ := signature.LoadPublicKeyPEM(keyData)
digest, _ := signature.HashFileSHA256("file.txt")
sigData, _ := os.ReadFile("file.sig")
sig, _ := signature.DecodeSignatureBase64(string(sigData))
err := signature.VerifyDigest(pubKey, digest, sig)
if err != nil {
    fmt.Println("Signature invalid")
}
```

**LoadPrivateKeyPEM**
```go
func LoadPrivateKeyPEM(data []byte) (crypto.PrivateKey, error)
```
Загружает закрытый ключ из PEM данных.

**Поддерживаемые форматы**:
- `RSA PRIVATE KEY` (PKCS#1)
- `EC PRIVATE KEY` (SEC1)
- `PRIVATE KEY` (PKCS#8)

**Пример**:
```go
keyData, _ := os.ReadFile("private.pem")
privKey, err := signature.LoadPrivateKeyPEM(keyData)
if err != nil {
    log.Fatal(err)
}
```

**LoadPublicKeyPEM**
```go
func LoadPublicKeyPEM(data []byte) (crypto.PublicKey, error)
```
Загружает открытый ключ из PEM данных.

**Поддерживаемые форматы**:
- `PUBLIC KEY` (PKIX)
- `RSA PUBLIC KEY` (PKCS#1)

**EncodeSignatureBase64 / DecodeSignatureBase64**
```go
func EncodeSignatureBase64(signature []byte) string
func DecodeSignatureBase64(data string) ([]byte, error)
```
Кодируют/декодируют подпись в Base64.

## 4. Примеры использования API

### 4.1. Полный цикл: генерация ключей, подпись, проверка

```go
package main

import (
    "fmt"
    "log"
    "os"
    "github.com/qyteboii/security-signature/pkg/signature"
)

func main() {
    // 1. Генерация ключей
    privPEM, pubPEM, err := signature.GenerateKeyPair(signature.AlgorithmRSA, 2048, "")
    if err != nil {
        log.Fatal(err)
    }
    
    // Сохранение ключей
    os.WriteFile("private.pem", privPEM, 0600)
    os.WriteFile("public.pem", pubPEM, 0644)
    
    // 2. Подпись файла
    privKey, err := signature.LoadPrivateKeyPEM(privPEM)
    if err != nil {
        log.Fatal(err)
    }
    
    digest, err := signature.HashFileSHA256("document.pdf")
    if err != nil {
        log.Fatal(err)
    }
    
    sig, err := signature.SignDigest(privKey, digest)
    if err != nil {
        log.Fatal(err)
    }
    
    sigBase64 := signature.EncodeSignatureBase64(sig)
    os.WriteFile("document.sig", []byte(sigBase64), 0644)
    
    // 3. Проверка подписи
    pubKey, err := signature.LoadPublicKeyPEM(pubPEM)
    if err != nil {
        log.Fatal(err)
    }
    
    digest2, err := signature.HashFileSHA256("document.pdf")
    if err != nil {
        log.Fatal(err)
    }
    
    sigData, _ := os.ReadFile("document.sig")
    sig2, _ := signature.DecodeSignatureBase64(string(sigData))
    
    err = signature.VerifyDigest(pubKey, digest2, sig2)
    if err != nil {
        fmt.Println("Signature verification failed:", err)
    } else {
        fmt.Println("Signature is valid")
    }
}
```

### 4.2. Использование ECDSA

```go
// Генерация ECDSA ключей
privPEM, pubPEM, err := signature.GenerateKeyPair(
    signature.AlgorithmECDSA, 
    0, 
    "p256",
)

// Остальное аналогично RSA
```

### 4.3. Обработка ошибок

```go
digest, err := signature.HashFileSHA256("file.txt")
if err != nil {
    switch {
    case os.IsNotExist(err):
        fmt.Println("File not found")
    case os.IsPermission(err):
        fmt.Println("Permission denied")
    default:
        fmt.Printf("Error: %v\n", err)
    }
    return
}
```

## 5. Внутренние структуры данных

### 5.1. Формат ключей

**RSA закрытый ключ (PKCS#1)**:
```go
type PrivateKey struct {
    PublicKey PublicKey
    D         *big.Int
    Primes    []*big.Int
    // ...
}
```

**ECDSA закрытый ключ (SEC1)**:
```go
type PrivateKey struct {
    PublicKey PublicKey
    D         *big.Int
}
```

### 5.2. Формат подписей

**RSA подпись (PKCS#1 v1.5)**:
- Бинарные данные фиксированного размера (зависит от размера ключа)
- Для RSA 2048: 256 байт

**ECDSA подпись (ASN.1)**:
- Кодировка в формате ASN.1 DER
- Переменный размер (обычно 64-72 байта для P-256)

## 6. Расширение функциональности

### 6.1. Добавление нового алгоритма

Для добавления нового алгоритма подписи:

1. Добавьте константу в `key.go`:
```go
const AlgorithmEd25519 = "ed25519"
```

2. Реализуйте генерацию ключей в `GenerateKeyPair`:
```go
case AlgorithmEd25519:
    return generateEd25519KeyPair()
```

3. Добавьте поддержку в `SignDigest` и `VerifyDigest`:
```go
case *ed25519.PrivateKey:
    sig := ed25519.Sign(k, digest)
    return sig, nil
```

### 6.2. Добавление нового формата кодирования

Для поддержки других форматов подписей (например, hex):

```go
func EncodeSignatureHex(signature []byte) string {
    return hex.EncodeToString(signature)
}

func DecodeSignatureHex(data string) ([]byte, error) {
    return hex.DecodeString(data)
}
```

### 6.3. Добавление пакетной обработки

Пример функции для подписания нескольких файлов:

```go
func SignMultipleFiles(privKey crypto.PrivateKey, files []string) (map[string]string, error) {
    signatures := make(map[string]string)
    for _, file := range files {
        digest, err := HashFileSHA256(file)
        if err != nil {
            return nil, err
        }
        sig, err := SignDigest(privKey, digest)
        if err != nil {
            return nil, err
        }
        signatures[file] = EncodeSignatureBase64(sig)
    }
    return signatures, nil
}
```

## 7. Тестирование

### 7.1. Запуск тестов

```bash
# Все тесты
go test ./...

# С подробным выводом
go test -v ./...

# Конкретный тест
go test -v ./tests -run TestGenerateKeyPairRSA

# С покрытием
go test -cover ./...
```

### 7.2. Написание новых тестов

Пример теста:

```go
func TestCustomFunction(t *testing.T) {
    // Arrange
    privPEM, pubPEM, err := signature.GenerateKeyPair(signature.AlgorithmRSA, 2048, "")
    if err != nil {
        t.Fatalf("GenerateKeyPair failed: %v", err)
    }
    
    // Act
    privKey, err := signature.LoadPrivateKeyPEM(privPEM)
    if err != nil {
        t.Fatalf("LoadPrivateKeyPEM failed: %v", err)
    }
    
    // Assert
    if privKey == nil {
        t.Fatal("private key is nil")
    }
}
```

### 7.3. Бенчмарки

Пример бенчмарка:

```go
func BenchmarkSignRSA(b *testing.B) {
    priv, _ := rsa.GenerateKey(rand.Reader, 2048)
    digest := sha256.Sum256([]byte("test data"))
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        signature.SignDigest(priv, digest[:])
    }
}
```

Запуск:
```bash
go test -bench=. ./...
```

## 8. Отладка

### 8.1. Использование отладчика

```bash
# Запуск с отладчиком Delve
dlv debug ./cmd

# Установка точек останова
(dlv) break pkg/signature/crypto.go:35
(dlv) continue
```

### 8.2. Логирование

Для добавления логирования можно использовать стандартный пакет `log`:

```go
import "log"

func SignDigest(privateKey crypto.PrivateKey, digest []byte) ([]byte, error) {
    log.Printf("Signing digest of length %d", len(digest))
    // ...
}
```

### 8.3. Профилирование

```bash
# CPU профилирование
go test -cpuprofile=cpu.prof ./...
go tool pprof cpu.prof

# Профилирование памяти
go test -memprofile=mem.prof ./...
go tool pprof mem.prof
```

## 9. Стиль кода

### 9.1. Соглашения Go

- Имена экспортируемых функций начинаются с заглавной буквы
- Имена неэкспортируемых функций начинаются со строчной буквы
- Документация для всех экспортируемых элементов
- Обработка всех ошибок

### 9.2. Форматирование

```bash
# Автоматическое форматирование
go fmt ./...

# Проверка стиля
golangci-lint run
```

### 9.3. Примеры кода

Все примеры должны быть рабочими и проверяться компилятором:

```bash
go run examples/example.go
```

## 10. Производительность

### 10.1. Оптимизация

- Использование потокового чтения для больших файлов
- Избежание лишних копирований данных
- Использование `io.Copy` вместо чтения всего файла

### 10.2. Профилирование

Регулярно проверяйте производительность:

```bash
go test -bench=. -benchmem ./...
```

## 11. Безопасность кода

### 11.1. Рекомендации

- Всегда проверяйте входные данные
- Используйте криптографически стойкие генераторы случайных чисел
- Не логируйте закрытые ключи
- Очищайте чувствительные данные из памяти (если возможно)

### 11.2. Аудит безопасности

Периодически проверяйте:
- Использование устаревших алгоритмов
- Правильность обработки ошибок
- Отсутствие утечек информации через ошибки

## 12. Справочная информация

### 12.1. Зависимости

Система использует только стандартную библиотеку Go:
- `crypto/rsa`
- `crypto/ecdsa`
- `crypto/sha256`
- `crypto/x509`
- `encoding/pem`
- `encoding/base64`

### 12.2. Совместимость

- Go 1.25.4+
- Кроссплатформенность: Windows, Linux, macOS
- Совместимость с OpenSSL для формата ключей PEM

### 12.3. Ограничения

- Максимальный размер файла ограничен только доступной памятью (но используется потоковая обработка)
- Поддержка только RSA и ECDSA алгоритмов
- Поддержка только SHA-256 для хеширования

---

## СПИСОК ИСПОЛЬЗОВАННЫХ ИСТОЧНИКОВ

1. ГОСТ 34.201-89. Информационные технологии. Комплекс стандартов на автоматизированные системы. Виды, комплектность и обозначение документов при создании автоматизированных систем. — М.: Стандартинформ, 1989.

2. Руководство программиста системы подписи и проверки целостности файлов. Версия 1.0. — 2025.

3. RFC 3447. PKCS #1: RSA Cryptography Specifications Version 2.1. — 2003.

4. RFC 5480. Elliptic Curve Cryptography Subject Public Key Info. — 2009.

5. RFC 7468. Textual Encodings of PKIX, PKCS, and CMS Structures. — 2015.

6. FIPS 186-4. Digital Signature Standard (DSS). — 2013.

7. The Go Programming Language Specification. Version 1.25. — https://go.dev/ref/spec

8. Effective Go. — https://go.dev/doc/effective_go

---

**Разработчик:** _________________  
**Дата:** _________________  
**Утверждено:** _________________

