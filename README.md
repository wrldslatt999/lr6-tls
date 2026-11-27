# ЛР №6. Безпечний клієнт-серверний застосунок на SSL/TLS

**Виконавець:** Чучула Євгеній Андрійович  
**Дисципліна:** Прикладні аспекти програмування  
**Тип:** лабораторна робота №6 (11 балів)  
**Середовище:** Python 3.11+, OpenSSL, Kali Linux або інший Linux, GitHub Actions

> Навчальний проєкт на основі структури `додаток_лр_6.rar` викладача. Код шаблону відкориговано: випадковий HMAC-ключ на сервері не збігався з клієнтським, а пароль передавався через аргумент CLI. Тут ключ HMAC узгоджується лише після автентифікації через перевірений TLS-канал, а пароль вводиться приховано.

## 1. Підготовка Kali Linux

```bash
cd ~/Downloads/LR6_TLS_Chuchula
python3 --version
openssl version
bash scripts/gencerts.sh
python3 tools/setup_users.py add-user --username alice --role user
```

`setup_users.py` **двічі приховано запитає пароль** (мінімум 12 байтів). На диск записується лише `scrypt`-хеш із випадковим salt, а не пароль. Сертифікат і ключі створюються **локально**, вони навмисно не включені в ZIP/GitHub. Для повторного використання існуючих сертифікатів не запускай генерацію знову.

## 2. Запуск сервера (термінал №1)

```bash
python3 server.py --host 127.0.0.1 --port 8443
```

Сервер слухає лише `127.0.0.1` за замовчуванням. Порт `8443`. У лабораторній достатньо **двох терміналів Kali**, оскільки вимоги ЛР №6 не зобов'язують створювати дві VM (на відміну від ПР №5–7). Для окремих вузлів можна змінити `--host` на адресу сервера, а сертифікат перегенерувати із SAN цієї адреси.

## 3. Клієнт із перевіркою CA та hostname (термінал №2)

```bash
cd ~/Downloads/LR6_TLS_Chuchula
python3 client.py --host 127.0.0.1 --server-name localhost --port 8443 --ca certs/ca.crt --user alice --msg "Hello secure TLS"
python3 client.py --host 127.0.0.1 --server-name localhost --ca certs/ca.crt --user alice --file data/message.txt
```

В обох випадках пароль вводиться через `getpass`. Успішний результат: `TLS verified: TLSv1.3 ...` (залежить від OpenSSL), `Authentication: OK`, `Data: VERIFIED`, SHA-256 повідомлення. Клієнт перевіряє ланцюжок довіри `ca.crt`, SAN `localhost` і сертифікат сервера. **Не застосовується** небезпечне `verify=False` або `CERT_NONE`.

## 4. Негативні сценарії

```bash
# Спроба підміни HMAC на власному лабораторному сервері.
python3 client.py --user alice --msg "tamper" --tamper
# Очікується: Data: REJECTED bad_hmac, код завершення 2.

# Вказано хибне DNS-ім'я, сертифікат має бути відхилений.
python3 client.py --user alice --server-name not-localhost.invalid --msg "test"
# Очікується: SSLCertVerificationError; дані не передаються.

# Неправильний пароль: введи завідомо неправильний пароль у prompt.
python3 client.py --user alice --msg "wrong password check"
# Очікується: Authentication: invalid_credentials.
```

Підміна є **навчальною**, лише власного сервера. Усі негативні тести також доступні в `tests/test_security.py`.

## 5. Журналювання та аналіз

```bash
python3 analyze_logs.py logs/server.jsonl
python3 analyze_logs.py logs/server.jsonl --event auth.failed
python3 analyze_logs.py logs/server.jsonl --user alice
python3 analyze_logs.py logs/server.jsonl --out reports/kali-analysis.json
```

Записуються UTC-час, тип події, IP, користувач (де застосовно), TLS-версія й шифр, кількість байтів або SHA-256. **Паролі, HMAC-ключі, токени й текст повідомлень не логуються.** Відстежуються TLS-handshake помилки, повторні помилки автентифікації, порушення цілісності та відхилення доступу.

`logs/`, `users.json`, приватні ключі сертифікатів додані до `.gitignore`. Згенерований звіт `reports/kali-analysis.json` містить лише агрегацію подій, і його можна комітити після перегляду.

## 6. Автоматизовані тести

```bash
python3 -m unittest discover -s tests -v
```

Тести створюють тимчасовий CA, реальний TLS-сервер із випадковим портом і виконують справжні з'єднання. Перевіряються TLS, сертифікати, паролі, HMAC, повторний запит, обмеження спроб входу, обмеження довжини й логи. Локально проведено **22/22 тестів**; для підтвердження саме в Kali запусти цю команду самостійно.

GitHub Actions: `.github/workflows/tests.yml` — Python 3.11, 3.12, 3.13. Ніякі ключі та паролі в CI не завантажуються: усе створюється в тимчасовій папці під час тестів.

## 7. Публікація

```bash
bash scripts/publish-github.sh
```

Скрипт перевіряє автентифікацію GitHub CLI, локальні Git name/email, перевіряє файли для секретів, створює приватний репозиторій `wrldslatt999/lr6-tls` і завантажує код лише після підтвердження. Перед зміною видимості на Public перевір вміст репозиторію. У Moodle здається посилання на GitHub.

## Структура

| Шлях | Призначення |
|---|---|
| `server.py` | TLS 1.2+, автентифікація, сесії, валідація HMAC, логи |
| `client.py` | Перевірка сертифіката, hostname, відправка повідомлення/файлу |
| `security.py` | `scrypt`, HMAC, термін дії токенів, rate limit |
| `eventlog.py` | Потокобезпечний журнал JSONL |
| `tools/setup_users.py` | Створення користувача із захищеним хешем |
| `scripts/gencerts.sh` | Локальний CA та сертифікат сервера із SAN |
| `analyze_logs.py` | Фільтрація, підрахунок, підозрілі події |
| `tests/test_security.py` | Реальні TLS-інтеграційні та модульні тести |
| `docs/LR6_report.md` | Технічний звіт за 3 пунктами завдання |
| `docs/protocol.md` | Формат обміну, TLS та контроль цілісності |
| `docs/security.md` | Модель загроз, обмеження та рекомендації |
| `docs/verification.md` | Протокол локальної перевірки |

## Джерела

- [Python 3.11 — ssl](https://docs.python.org/3.11/library/ssl.html)
- [Python — hashlib.scrypt](https://docs.python.org/3/library/hashlib.html#hashlib.scrypt)
- [OpenSSL — x509](https://docs.openssl.org/3.0/man1/openssl-x509/)
- [OWASP — Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
- [OWASP — Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

Це **навчальний прототип**. Він не є аудитованим production-сервісом, не має централізованого KMS, обробляє тільки невеликі повідомлення (до 32 КіБ) та не зберігає користувацькі дані на сервері.
