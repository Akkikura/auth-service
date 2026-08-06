# Auth Service

Небольшой сервис аутентификации на Go. PostgreSQL хранит пользователей, Redis —
короткоживущие серверные сессии и счётчики rate limit.

## API

| Метод | Путь | Описание |
|---|---|---|
| `POST` | `/register` | Регистрация пользователя |
| `POST` | `/login` | Создание сессии |
| `GET` | `/me` | Данные текущего пользователя |
| `POST` | `/logout` | Отзыв текущей сессии |
| `GET` | `/health/live` | Liveness probe |
| `GET` | `/health/ready` | Проверка PostgreSQL и Redis |
| `GET` | `/metrics` | Prometheus metrics |

Полный контракт и все коды ответов описаны в
[`api/openapi.yaml`](api/openapi.yaml). Корневой путь `/` не обслуживается: это
backend-only приложение.

Пример регистрации:

```http
POST /register
Content-Type: application/json

{"email":"user@example.com","password":"strong-password"}
```

Успешная регистрация возвращает `201 Created`, повторная — `409 Conflict`, а
невалидное тело или учётные данные — `400 Bad Request`. Email приводится к
нижнему регистру и обрезается по краям до сохранения.

Успешный вход возвращает непрозрачный Bearer token:

```json
{
  "token": "...",
  "token_type": "Bearer",
  "expires_at": "2026-08-05T12:00:00Z"
}
```

Токен передаётся в `Authorization: Bearer <token>`. В ответах никогда нет
пароля или password hash. Неизвестный email и неправильный пароль дают
одинаковый `401 Unauthorized` и одинаковое тело ошибки.

## Быстрый запуск

Нужны Docker и Docker Compose v2.

```bash
cp .env.example .env
docker compose up --build --wait
./scripts/smoke-test.sh
```

В PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\start.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\smoke-test.ps1
```

API будет доступен на `http://localhost:8080`. PostgreSQL и Redis доступны API
только во внутренней Docker-сети и по умолчанию не занимают порты хоста.

Если HTTP-порт занят, измените `HTTP_PORT` в `.env`.

Остановить сервис:

```bash
docker compose down
```

Удалить контейнеры вместе с локальными данными:

```bash
docker compose down -v --remove-orphans
```

Для PowerShell доступны `scripts/stop.ps1` и `scripts/reset.ps1`.

## Запуск без Docker для приложения

Для запуска Go-процесса на хосте опубликуйте порты зависимостей через отдельный
Compose override, затем экспортируйте настройки и запустите миграции перед API:

```bash
POSTGRES_PORT=5432 REDIS_PORT=6379 docker compose \
  -f docker-compose.yml -f docker-compose.host.yml \
  up -d --wait postgres redis
export AUTH_SESSION_HASH_KEY='replace-with-at-least-32-random-bytes'
export POSTGRES_URL='postgres://auth:auth@localhost:5432/auth?sslmode=disable'
export REDIS_ADDRESS='localhost:6379'
go run ./cmd/migrate
go run ./cmd/api
```

Если локальный PostgreSQL уже занимает `5432`, используйте, например,
`POSTGRES_PORT=15432` и тот же порт в `POSTGRES_URL`. Для integration tests это
можно передать напрямую: `make test-integration POSTGRES_HOST_PORT=15432`.

Проект совместим с Go 1.25+, а CI и Docker image собираются Go 1.26.5.

## Конфигурация

Все параметры и локальные значения находятся в [`.env.example`](.env.example).
Основные настройки:

| Переменная | Назначение | Значение по умолчанию |
|---|---|---|
| `APP_ENV` | Имя окружения | `development` |
| `HTTP_ADDRESS` | Адрес HTTP-сервера | `:8080` |
| `HTTP_REQUEST_TIMEOUT` | Deadline одного запроса | `5s` |
| `HTTP_TRUSTED_PROXY_CIDRS` | Доверенные proxy CIDR через запятую | пусто |
| `POSTGRES_URL` | PostgreSQL DSN | локальный DSN |
| `POSTGRES_MAX_CONNECTIONS` | Максимум соединений на экземпляр | `20` |
| `REDIS_ADDRESS` | Redis endpoint | `localhost:6379` |
| `REDIS_TLS` | TLS для Redis | `false` |
| `REDIS_KEY_PREFIX` | Namespace ключей Redis | `auth:` |
| `AUTH_SESSION_HASH_KEY` | HMAC-ключ отпечатков токенов | обязательна |
| `AUTH_SESSION_TTL` | Абсолютный TTL сессии | `30m` |
| `AUTH_PASSWORD_MIN_LENGTH` | Минимальная длина пароля | `12` |
| `AUTH_PASSWORD_MAX_LENGTH` | Максимальная длина пароля | `128` |
| `AUTH_HASH_CONCURRENCY` | Предел одновременных Argon2-операций | `4` |

`AUTH_SESSION_HASH_KEY` принимает обычную строку или значение вида
`base64:<standard-base64>` и должен содержать не менее 32 байт. Его ротация
инвалидирует все активные сессии. В production сервис требует явно заданные
PostgreSQL и Redis endpoints и отклоняет демонстрационные ключи из примеров
конфигурации.

Заголовки `X-Forwarded-For` и `X-Real-IP` учитываются только когда непосредственный
peer входит в `HTTP_TRUSTED_PROXY_CIDRS`. В список следует включать только ingress
или load balancer, который сам перезаписывает forwarded chain.

## Миграции

```bash
go run ./cmd/migrate
```

SQL-файлы встроены в migration binary. Миграции выполняются транзакционно под
PostgreSQL advisory lock. Таблица `schema_migrations` хранит SHA-256 каждого
применённого файла; изменённая задним числом миграция останавливает rollout с
явной ошибкой.

В Kubernetes миграции следует запускать отдельным Job до обновления Deployment.
Пример находится в `deploy/kubernetes/migration-job.yaml`.

## Kubernetes

Манифесты в `deploy/kubernetes` — безопасная отправная точка, а не готовые
секреты конкретного кластера. Перед применением:

1. опубликуйте image и замените `ghcr.io/acme/auth-service:1.0.0` на immutable
   tag или digest вашего registry;
2. создайте Secret из secret manager — не применяйте `secret.example.yaml` как
   production-секрет;
3. укажите CIDR ingress в `HTTP_TRUSTED_PROXY_CIDRS` и проверьте TLS-параметры
   PostgreSQL/Redis;
4. запустите migration Job и только после его успеха обновляйте Deployment.

Deployment запускается non-root с read-only root filesystem, без service account
token и Linux capabilities. Настроены startup/readiness/liveness probes,
graceful termination, resource requests/limits, PodDisruptionBudget и
распределение реплик по узлам.

## Тесты и проверки

```bash
make fmt-check
make vet
make lint
make test
make test-race
make test-integration
make build
make vuln
make validate-openapi
make validate-k8s
```

`make test-integration` поднимает PostgreSQL и Redis и проверяет весь сценарий:
регистрацию, повторный email, generic login errors, `/me`, logout, фактическое
истечение TTL и поведение при отказе зависимостей. Каждый тест создаёт отдельную
PostgreSQL-схему и Redis namespace; общие таблицы и база Redis не очищаются.

CI дополнительно проверяет чистоту `go.mod`/`go.sum`, запускает тесты с race
detector, `golangci-lint`, `govulncheck`, валидацию OpenAPI/Kubernetes и Trivy scan
финального image. Сторонние GitHub Actions закреплены на полных commit SHA.

## Надёжность и безопасность

- Пароли хешируются Argon2id с отдельной случайной солью. Параметры хеша
  сохраняются в PHC-строке и обновляются после успешного входа при смене
  настроек.
- Случайный session token содержит 256 бит энтропии. Redis хранит только его
  HMAC-SHA-256 digest и `user_id` с TTL.
- Login ограничивается атомарными Redis-счётчиками по IP и identity. Email и IP
  перед попаданием в Redis-ключ хешируются.
- Argon2-операции ограничены семафором, поэтому всплеск запросов не может
  породить неограниченное количество тяжёлой CPU/RAM работы.
- Сервер ограничивает body и headers, принимает строгий JSON, задаёт timeouts,
  восстанавливается после panic и завершает работу по SIGTERM через graceful
  shutdown.
- Логи структурированы и содержат request ID. Метрики используют ограниченный
  набор route/method labels и не принимают произвольные значения из URL.

PostgreSQL и Redis не проверяются синхронно при старте: временная недоступность
зависимости не завершает процесс. Операции, которым нужна недоступная зависимость,
возвращают `503 Service Unavailable`, readiness становится неуспешным, а liveness
остаётся успешным. Регистрация намеренно работает fail-open только при отказе
Redis rate limiter; уникальность email и ограничение Argon2 при этом продолжают
действовать. Login и все session operations при отказе Redis работают fail-closed.

Production checklist и модель границ доверия находятся в
[`SECURITY.md`](SECURITY.md). Kubernetes-манифесты — в `deploy/kubernetes`.

## Границы ответственности

Сервис реализует authentication core, а не полный IAM. Подтверждение email,
password reset, MFA, управление устройствами и сессиями, RBAC и аудит действий
следует добавлять отдельными use cases и контрактами.
