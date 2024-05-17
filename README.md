# Auth Service

## Setup & Building

```bash
cargo install cargo-watch
cargo build
```

## Run service locally (Manually)

```bash
cargo watch -q -c -w src/ -w assets/ -x run
```

visit <http://localhost:3000>

## Run servers locally (Docker)

```bash
docker compose build
docker compose up
```

visit <http://localhost:3000>
