docker run -e POSTGRES_PASSWORD=password -p 5432:5432 -d postgres:15.2-alpine
docker run -p "6379:6379" -d redis:7.0-alpine

sqlx migrate run
cargo nextest run
