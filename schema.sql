CREATE TABLE IF NOT EXISTS users (
    id text,
    username text,
    hash char(64),
    salt char(64),
    groups text[]
);

CREATE TABLE IF NOT EXISTS sessions (
    id text,
    token text, 
    expiry int
);


