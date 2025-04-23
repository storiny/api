CREATE TABLE IF NOT EXISTS blog_login_tokens
(
    -- Hashed token value
    id                    TEXT PRIMARY KEY,
    blog_id               BIGINT      NOT NULL
        REFERENCES blogs (id)
            ON DELETE CASCADE,
    user_id               BIGINT      NOT NULL
        REFERENCES users (id)
            ON DELETE CASCADE,
    is_persistent_session BOOL        NOT NULL DEFAULT TRUE,
    expires_at            TIMESTAMPTZ NOT NULL,
    UNIQUE (blog_id, user_id)
);
