WITH inserted_user AS (
    INSERT
    INTO users (name, username, email)
    VALUES ('Sample user', 'sample_user', 'sample@example.com')
        RETURNING id
), inserted_blogs AS (
    INSERT
    INTO blogs (name, slug, user_id)
    SELECT
        'Sample blog ' || i, 'sample-blog-' || i, (SELECT id FROM inserted_user)
    FROM generate_series(1, 5) i
        RETURNING id
)
INSERT INTO blog_login_tokens (id, user_id, blog_id, expires_at)
SELECT uuid_generate_v4(),
       (SELECT id FROM inserted_user),
       id,
       NOW() - INTERVAL '7 days'
FROM inserted_blogs;