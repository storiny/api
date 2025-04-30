WITH inserted_user AS (
    INSERT INTO users (name, username, email)
        VALUES ('Sample user', 'sample_user', 'sample@example.com')
        RETURNING id)
INSERT
INTO blogs (id, name, slug, domain, user_id)
VALUES (1, 'Sample blog', 'test-blog', 'test.com', (SELECT id FROM inserted_user));
