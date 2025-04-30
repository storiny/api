use crate::{
    constants::{
        blog_login_token_data::BlogLoginTokenData,
        notification_entity_type::NotificationEntityType,
        redis_namespaces::RedisNamespace,
        session_cookie::SESSION_COOKIE_NAME,
        token::TOKEN_LENGTH,
    },
    grpc::{
        defs::blog_def::v1::{
            VerifyBlogLoginRequest,
            VerifyBlogLoginResponse,
        },
        service::GrpcService,
    },
    middlewares::identity::identity::Identity,
    utils::{
        clear_user_sessions::clear_user_sessions,
        get_user_sessions::get_user_sessions,
    },
};
use actix_web::cookie::{
    Cookie,
    CookieJar,
};
use argon2::{
    Argon2,
    PasswordHasher,
    password_hash::SaltString,
};
use redis::cmd;
use serde_json::Value;
use sqlx::{
    Postgres,
    QueryBuilder,
    Row,
};
use storiny_session::{
    EXTERNAL_BLOG_KEY,
    LIFECYCLE_KEY,
    config::SessionLifecycle,
    storage::generate_session_key,
};
use time::Duration;
use tonic::{
    Request,
    Response,
    Status,
};
use tracing::{
    debug,
    error,
    warn,
};

/// The TTL value (in seconds) for a user's session.
static SESSION_TTL: i64 = Duration::weeks(1).whole_seconds();

/// Verifies blog login token for a user.
#[tracing::instrument(
    name = "GRPC verify_blog_login",
    skip_all,
    fields(
        identifier = tracing::field::Empty,
        hostname = tracing::field::Empty
    ),
    err
)]
pub async fn verify_blog_login(
    client: &GrpcService,
    request: Request<VerifyBlogLoginRequest>,
) -> Result<Response<VerifyBlogLoginResponse>, Status> {
    let request = request.into_inner();
    let pg_pool = &client.db_pool;
    let identifier = request.blog_identifier;
    let token_id = request.token;
    let hostname = request.host;

    // Identifier can be slug, domain or the ID
    let is_identifier_number = identifier.parse::<i64>().is_ok();

    tracing::Span::current().record("identifier", &identifier);
    tracing::Span::current().record("hostname", &hostname);

    // Validate token length.
    if token_id.chars().count() != TOKEN_LENGTH {
        warn!("token length does not match");
        return Ok(Response::new(VerifyBlogLoginResponse {
            is_token_valid: false,
            is_persistent_cookie: None,
            cookie_value: None,
        }));
    }

    let salt = SaltString::from_b64(&client.config.token_salt).map_err(|error| {
        error!("unable to parse the salt string: {error:?}");
        Status::internal("unable to verify the token")
    })?;

    let hashed_token = Argon2::default()
        .hash_password(token_id.as_bytes(), &salt)
        .map_err(|error| {
            error!("unable to generate token hash: {error:?}");
            Status::internal("unable to verify the token")
        })?;
    let cache_key = format!("{}:{hashed_token}", RedisNamespace::BlogLogin);

    let mut redis_conn = client.redis_pool.get().await.map_err(|error| {
        error!("unable to acquire a connection from the Redis pool: {error:?}");
        Status::internal("Redis error")
    })?;

    // Fetch login data from cache.
    let result: Option<Vec<u8>> = cmd("GET")
        .arg(&[&cache_key])
        .query_async(&mut redis_conn)
        .await
        .map_err(|error| {
            error!("unable to fetch the login data: {error:?}");
            Status::internal("Redis error")
        })?;

    // Missing or expired login token.
    if result.is_none() {
        warn!("no login token found in the cache");

        return Ok(Response::new(VerifyBlogLoginResponse {
            is_token_valid: false,
            is_persistent_cookie: None,
            cookie_value: None,
        }));
    }

    let login_data = rmp_serde::from_slice::<BlogLoginTokenData>(&result.unwrap_or_default())
        .map_err(|error| {
            error!("unable to parse login data: {error:?}");
            Status::internal("parsing error")
        })?;
    let user_id = login_data.uid;

    let mut txn = pg_pool.begin().await.map_err(|error| {
        error!("unable to begin the transaction: {error:?}");
        Status::internal("Database error")
    })?;

    // Fetch blog using identifier.
    let mut query_builder: QueryBuilder<Postgres> = QueryBuilder::new(
        r#"
SELECT id, domain FROM blogs b
WHERE
"#,
    );

    query_builder.push(if is_identifier_number {
        r#"
(b.id = $1::BIGINT OR b.slug = $1)
"#
    } else {
        // The identifier is definitely not an ID
        r#"
(b.domain = $1 OR b.slug = $1)
"#
    });

    query_builder.push(r#" AND b.deleted_at IS NULL "#);

    let blog = query_builder
        .build()
        .bind(identifier)
        .fetch_one(&mut *txn)
        .await
        .map_err(|error| {
            if matches!(error, sqlx::Error::RowNotFound) {
                Status::not_found("Blog not found")
            } else {
                error!("database error: {error:?}");
                Status::internal("Database error")
            }
        })?;
    let blog_id = blog.get::<i64, _>("id");

    // Assert blog ID.
    if blog_id != login_data.bid {
        warn!("blog id from database does not match the one from cache");

        return Ok(Response::new(VerifyBlogLoginResponse {
            is_token_valid: false,
            is_persistent_cookie: None,
            cookie_value: None,
        }));
    }

    // Assert blog domain.
    if blog.get::<Option<String>, _>("domain") != Some(hostname.clone()) {
        warn!("blog domain from database does not match the one from cache");

        return Ok(Response::new(VerifyBlogLoginResponse {
            is_token_valid: false,
            is_persistent_cookie: None,
            cookie_value: None,
        }));
    }

    // Insert session into cache.
    let client_location = login_data.loc;
    let client_device = login_data.device;
    let mut login_data_map = Identity::get_login_data_map(user_id);

    login_data_map.insert(EXTERNAL_BLOG_KEY.to_string(), Value::Bool(true));
    login_data_map.insert(
        LIFECYCLE_KEY.to_string(),
        Value::from(if login_data.persistent {
            SessionLifecycle::PersistentSession
        } else {
            SessionLifecycle::BrowserSession
        } as i32),
    );

    if let Ok(domain) = serde_json::to_value(hostname) {
        login_data_map.insert("domain".to_string(), domain);
    }

    if let Some(ref device) = client_device {
        if let Ok(device) = serde_json::to_value(device) {
            login_data_map.insert("device".to_string(), device);
        }
    }

    if let Some(ref location) = client_location {
        if let Ok(location) = serde_json::to_value(location) {
            login_data_map.insert("location".to_string(), location);
        }
    }

    let session_key = generate_session_key(Some(user_id.to_string()));
    let session_cache_key = format!("{}:{}", RedisNamespace::Session, session_key.as_ref());
    let body = rmp_serde::to_vec_named(&login_data_map).map_err(|error| {
        error!("unable to serialize login data: {error:?}");
        Status::internal("serialization error")
    })?;

    let mut redis_pipe = redis::pipe();
    redis_pipe
        .atomic()
        .cmd("SET") // Insert session
        .arg(&session_cache_key)
        .arg(&body)
        .arg("NX") // NX: only set the key if it does not already exist
        .arg("EX") // EX: set expiry
        .arg(SESSION_TTL)
        .ignore()
        .cmd("DEL") // Delete login token
        .arg(&[&cache_key]);

    // Generate signed cookie value.
    let encoded_cookie_value = {
        let mut jar = CookieJar::new();
        jar.signed_mut(&client.cookie_secret_key)
            .add(Cookie::new(SESSION_COOKIE_NAME, session_key.to_string()));
        jar.delta()
            .next()
            .and_then(|cookie| {
                cookie
                    .encoded() // Percent-encode cookie
                    .stripped()
                    .to_string()
                    .splitn(2, '=') // Extract value from the encoded string
                    .nth(1)
                    .map(|value| value.to_string())
            })
            .ok_or(Status::internal("unable to sign the cookie"))?
    };

    let client_device_str = client_device
        .map(|device| device.display_name.to_string())
        .unwrap_or("Unknown device".to_string());

    // Update the `last_login_at` and insert a login notification for the user.
    sqlx::query(
        r#"
WITH updated_user AS (
    UPDATE users
    SET last_login_at = NOW()
    WHERE id = $2
),
inserted_notification AS (
    INSERT INTO notifications (entity_type)
    VALUES ($1)
    RETURNING id
)
INSERT
INTO
    notification_outs (
        notified_id,
        notification_id,
        rendered_content
    )
SELECT $2, (SELECT id FROM inserted_notification), $3
"#,
    )
    .bind(NotificationEntityType::LoginAttempt as i16)
    .bind(user_id)
    .bind(if let Some(location) = client_location {
        format!("{client_device_str}:{}", location.display_name.to_string())
    } else {
        client_device_str
    })
    .execute(&mut *txn)
    .await
    .map_err(|_| Status::internal("Database error"))?;

    // Check if the user maintains more than or equal to 10 sessions, and
    // delete all the previous sessions if the current number of active
    // sessions for the user exceeds the per user session limit (10).
    match get_user_sessions(&client.redis_pool, user_id).await {
        Ok(sessions) => {
            if sessions.len() >= 10 {
                match clear_user_sessions(&client.redis_pool, user_id).await {
                    Ok(_) => {
                        debug!(
                            "cleared {} overflowing sessions for the user",
                            sessions.len()
                        );
                    }
                    Err(error) => {
                        return Err(Status::internal(format!(
                            "unable to clear the overflowing sessions for the user: {:?}",
                            error
                        )));
                    }
                };
            }
        }
        Err(error) => {
            return Err(Status::internal(format!(
                "unable to fetch the sessions for the user: {:?}",
                error
            )));
        }
    };

    redis_pipe
        .query_async::<_, ()>(&mut redis_conn)
        .await
        .map_err(|error| {
            error!("Redis error: {error:?}");
            Status::internal("Redis error")
        })?;

    txn.commit().await.map_err(|error| {
        error!("unable to commit the transaction: {error:?}");
        Status::internal("Database error")
    })?;

    Ok(Response::new(VerifyBlogLoginResponse {
        is_token_valid: true,
        is_persistent_cookie: Some(login_data.persistent),
        cookie_value: Some(encoded_cookie_value),
    }))
}

#[cfg(test)]
mod tests {
    use crate::{
        config::get_app_config,
        constants::{
            blog_login_token_data::BlogLoginTokenData,
            blog_login_token_expiration::BLOG_LOGIN_TOKEN_EXPIRATION,
            notification_entity_type::NotificationEntityType,
            redis_namespaces::RedisNamespace,
            session_cookie::SESSION_COOKIE_NAME,
        },
        grpc::defs::{
            blog_def::v1::VerifyBlogLoginRequest,
            login_activity_def::v1::DeviceType,
        },
        routes::{
            GetLoginDetailsResponse,
            get_login_details,
        },
        test_utils::{
            RedisTestContext,
            init_app_for_test,
            test_grpc_service,
        },
        utils::{
            clear_user_sessions::clear_user_sessions,
            generate_hashed_token::generate_hashed_token,
            get_client_device::ClientDevice,
            get_client_location::ClientLocation,
            get_user_sessions::{
                UserSession,
                get_user_sessions,
            },
        },
    };
    use actix_web::{
        cookie::Cookie,
        test,
    };
    use redis::{
        AsyncCommands,
        RedisResult,
        aio::ConnectionLike,
    };
    use sqlx::{
        PgPool,
        Row,
    };
    use storiny_macros::test_context;
    use time::OffsetDateTime;
    use tokio::time::{
        Duration,
        sleep,
    };
    use tonic::Request;
    use urlencoding::decode;
    use uuid::Uuid;

    /// Generates a random hashed token based on the provided `salt` and returns the (cache_key,
    /// token_id, hashed_token) tuple.
    ///
    /// * `salt` - The salt string used to hash the token.
    fn get_token(salt: &str) -> (String, String, String) {
        let (token_id, hashed_token) = generate_hashed_token(salt).unwrap();
        let cache_key = format!("{}:{hashed_token}", RedisNamespace::BlogLogin);
        (cache_key, token_id, hashed_token)
    }

    /// Inserts the provided `token_data` into the cache.
    ///
    /// * `cache_key` - The key for this token data.
    /// * `token_data` - The [BlogLoginTokenData] instance.
    /// * `conn` - The Redis connection instance.
    async fn insert_login_token<C>(
        cache_key: &str,
        token_data: &BlogLoginTokenData,
        conn: &mut C,
    ) -> RedisResult<()>
    where
        C: ConnectionLike,
    {
        let serialized_token_data =
            rmp_serde::to_vec_named(token_data).expect("unable to serialize");

        redis::cmd("SET")
            .arg(&cache_key)
            .arg(&serialized_token_data)
            .arg("EX") // EX: set expiry
            .arg(BLOG_LOGIN_TOKEN_EXPIRATION)
            .query_async::<_, ()>(&mut *conn)
            .await
    }

    mod serial {
        use super::*;
        use tonic::Code;

        #[test_context(RedisTestContext)]
        #[sqlx::test(fixtures("verify_blog_login"))]
        async fn can_verify_blog_login_by_id(_ctx: &mut RedisTestContext, pool: PgPool) {
            test_grpc_service(
                pool,
                true,
                Box::new(|mut client, pool, redis_pool, user_id| async move {
                    let config = get_app_config().unwrap();

                    let mut db_conn = pool.acquire().await.unwrap();
                    let mut redis_conn = redis_pool.get().await.unwrap();
                    let web_app = init_app_for_test(get_login_details, pool, false, true, None)
                        .await
                        .0;

                    let user_id = user_id.unwrap();
                    let blog_id = 1_i64;
                    let domain = "test.com";
                    let (cache_key, token_id, _) = get_token(&config.token_salt);

                    let mut token_data = BlogLoginTokenData {
                        uid: user_id,
                        bid: blog_id,
                        persistent: true,
                        loc: None,
                        device: None,
                    };

                    // With `persistent` = true and no other properties.
                    insert_login_token(&cache_key, &token_data, &mut *redis_conn)
                        .await
                        .unwrap();

                    let response = client
                        .verify_blog_login(Request::new(VerifyBlogLoginRequest {
                            blog_identifier: blog_id.to_string(),
                            token: token_id.to_string(),
                            host: domain.to_string(),
                        }))
                        .await;

                    assert!(response.is_ok());

                    let response = response.unwrap().into_inner();

                    assert!(response.cookie_value.is_some());
                    assert_eq!(response.is_persistent_cookie.unwrap(), true);
                    assert_eq!(response.is_token_valid, true);

                    // Should insert a login session into the cache.
                    let sessions = get_user_sessions(&redis_pool, user_id)
                        .await
                        .expect("unable to get user sessions");

                    assert_eq!(sessions.len(), 1);

                    let session_data = &sessions[0].1;

                    assert_eq!(session_data.user_id, user_id);
                    assert_eq!(session_data.domain.clone().unwrap(), "test.com");
                    assert_eq!(session_data.ext_blog, Some(true));
                    assert_eq!(session_data.ack, false);
                    assert!(session_data.device.is_none());
                    assert!(session_data.location.is_none());

                    // Should also insert a notification.
                    let result = sqlx::query(
                        r#"
SELECT EXISTS (
    SELECT
        1
    FROM
        notification_outs
    WHERE
        notification_id = (
            SELECT id FROM notifications
            WHERE entity_type = $1
        )
   )
"#,
                    )
                    .bind(NotificationEntityType::LoginAttempt as i16)
                    .fetch_one(&mut *db_conn)
                    .await
                    .unwrap();

                    assert!(result.get::<bool, _>("exists"));

                    // Should also update the `last_login_at` column.
                    let result = sqlx::query(
                        r#"
SELECT last_login_at FROM users
WHERE id = $1
"#,
                    )
                    .bind(user_id)
                    .fetch_one(&mut *db_conn)
                    .await
                    .unwrap();

                    assert!(
                        result
                            .get::<Option<OffsetDateTime>, _>("last_login_at")
                            .is_some()
                    );

                    // Should delete the login token.
                    let result: Option<Vec<u8>> = redis::cmd("GET")
                        .arg(&[&cache_key])
                        .query_async(&mut *redis_conn)
                        .await
                        .unwrap();

                    assert!(result.is_none());

                    clear_user_sessions(&redis_pool, user_id)
                        .await
                        .expect("unable to clear user sessions");

                    // With `persistent` = false and other client properties set.
                    token_data.persistent = false;
                    token_data.loc = Some(ClientLocation {
                        display_name: "test_location".to_string(),
                        lat: Some(25.0),
                        lng: Some(25.0),
                    });
                    token_data.device = Some(ClientDevice {
                        display_name: "test_device".to_string(),
                        r#type: DeviceType::Computer as i32,
                    });

                    insert_login_token(&cache_key, &token_data, &mut *redis_conn)
                        .await
                        .unwrap();

                    let response = client
                        .verify_blog_login(Request::new(VerifyBlogLoginRequest {
                            blog_identifier: blog_id.to_string(),
                            token: token_id.to_string(),
                            host: domain.to_string(),
                        }))
                        .await;

                    assert!(response.is_ok());

                    let response = response.unwrap().into_inner();

                    assert!(response.cookie_value.is_some());
                    assert_eq!(response.is_persistent_cookie.unwrap(), false);
                    assert_eq!(response.is_token_valid, true);

                    // Should insert a login session into the cache.
                    let sessions = get_user_sessions(&redis_pool, user_id)
                        .await
                        .expect("unable to get user sessions");

                    assert_eq!(sessions.len(), 1);

                    let session_data = &sessions[0].1;

                    assert_eq!(session_data.user_id, user_id);
                    assert_eq!(session_data.domain.clone().unwrap(), "test.com");
                    assert_eq!(session_data.ext_blog, Some(true));
                    assert_eq!(session_data.ack, false);
                    assert_eq!(
                        session_data.device.clone().unwrap(),
                        token_data.device.unwrap()
                    );
                    assert_eq!(
                        session_data.location.clone().unwrap(),
                        token_data.loc.unwrap()
                    );

                    let cookie_value = response.cookie_value.unwrap();
                    let decoded_value =
                        decode(&cookie_value).expect("unable to decode cookie value");

                    // Should be a valid cookie value to be used as a session token.
                    let req = test::TestRequest::get()
                        .cookie(Cookie::new(SESSION_COOKIE_NAME, decoded_value.to_string()))
                        .uri("/get-login-details")
                        .to_request();
                    let res = test::call_service(&web_app, req).await;
                    let client_session =
                        test::read_body_json::<GetLoginDetailsResponse, _>(res).await;

                    assert!(client_session.device.is_some());
                    assert!(client_session.location.is_some());
                    assert_eq!(client_session.domain, Some("test.com".to_string()));

                    // Should delete the login token.
                    let result: Option<Vec<u8>> = redis::cmd("GET")
                        .arg(&[&cache_key])
                        .query_async(&mut *redis_conn)
                        .await
                        .unwrap();

                    assert!(result.is_none());
                }),
            )
            .await;
        }

        #[test_context(RedisTestContext)]
        #[sqlx::test(fixtures("verify_blog_login"))]
        async fn can_verify_blog_login_by_slug(_ctx: &mut RedisTestContext, pool: PgPool) {
            test_grpc_service(
                pool,
                true,
                Box::new(|mut client, _pool, redis_pool, user_id| async move {
                    let config = get_app_config().unwrap();
                    let mut redis_conn = redis_pool.get().await.unwrap();
                    let user_id = user_id.unwrap();
                    let blog_id = 1_i64;
                    let domain = "test.com";
                    let (cache_key, token_id, _) = get_token(&config.token_salt);

                    insert_login_token(
                        &cache_key,
                        &BlogLoginTokenData {
                            uid: user_id,
                            bid: blog_id,
                            persistent: true,
                            loc: None,
                            device: None,
                        },
                        &mut *redis_conn,
                    )
                    .await
                    .unwrap();

                    let response = client
                        .verify_blog_login(Request::new(VerifyBlogLoginRequest {
                            blog_identifier: "test-blog".to_string(),
                            token: token_id.to_string(),
                            host: domain.to_string(),
                        }))
                        .await;

                    assert!(response.is_ok());

                    let response = response.unwrap().into_inner();

                    assert!(response.cookie_value.is_some());
                    assert_eq!(response.is_token_valid, true);
                }),
            )
            .await;
        }

        #[test_context(RedisTestContext)]
        #[sqlx::test(fixtures("verify_blog_login"))]
        async fn can_verify_blog_login_by_domain(_ctx: &mut RedisTestContext, pool: PgPool) {
            test_grpc_service(
                pool,
                true,
                Box::new(|mut client, _pool, redis_pool, user_id| async move {
                    let config = get_app_config().unwrap();
                    let mut redis_conn = redis_pool.get().await.unwrap();
                    let user_id = user_id.unwrap();
                    let blog_id = 1_i64;
                    let domain = "test.com";
                    let (cache_key, token_id, _) = get_token(&config.token_salt);

                    insert_login_token(
                        &cache_key,
                        &BlogLoginTokenData {
                            uid: user_id,
                            bid: blog_id,
                            persistent: true,
                            loc: None,
                            device: None,
                        },
                        &mut *redis_conn,
                    )
                    .await
                    .unwrap();

                    let response = client
                        .verify_blog_login(Request::new(VerifyBlogLoginRequest {
                            blog_identifier: domain.to_string(),
                            token: token_id.to_string(),
                            host: domain.to_string(),
                        }))
                        .await;

                    assert!(response.is_ok());

                    let response = response.unwrap().into_inner();

                    assert!(response.cookie_value.is_some());
                    assert_eq!(response.is_token_valid, true);
                }),
            )
            .await;
        }

        #[test_context(RedisTestContext)]
        #[sqlx::test]
        async fn can_handle_an_expired_token(_ctx: &mut RedisTestContext, pool: PgPool) {
            test_grpc_service(
                pool,
                true,
                Box::new(|mut client, _, redis_pool, user_id| async move {
                    let config = get_app_config().unwrap();
                    let mut redis_conn = redis_pool.get().await.unwrap();
                    let user_id = user_id.unwrap();
                    let blog_id = 1_i64;
                    let domain = "test.com";
                    let (cache_key, token_id, _) = get_token(&config.token_salt);

                    let serialized_token_data = rmp_serde::to_vec_named(&BlogLoginTokenData {
                        uid: user_id,
                        bid: blog_id,
                        persistent: true,
                        loc: None,
                        device: None,
                    })
                    .expect("unable to serialize");

                    redis::cmd("SET")
                        .arg(&cache_key)
                        .arg(&serialized_token_data)
                        .arg("EX") // EX: set expiry
                        .arg(3) // 3 seconds
                        .query_async::<_, ()>(&mut *redis_conn)
                        .await
                        .unwrap();

                    sleep(Duration::from_secs(5)).await; // Wait for token to expire

                    let response = client
                        .verify_blog_login(Request::new(VerifyBlogLoginRequest {
                            blog_identifier: blog_id.to_string(),
                            token: token_id.to_string(),
                            host: domain.to_string(),
                        }))
                        .await;

                    assert!(response.is_ok());

                    let response = response.unwrap().into_inner();

                    assert_eq!(response.is_token_valid, false);
                }),
            )
            .await;
        }

        #[test_context(RedisTestContext)]
        #[sqlx::test(fixtures("verify_blog_login"))]
        async fn can_reject_verification_for_unmatched_host(
            _ctx: &mut RedisTestContext,
            pool: PgPool,
        ) {
            test_grpc_service(
                pool,
                true,
                Box::new(|mut client, _, redis_pool, user_id| async move {
                    let config = get_app_config().unwrap();
                    let mut redis_conn = redis_pool.get().await.unwrap();
                    let user_id = user_id.unwrap();
                    let blog_id = 1_i64;
                    let (cache_key, token_id, _) = get_token(&config.token_salt);

                    insert_login_token(
                        &cache_key,
                        &BlogLoginTokenData {
                            uid: user_id,
                            bid: blog_id,
                            persistent: true,
                            loc: None,
                            device: None,
                        },
                        &mut *redis_conn,
                    )
                    .await
                    .unwrap();

                    let response = client
                        .verify_blog_login(Request::new(VerifyBlogLoginRequest {
                            blog_identifier: blog_id.to_string(),
                            token: token_id.to_string(),
                            host: "invalid.com".to_string(),
                        }))
                        .await;

                    assert!(response.is_ok());

                    let response = response.unwrap().into_inner();

                    assert_eq!(response.is_token_valid, false);
                }),
            )
            .await;
        }

        #[test_context(RedisTestContext)]
        #[sqlx::test(fixtures("verify_blog_login"))]
        async fn can_reject_verification_for_unmatched_blog_id(
            _ctx: &mut RedisTestContext,
            pool: PgPool,
        ) {
            test_grpc_service(
                pool,
                true,
                Box::new(|mut client, _, redis_pool, user_id| async move {
                    let config = get_app_config().unwrap();
                    let mut redis_conn = redis_pool.get().await.unwrap();
                    let user_id = user_id.unwrap();
                    let blog_id = 10_i64; // Invalid blog ID.
                    let domain = "test.com";
                    let (cache_key, token_id, _) = get_token(&config.token_salt);

                    insert_login_token(
                        &cache_key,
                        &BlogLoginTokenData {
                            uid: user_id,
                            bid: blog_id,
                            persistent: true,
                            loc: None,
                            device: None,
                        },
                        &mut *redis_conn,
                    )
                    .await
                    .unwrap();

                    let response = client
                        .verify_blog_login(Request::new(VerifyBlogLoginRequest {
                            blog_identifier: "test-blog".to_string(),
                            token: token_id.to_string(),
                            host: domain.to_string(),
                        }))
                        .await;

                    assert!(response.is_ok());

                    let response = response.unwrap().into_inner();

                    assert_eq!(response.is_token_valid, false);
                }),
            )
            .await;
        }

        #[test_context(RedisTestContext)]
        #[sqlx::test(fixtures("verify_blog_login"))]
        async fn can_reject_verification_for_soft_deleted_blog(
            _ctx: &mut RedisTestContext,
            pool: PgPool,
        ) {
            test_grpc_service(
                pool,
                true,
                Box::new(|mut client, pool, redis_pool, user_id| async move {
                    let config = get_app_config().unwrap();
                    let mut redis_conn = redis_pool.get().await.unwrap();
                    let user_id = user_id.unwrap();
                    let blog_id = 1_i64;
                    let domain = "test.com";
                    let (cache_key, token_id, _) = get_token(&config.token_salt);

                    insert_login_token(
                        &cache_key,
                        &BlogLoginTokenData {
                            uid: user_id,
                            bid: blog_id,
                            persistent: true,
                            loc: None,
                            device: None,
                        },
                        &mut *redis_conn,
                    )
                    .await
                    .unwrap();

                    // Soft-delete the blog.
                    let result = sqlx::query(
                        r#"
UPDATE blogs
SET deleted_at = NOW()
WHERE id = $1
"#,
                    )
                    .bind(blog_id)
                    .execute(&pool)
                    .await
                    .unwrap();

                    assert_eq!(result.rows_affected(), 1);

                    let response = client
                        .verify_blog_login(Request::new(VerifyBlogLoginRequest {
                            blog_identifier: blog_id.to_string(),
                            token: token_id.to_string(),
                            host: domain.to_string(),
                        }))
                        .await;

                    assert!(response.is_err());
                    assert_eq!(response.unwrap_err().code(), Code::NotFound);
                }),
            )
            .await;
        }

        #[test_context(RedisTestContext)]
        #[sqlx::test(fixtures("verify_blog_login"))]
        async fn can_clear_overflowing_sessions_on_verification(
            _ctx: &mut RedisTestContext,
            pool: PgPool,
        ) {
            test_grpc_service(
                pool,
                true,
                Box::new(|mut client, _, redis_pool, user_id| async move {
                    let config = get_app_config().unwrap();
                    let mut redis_conn = redis_pool.get().await.unwrap();
                    let user_id = user_id.unwrap();
                    let blog_id = 1_i64;
                    let domain = "test.com";
                    let (cache_key, token_id, _) = get_token(&config.token_salt);

                    insert_login_token(
                        &cache_key,
                        &BlogLoginTokenData {
                            uid: user_id,
                            bid: blog_id,
                            persistent: true,
                            loc: None,
                            device: None,
                        },
                        &mut *redis_conn,
                    )
                    .await
                    .unwrap();

                    // Create 10 sessions.
                    for _ in 0..10 {
                        let _: () = redis_conn
                            .set(
                                &format!(
                                    "{}:{}:{}",
                                    RedisNamespace::Session,
                                    user_id,
                                    Uuid::new_v4()
                                ),
                                &rmp_serde::to_vec_named(&UserSession {
                                    user_id,
                                    ..Default::default()
                                })
                                .unwrap(),
                            )
                            .await
                            .unwrap();
                    }

                    let sessions = get_user_sessions(&redis_pool, user_id).await.unwrap();

                    assert_eq!(sessions.len(), 10);

                    // Send verification request.
                    let response = client
                        .verify_blog_login(Request::new(VerifyBlogLoginRequest {
                            blog_identifier: blog_id.to_string(),
                            token: token_id.to_string(),
                            host: domain.to_string(),
                        }))
                        .await;

                    assert!(response.is_ok());

                    let response = response.unwrap().into_inner();

                    assert_eq!(response.is_token_valid, true);

                    // Should remove previous sessions.
                    let sessions = get_user_sessions(&redis_pool, user_id).await.unwrap();

                    assert_eq!(sessions.len(), 1);
                }),
            )
            .await;
        }
    }
}
