use crate::{
    AppState,
    constants::notification_entity_type::NotificationEntityType,
    error::{
        AppError,
        ToastErrorResponse,
    },
    middlewares::identity::identity::Identity,
    utils::{
        clear_user_sessions::clear_user_sessions,
        get_client_device::get_client_device,
        get_client_location::get_client_location,
        get_user_sessions::get_user_sessions,
    },
};
use actix_http::HttpMessage;
use actix_web::{
    HttpRequest,
    HttpResponse,
    post,
    web,
};
use actix_web_validator::Json;
use argon2::{
    Argon2,
    PasswordHasher,
    password_hash::SaltString,
};
use serde::{
    Deserialize,
    Serialize,
};
use sqlx::Row;
use std::net::IpAddr;
use storiny_session::{
    Session,
    config::SessionLifecycle,
};
use tracing::debug;
use url::Url;
use validator::Validate;

#[derive(Deserialize, Validate)]
struct Fragments {
    blog_id: String,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
struct Request {
    #[validate(length(equal = 48, message = "Invalid token length"))]
    token: String,
}

#[derive(Debug, Clone, Serialize)]
struct Response {
    result: String,
}

#[post("/v1/blogs/{blog_id}/verify-login")]
#[tracing::instrument(name = "POST /v1/blogs/{blog_id}/verify-login", skip_all, err)]
async fn post(
    req: HttpRequest,
    payload: Json<Request>,
    data: web::Data<AppState>,
    path: web::Path<Fragments>,
    session: Session,
) -> Result<HttpResponse, AppError> {
    let blog_id = path
        .blog_id
        .parse::<i64>()
        .map_err(|_| AppError::from("Invalid blog ID"))?;
    let token = &payload.token;
    let mut req_host: Option<String> = None;

    if let Some(origin) = req.headers().get(actix_http::header::ORIGIN) {
        if let Ok(url) = Url::parse(origin.to_str().unwrap_or_default()) {
            if let Some(domain) = url.domain() {
                req_host = Some(domain.strip_prefix("www.").unwrap_or(domain).to_string());
            }
        }
    }

    if req_host.is_none() {
        return Err(AppError::InternalError("missing host name".to_string()));
    }

    let pg_pool = &data.db_pool;
    let mut txn = pg_pool.begin().await?;

    let blog = sqlx::query(
        r#"
SELECT domain
FROM blogs
WHERE
    id = $1
    AND deleted_at IS NULL
"#,
    )
    .bind(blog_id)
    .fetch_one(&mut *txn)
    .await
    .map_err(|error| {
        if matches!(error, sqlx::Error::RowNotFound) {
            AppError::ToastError(ToastErrorResponse::new(None, "Unknown blog"))
        } else {
            AppError::SqlxError(error)
        }
    })?;

    if blog.get::<Option<String>, _>("domain") != req_host {
        return Err(AppError::ToastError(ToastErrorResponse::new(
            None,
            "Blog domain does not match",
        )));
    }

    let salt = SaltString::from_b64(&data.config.token_salt)
        .map_err(|error| AppError::InternalError(error.to_string()))?;

    let hashed_token = Argon2::default()
        .hash_password(token.as_bytes(), &salt)
        .map_err(|error| AppError::InternalError(format!("unable to hash the token: {error:?}")))?;

    let (user_id, is_persistent_session) = match sqlx::query(
        r#"
DELETE FROM blog_login_tokens
WHERE
    id = $1
    AND blog_id = $2
    AND expires_at > NOW()
RETURNING user_id, is_persistent_session
"#,
    )
    .bind(hashed_token.to_string())
    .bind(blog_id)
    .fetch_one(&mut *txn)
    .await
    {
        Ok(row) => {
            let user_id = row.get::<i64, _>("user_id");
            let is_persistent_session = row.get::<bool, _>("is_persistent_session");

            (user_id, is_persistent_session)
        }
        Err(error) => {
            if matches!(error, sqlx::Error::RowNotFound) {
                return Ok(HttpResponse::Ok().json(Response {
                    result: "invalid_token".to_string(),
                }));
            }

            return Err(AppError::from(error));
        }
    };

    // Proceed with login

    let mut client_device_value = "Unknown device".to_string();
    let mut client_location_value: Option<String> = None;

    // Insert additional data to the session.
    {
        if let Ok(domain) = serde_json::to_value(req_host.clone().unwrap_or_default()) {
            session.insert("domain", domain);
        }

        if let Some(ip) = req.connection_info().realip_remote_addr() {
            if let Ok(parsed_ip) = ip.parse::<IpAddr>() {
                if let Some(client_location_result) = get_client_location(parsed_ip, &data.geo_db) {
                    client_location_value = Some(client_location_result.display_name.to_string());

                    if let Ok(client_location) = serde_json::to_value(client_location_result) {
                        session.insert("location", client_location);
                    }
                }
            }
        }

        if let Some(ua_header) = req.headers().get("user-agent") {
            if let Ok(ua) = ua_header.to_str() {
                let client_device_result = get_client_device(ua, &data.ua_parser);
                client_device_value = client_device_result.display_name.to_string();

                if let Ok(client_device) = serde_json::to_value(client_device_result) {
                    session.insert("device", client_device);
                }
            }
        }
    }

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
    .bind(if let Some(location) = client_location_value {
        format!("{client_device_value}:{location}")
    } else {
        client_device_value
    })
    .execute(&mut *txn)
    .await?;

    // Session cookie domain
    session.set_cookie_domain(Some(req_host.unwrap_or_default()));

    // Session lifecycle depends on the `is_persistent_session` value.
    session.set_lifecycle(if is_persistent_session {
        SessionLifecycle::PersistentSession
    } else {
        SessionLifecycle::BrowserSession
    });

    // Check if the user maintains more than or equal to 10 sessions, and
    // delete all the previous sessions if the current number of active
    // sessions for the user exceeds the per user session limit (10).
    match get_user_sessions(&data.redis, user_id).await {
        Ok(sessions) => {
            if sessions.len() >= 10 {
                match clear_user_sessions(&data.redis, user_id).await {
                    Ok(_) => {
                        debug!(
                            "cleared {} overflowing sessions for the user",
                            sessions.len()
                        );
                    }
                    Err(error) => {
                        return Err(AppError::InternalError(format!(
                            "unable to clear the overflowing sessions for the user: {:?}",
                            error
                        )));
                    }
                };
            }
        }
        Err(error) => {
            return Err(AppError::InternalError(format!(
                "unable to fetch the sessions for the user: {:?}",
                error
            )));
        }
    };

    let login_result = Identity::login(&req.extensions(), user_id);

    match login_result {
        Ok(_) => {
            txn.commit().await?;

            debug!("user logged in to blog");

            Ok(HttpResponse::Ok().json(Response {
                result: "success".to_string(),
            }))
        }
        Err(error) => Err(AppError::InternalError(format!(
            "identity error: {:?}",
            error
        ))),
    }
}

pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(post);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::get_app_config,
        constants::{
            redis_namespaces::RedisNamespace,
            session_cookie::SESSION_COOKIE_NAME,
        },
        routes::init::v1::auth::login::{
            Request as LoginRequest,
            Response as LoginResponse,
            post as login_post,
            tests::{
                get as test_login_get,
                get_sample_email_and_password,
            },
        },
        test_utils::{
            RedisTestContext,
            assert_response_body_text,
            assert_toast_error_response,
            init_app_for_test,
            res_to_string,
        },
        utils::{
            get_client_device::ClientDevice,
            get_client_location::ClientLocation,
            get_user_sessions::UserSession,
        },
    };
    use actix_web::{
        Responder,
        services,
        test,
    };
    use argon2::PasswordHasher;
    use redis::AsyncCommands;
    use sqlx::PgPool;
    use std::net::{
        Ipv4Addr,
        SocketAddr,
        SocketAddrV4,
    };
    use storiny_macros::test_context;
    use uuid::Uuid;

    #[sqlx::test]
    async fn can_verify_login(pool: PgPool) -> sqlx::Result<()> {
        let mut conn = pool.acquire().await?;
        let app = init_app_for_test(services![login_post, post], pool, false, false, None)
            .await
            .0;

        let (email, password_hash, password) = get_sample_email_and_password();

        // Insert the user and blog.
        let blog = sqlx::query(
            r#"
WITH inserted_user AS (
    INSERT INTO users (name, username, email, password, email_verified)
    VALUES ($1, $2, $3, $4, TRUE)
    RETURNING id
)
INSERT INTO blogs (name, slug, domain, user_id)
VALUES ('Sample blog', 'sample_blog', 'test.com', (SELECT id FROM inserted_user))
RETURNING id
"#,
        )
        .bind("Sample user".to_string())
        .bind("sample_user".to_string())
        .bind(email.to_string())
        .bind(password_hash)
        .fetch_one(&mut *conn)
        .await?;

        let blog_id = blog.get::<i64, _>("id");

        // Send a login request.
        let req = test::TestRequest::post()
            .uri("/v1/auth/login")
            .set_json(LoginRequest {
                email: email.to_string(),
                password: password.to_string(),
                remember_me: true,
                code: None,
                blog_domain: Some("test.com".to_string()),
            })
            .to_request();
        let res = test::call_service(&app, req).await;

        assert!(res.status().is_success());

        let json = serde_json::from_str::<LoginResponse>(&res_to_string(res).await).unwrap();

        assert_eq!(json.result, "success".to_string());
        assert!(json.blog_token.is_some());

        let login_token = json.blog_token.unwrap();

        // Verify login token.
        let req = test::TestRequest::post()
            .append_header(("origin", "https://test.com"))
            .uri(&format!("/v1/blogs/{blog_id}/verify-login"))
            .set_json(Request { token: login_token })
            .to_request();
        let res = test::call_service(&app, req).await;

        assert!(res.status().is_success());
        assert_response_body_text(
            res,
            &serde_json::to_string(&Response {
                result: "success".to_string(),
            })
            .unwrap_or_default(),
        )
        .await;

        // Should delete login token.
        let result = sqlx::query(
            r#"
SELECT EXISTS (
    SELECT
        1
    FROM
        blog_login_tokens
    WHERE
        blog_id = $1
   )
"#,
        )
        .bind(blog_id)
        .fetch_one(&mut *conn)
        .await?;

        assert!(!result.get::<bool, _>("exists"));

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
        .fetch_one(&mut *conn)
        .await?;

        assert!(result.get::<bool, _>("exists"));

        // Should also update the `last_login_at` column.
        let result = sqlx::query(
            r#"
SELECT last_login_at FROM users
WHERE username = $1
"#,
        )
        .bind("sample_user")
        .fetch_one(&mut *conn)
        .await?;

        assert!(
            result
                .get::<Option<OffsetDateTime>, _>("last_login_at")
                .is_some()
        );

        Ok(())
    }

    #[sqlx::test]
    async fn can_reject_login_from_unmatched_host(pool: PgPool) -> sqlx::Result<()> {
        let mut conn = pool.acquire().await?;
        let config = get_app_config().unwrap();
        let app = init_app_for_test(post, pool, false, false, None).await.0;
        let (token_id, hashed_token) = generate_hashed_token(&config.token_salt).unwrap();

        // Insert data.
        let blog = sqlx::query(
            r#"
WITH inserted_user AS (
    INSERT INTO users (name, username, email, email_verified)
    VALUES ('Sample user', 'sample_user', 'sample@example.com', TRUE)
    RETURNING id
), inserted_blog AS (
    INSERT INTO blogs (name, slug, domain, user_id)
    VALUES ('Sample blog', 'sample_blog', 'test.com', (SELECT id FROM inserted_user))
    RETURNING id
)
INSERT INTO blog_login_tokens (id, user_id, blog_id, expires_at)
VALUES ($1, (SELECT id FROM inserted_user), (SELECT id FROM inserted_blog), NOW())
RETURNING blog_id
"#,
        )
        .bind(&hashed_token)
        .fetch_one(&mut *conn)
        .await?;

        let blog_id = blog.get::<i64, _>("id");

        // Try to verify login token.
        let req = test::TestRequest::post()
            .append_header(("origin", "https://invalid.com"))
            .uri(&format!("/v1/blogs/{blog_id}/verify-login"))
            .set_json(Request { token: token_id })
            .to_request();
        let res = test::call_service(&app, req).await;

        assert!(res.status().is_client_error());
        assert_toast_error_response(res, "Blog domain does not match").await;

        Ok(())
    }

    #[sqlx::test]
    async fn can_reject_login_for_expired_token(pool: PgPool) -> sqlx::Result<()> {
        let mut conn = pool.acquire().await?;
        let config = get_app_config().unwrap();
        let app = init_app_for_test(post, pool, false, false, None).await.0;
        let (token_id, hashed_token) = generate_hashed_token(&config.token_salt).unwrap();

        // Insert an expired token.
        let blog = sqlx::query(
            r#"
WITH inserted_user AS (
    INSERT INTO users (name, username, email, email_verified)
    VALUES ('Sample user', 'sample_user', 'sample@example.com', TRUE)
    RETURNING id
), inserted_blog AS (
    INSERT INTO blogs (name, slug, domain, user_id)
    VALUES ('Sample blog', 'sample_blog', 'test.com', (SELECT id FROM inserted_user))
    RETURNING id
)
INSERT INTO blog_login_tokens (id, user_id, blog_id, expires_at)
VALUES ($1, (SELECT id FROM inserted_user), (SELECT id FROM inserted_blog), $2)
RETURNING blog_id
"#,
        )
        .bind(&hashed_token)
        .bind(OffsetDateTime::now_utc() - Duration::days(1)) // Yesterday
        .fetch_one(&mut *conn)
        .await?;

        let blog_id = blog.get::<i64, _>("id");

        // Try to verify login token.
        let req = test::TestRequest::post()
            .append_header(("origin", "https://test.com"))
            .uri(&format!("/v1/blogs/{blog_id}/verify-login"))
            .set_json(Request { token: token_id })
            .to_request();
        let res = test::call_service(&app, req).await;

        assert!(res.status().is_success());
        assert_response_body_text(
            res,
            &serde_json::to_string(&Response {
                result: "invalid_token".to_string(),
            })
            .unwrap_or_default(),
        )
        .await;

        Ok(())
    }

    mod serial {
        use super::*;

        #[test_context(RedisTestContext)]
        #[sqlx::test]
        async fn can_clear_overflowing_sessions_on_login(
            ctx: &mut RedisTestContext,
            pool: PgPool,
        ) -> sqlx::Result<()> {
            let redis_pool = &ctx.redis_pool;
            let mut redis_conn = redis_pool.get().await.unwrap();
            let mut conn = pool.acquire().await?;
            let (app, _, user_id) =
                init_app_for_test(services![login_post, post], pool, true, true, None).await;

            let (email, password_hash, password) = get_sample_email_and_password();

            // Create 10 sessions (one is already created from `init_app_for_test`).
            for _ in 0..9 {
                let _: () = redis_conn
                    .set(
                        &format!(
                            "{}:{}:{}",
                            RedisNamespace::Session,
                            user_id.unwrap(),
                            Uuid::new_v4()
                        ),
                        &rmp_serde::to_vec_named(&UserSession {
                            user_id: user_id.unwrap(),
                            ..Default::default()
                        })
                        .unwrap(),
                    )
                    .await
                    .unwrap();
            }

            let sessions = get_user_sessions(redis_pool, user_id.unwrap())
                .await
                .unwrap();

            assert_eq!(sessions.len(), 10);

            // Insert the user and blog.
            let blog = sqlx::query(
                r#"
WITH inserted_user AS (
    INSERT INTO users (id, name, username, email, password, email_verified)
    VALUES ($1, $2, $3, $4, $5, TRUE)
)
INSERT INTO blogs (name, slug, domain, user_id)
VALUES ('Sample blog', 'sample_blog', 'test.com', $1)
RETURNING id
"#,
            )
            .bind(user_id.unwrap())
            .bind("Sample user".to_string())
            .bind("sample_user".to_string())
            .bind(email.to_string())
            .bind(password_hash)
            .fetch_one(&mut *conn)
            .await?;

            let blog_id = blog.get::<i64, _>("id");

            // Send login request.
            let req = test::TestRequest::post()
                .uri("/v1/auth/login")
                .set_json(LoginRequest {
                    email: email.to_string(),
                    password: password.to_string(),
                    remember_me: true,
                    code: None,
                    blog_domain: Some("test.com".to_string()),
                })
                .to_request();
            let res = test::call_service(&app, req).await;

            assert!(res.status().is_success());

            let json = serde_json::from_str::<LoginResponse>(&res_to_string(res).await).unwrap();

            assert_eq!(json.result, "success".to_string());
            assert!(json.blog_token.is_some());

            let login_token = json.blog_token.unwrap();

            // Verify login token.
            let req = test::TestRequest::post()
                .uri(&format!("/v1/blogs/{blog_id}/verify-login"))
                .set_json(Request { token: login_token })
                .to_request();
            let res = test::call_service(&app, req).await;

            assert!(res.status().is_success());
            assert_response_body_text(
                res,
                &serde_json::to_string(&Response {
                    result: "success".to_string(),
                })
                .unwrap_or_default(),
            )
            .await;

            // Should remove previous sessions.
            let sessions = get_user_sessions(redis_pool, user_id.unwrap())
                .await
                .unwrap();

            assert_eq!(sessions.len(), 1);

            Ok(())
        }

        #[test_context(RedisTestContext)]
        #[sqlx::test]
        async fn can_insert_client_device_and_location_into_the_session(
            _ctx: &mut RedisTestContext,
            pool: PgPool,
        ) -> sqlx::Result<()> {
            let mut conn = pool.acquire().await?;
            let app = init_app_for_test(
                services![test_login_get, login_post, post],
                pool,
                false,
                false,
                None,
            )
            .await
            .0;

            let (email, password_hash, password) = get_sample_email_and_password();

            // Insert the user and blog.
            let blog = sqlx::query(
                r#"
WITH inserted_user AS (
    INSERT INTO users (name, username, email, password, email_verified)
    VALUES ($1, $2, $3, $4, TRUE)
    RETURNING id
)
INSERT INTO blogs (name, slug, domain, user_id)
VALUES ('Sample blog', 'sample_blog', 'test.com', (SELECT id FROM inserted_user))
RETURNING id
"#,
            )
            .bind("Sample user".to_string())
            .bind("sample_user".to_string())
            .bind(email.to_string())
            .bind(password_hash)
            .fetch_one(&mut *conn)
            .await?;

            let blog_id = blog.get::<i64, _>("id");

            // Send login request.
            let req = test::TestRequest::post()
                .uri("/v1/auth/login")
                .set_json(LoginRequest {
                    email: email.to_string(),
                    password: password.to_string(),
                    remember_me: true,
                    code: None,
                    blog_domain: Some("test.com".to_string()),
                })
                .to_request();
            let res = test::call_service(&app, req).await;

            assert!(res.status().is_success());

            let json = serde_json::from_str::<LoginResponse>(&res_to_string(res).await).unwrap();

            assert_eq!(json.result, "success".to_string());
            assert!(json.blog_token.is_some());

            let login_token = json.blog_token.unwrap();

            // Verify login token.
            let req = test::TestRequest::post()
                .peer_addr(SocketAddr::from(SocketAddrV4::new(
                    Ipv4Addr::new(8, 8, 8, 8),
                    8080,
                )))
                .append_header(("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:40.0) Gecko/20100101 Firefox/40.0"))
                .append_header(("origin", "https://test.com"))
                .uri(&format!("/v1/blogs/{blog_id}/verify-login"))
                .set_json(Request { token: login_token })
                .to_request();
            let res = test::call_service(&app, req).await;

            let cookie_value = res
                .response()
                .cookies()
                .find(|cookie| cookie.name() == SESSION_COOKIE_NAME);

            assert!(res.status().is_success());
            assert!(cookie_value.is_some());

            let cookie_value = cookie_value.unwrap();

            // Should use the correct domain.
            assert_eq!(cookie_value.domain(), Some("test.com"));

            let req = test::TestRequest::get()
                .cookie(cookie_value)
                .uri("/get-login-details")
                .to_request();
            let res = test::call_service(&app, req).await;

            #[derive(Deserialize)]
            struct ClientSession {
                device: Option<ClientDevice>,
                location: Option<ClientLocation>,
                domain: Option<String>,
            }

            let client_session = test::read_body_json::<ClientSession, _>(res).await;

            assert!(client_session.device.is_some());
            assert!(client_session.location.is_some());
            assert_eq!(client_session.domain, Some("test.com".to_string()));

            Ok(())
        }
    }
}
