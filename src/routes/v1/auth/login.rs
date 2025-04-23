use crate::{
    AppState,
    constants::{
        blog_domain_regex::BLOG_DOMAIN_REGEX,
        notification_entity_type::NotificationEntityType,
        resource_lock::ResourceLock,
        user_flag::UserFlag,
    },
    error::{
        AppError,
        FormErrorResponse,
        ToastErrorResponse,
    },
    middlewares::identity::identity::Identity,
    utils::{
        clear_user_sessions::clear_user_sessions,
        flag::{
            Flag,
            Mask,
        },
        generate_hashed_token::generate_hashed_token,
        generate_totp::generate_totp,
        get_client_device::get_client_device,
        get_client_location::get_client_location,
        get_user_sessions::get_user_sessions,
        incr_resource_lock_attempts::incr_resource_lock_attempts,
        is_resource_locked::is_resource_locked,
        reset_resource_lock::reset_resource_lock,
    },
};
use actix_http::HttpMessage;
use actix_web::{
    HttpRequest,
    HttpResponse,
    http::StatusCode,
    post,
    web,
};
use actix_web_validator::{
    Json,
    QsQuery,
};
use argon2::{
    Argon2,
    PasswordHash,
    PasswordVerifier,
};
use serde::{
    Deserialize,
    Serialize,
};
use sqlx::{
    Postgres,
    Row,
    Transaction,
};
use std::net::IpAddr;
use storiny_session::{
    Session,
    config::SessionLifecycle,
};
use time::{
    Duration,
    OffsetDateTime,
};
use totp_rs::Secret;
use tracing::{
    debug,
    error,
    trace,
};
use url::Url;
use validator::Validate;

// This struct is public because it is used by `blogs/verify-login` route.
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct Request {
    #[validate(email(message = "Invalid e-mail"))]
    #[validate(length(min = 3, max = 300, message = "Invalid e-mail length"))]
    pub email: String,
    #[validate(length(min = 6, max = 64, message = "Invalid password length"))]
    pub password: String,
    pub remember_me: bool,
    #[validate(length(min = 6, max = 12, message = "Invalid authentication code"))]
    pub code: Option<String>,
    #[validate(regex = "BLOG_DOMAIN_REGEX")]
    #[validate(length(min = 3, max = 512, message = "Invalid blog domain"))]
    pub blog_domain: Option<String>,
}

// This struct is public because it is used by `blogs/verify-login` route.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub result: String,
    pub is_first_login: bool,
    pub blog_token: Option<String>,
}

#[derive(Deserialize, Validate)]
struct QueryParams {
    bypass: Option<String>,
}

#[post("/v1/auth/login")]
#[tracing::instrument(
    name = "POST /v1/auth/login",
    skip_all,
    fields(
        email = %payload.email,
        remember_me = %payload.remember_me,
        blog_domain = tracing::field::Empty,
        bypass = query.bypass
    )
)]
async fn post(
    payload: Json<Request>,
    req: HttpRequest,
    query: QsQuery<QueryParams>,
    data: web::Data<AppState>,
    session: Session,
) -> Result<HttpResponse, AppError> {
    if is_resource_locked(&data.redis, ResourceLock::Login, &payload.email).await? {
        return Err(ToastErrorResponse::new(
            Some(StatusCode::TOO_MANY_REQUESTS),
            "Login attempts for this email are currently rate-limited. Try again later.",
        )
        .into());
    }

    let pg_pool = &data.db_pool;
    let mut txn = pg_pool.begin().await?;
    let should_bypass = query.bypass == Some("true".to_string());

    let user = sqlx::query(
        r#"
SELECT
    id,
    username,
    password,
    email_verified,
    public_flags,
    deactivated_at,
    deleted_at,
    mfa_enabled,
    mfa_secret,
    last_login_at
FROM users
WHERE email = $1
"#,
    )
    .bind(&payload.email)
    .fetch_one(&mut *txn)
    .await
    .map_err(|error| {
        if matches!(error, sqlx::Error::RowNotFound) {
            AppError::ToastError(ToastErrorResponse::new(
                Some(StatusCode::UNAUTHORIZED),
                "Invalid e-mail or password",
            ))
        } else {
            AppError::SqlxError(error)
        }
    })?;

    let is_first_login = user
        .get::<Option<OffsetDateTime>, _>("last_login_at")
        .is_none();
    let user_id = user.get::<i64, _>("id");

    // MFA check
    if user.get::<bool, _>("mfa_enabled") {
        debug!("checking mfa for the user");

        if payload.code.is_none() {
            return Err(ToastErrorResponse::new(
                Some(StatusCode::UNAUTHORIZED),
                "Missing authentication code",
            )
            .into());
        }

        let authentication_code = payload.code.clone().unwrap_or_default();

        match authentication_code.chars().count() {
            // Recovery code
            12 => {
                debug!("user provided a recovery/backup code");

                let result = sqlx::query(
                    r#"
SELECT EXISTS (
    SELECT 1 FROM mfa_recovery_codes
    WHERE
        code = $1
        AND user_id = $2
        AND used_at IS NULL
)
"#,
                )
                .bind(&authentication_code)
                .bind(user_id)
                .fetch_one(&mut *txn)
                .await?;

                if !result.get::<bool, _>("exists") {
                    // Increment the login attempts.
                    incr_resource_lock_attempts(&data.redis, ResourceLock::Login, &payload.email)
                        .await?;

                    return Err(FormErrorResponse::new(
                        None,
                        vec![("code", "Invalid authentication code")],
                    )
                    .into());
                }

                // Mark the code as used.
                sqlx::query(
                    r#"
UPDATE mfa_recovery_codes
SET used_at = NOW()
WHERE code = $1 AND user_id = $2
"#,
                )
                .bind(&authentication_code)
                .bind(user_id)
                .execute(&mut *txn)
                .await?;
            }
            // TOTP code
            6 => {
                debug!("user provided a TOTP authentication code");

                let mfa_secret = user
                    .get::<Option<String>, _>("mfa_secret")
                    .unwrap_or_default();
                let secret_as_bytes = Secret::Encoded(mfa_secret)
                    .to_bytes()
                    .map_err(|error| AppError::InternalError(error.to_string()))?;
                let totp = generate_totp(secret_as_bytes, &user.get::<String, _>("username"))
                    .map_err(|error| AppError::InternalError(error.to_string()))?;

                let is_valid = totp.check_current(&authentication_code).map_err(|error| {
                    error!(?error, "unable to validate the TOTP code");

                    AppError::ToastError(ToastErrorResponse::new(
                        Some(StatusCode::INTERNAL_SERVER_ERROR),
                        "Unable to validate the authentication code",
                    ))
                })?;

                if !is_valid {
                    // Increment the login attempts.
                    incr_resource_lock_attempts(&data.redis, ResourceLock::Login, &payload.email)
                        .await?;

                    return Err(FormErrorResponse::new(
                        None,
                        vec![("code", "Invalid authentication code")],
                    )
                    .into());
                }
            }
            // Other invalid cases
            _ => {
                return Err(FormErrorResponse::new(
                    None,
                    vec![("code", "Invalid authentication code")],
                )
                .into());
            }
        };
    }

    // Validate the password.
    {
        let user_password = user.get::<Option<String>, _>("password");

        // The password can be NULL if the user has created the account using a third-party service,
        // such as Apple or Google.
        if user_password.is_none() {
            return Err(ToastErrorResponse::new(
                Some(StatusCode::UNAUTHORIZED),
                "Invalid e-mail or password",
            )
            .into());
        }

        let user_password = user_password.unwrap_or_default();
        let password_hash = PasswordHash::new(&user_password)
            .map_err(|error| AppError::InternalError(error.to_string()))?;

        match Argon2::default().verify_password(payload.password.as_bytes(), &password_hash) {
            Ok(_) => {
                // The user is validated at this point, so it is safe to reset the login attempts.
                reset_resource_lock(&data.redis, ResourceLock::Login, &payload.email).await?;
            }
            Err(_) => {
                // Increment the login attempts.
                incr_resource_lock_attempts(&data.redis, ResourceLock::Login, &payload.email)
                    .await?;

                return Err(ToastErrorResponse::new(
                    Some(StatusCode::UNAUTHORIZED),
                    "Invalid e-mail or password",
                )
                .into());
            }
        }
    }

    // Check whether the user is suspended.
    {
        let public_flags = user.get::<i32, _>("public_flags");
        let user_flags = Flag::new(public_flags as u32);

        if user_flags.has_any_of(Mask::Multiple(vec![
            UserFlag::TemporarilySuspended,
            UserFlag::PermanentlySuspended,
        ])) {
            debug!("user has been suspended");

            return Ok(HttpResponse::Ok().json(Response {
                result: "suspended".to_string(),
                is_first_login,
                blog_token: None,
            }));
        }
    }

    // Check whether the user is soft-deleted.
    {
        let deleted_at = user.get::<Option<OffsetDateTime>, _>("deleted_at");

        if deleted_at.is_some() {
            debug!("user has been soft-deleted");

            if should_bypass {
                trace!("bypassing the soft-delete by restoring the user");

                sqlx::query(
                    r#"
UPDATE users
SET deleted_at = NULL
WHERE id = $1
"#,
                )
                .bind(user_id)
                .execute(&mut *txn)
                .await?;
            } else {
                return Ok(HttpResponse::Ok().json(Response {
                    result: "held_for_deletion".to_string(),
                    is_first_login,
                    blog_token: None,
                }));
            }
        }
    }

    // Check whether the user is deactivated.
    {
        let deactivated_at = user.get::<Option<OffsetDateTime>, _>("deactivated_at");

        if deactivated_at.is_some() {
            debug!("user has been deactivated");

            if should_bypass {
                trace!("bypassing the deactivation by reactivating the user");

                sqlx::query(
                    r#"
UPDATE users
SET deactivated_at = NULL
WHERE id = $1
"#,
                )
                .bind(user_id)
                .execute(&mut *txn)
                .await?;
            } else {
                return Ok(HttpResponse::Ok().json(Response {
                    result: "deactivated".to_string(),
                    is_first_login,
                    blog_token: None,
                }));
            }
        }
    }

    // Check whether the user's email address has been verified.
    {
        let email_verified = user.get::<bool, _>("email_verified");

        if !email_verified {
            debug!("user's email has not been verified yet");

            return Ok(HttpResponse::Ok().json(Response {
                result: "email_confirmation".to_string(),
                is_first_login,
                blog_token: None,
            }));
        }
    }

    // Handle blog login
    if let Some(domain) = &payload.blog_domain {
        tracing::Span::current().record("blog_domain", domain);

        if let Some(login_token) = handle_blog_login(
            domain,
            user_id,
            payload.remember_me,
            &data.config.token_salt,
            &mut txn,
        )
        .await?
        {
            txn.commit().await?;

            debug!("blog login token generated");

            return Ok(HttpResponse::Ok().json(Response {
                result: "success".to_string(),
                is_first_login: false,
                blog_token: Some(login_token),
            }));
        }
    }

    let mut client_device_value = "Unknown device".to_string();
    let mut client_location_value: Option<String> = None;

    // Insert additional data to the session.
    {
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

        if let Some(origin) = req.headers().get(actix_http::header::ORIGIN) {
            if let Ok(url) = Url::parse(origin.to_str().unwrap_or_default()) {
                if let Some(domain) = url.domain() {
                    match domain {
                        "storiny.com" => {}
                        "www.storiny.com" => {}
                        _ => {
                            if domain.chars().count() < 256 {
                                if let Ok(domain) = serde_json::to_value(domain) {
                                    session.insert("domain", domain);
                                }
                            }
                        }
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

    // Session lifecycle depends on the `remember_me` value.
    session.set_lifecycle(if payload.remember_me {
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

            debug!("user logged in");

            Ok(HttpResponse::Ok().json(Response {
                result: "success".to_string(),
                is_first_login,
                blog_token: None,
            }))
        }
        Err(error) => Err(AppError::InternalError(format!(
            "identity error: {:?}",
            error
        ))),
    }
}

/// Generates a login token for an external blog.
///
/// * `domain` - The blog's domain name.
/// * `user_id` - The ID of the user trying to log in.
/// * `token_salt` - The salt for generating login token.
/// * `persistent` - Whether to use a persistent browser session after login.
/// * `txn` - The Postgres transaction.
async fn handle_blog_login<'a>(
    domain: &str,
    user_id: i64,
    persistent: bool,
    token_salt: &str,
    txn: &mut Transaction<'a, Postgres>,
) -> Result<Option<String>, AppError> {
    let blog_result = sqlx::query(
        r#"
SELECT b.id
FROM blogs b
WHERE
    b.domain = $1
    AND b.deleted_at IS NULL
"#,
    )
    .bind(domain.to_string())
    .fetch_one(&mut **txn)
    .await;

    match blog_result {
        Ok(blog) => {
            let blog_id = blog.get::<i64, _>("id");

            // Generate a new login token.
            let (token_id, hashed_token) = generate_hashed_token(token_salt)?;

            // Delete old tokens
            sqlx::query(
                r#"
DELETE FROM blog_login_tokens
WHERE blog_id = $1 AND user_id = $2
"#,
            )
            .bind(blog_id)
            .bind(user_id)
            .execute(&mut **txn)
            .await?;

            sqlx::query(
                r#"
INSERT INTO blog_login_tokens (id, blog_id, user_id, is_persistent_session, expires_at)
VALUES ($1, $2, $3, $4, $5)
"#,
            )
            .bind(&hashed_token)
            .bind(blog_id)
            .bind(user_id)
            .bind(persistent)
            .bind(OffsetDateTime::now_utc() + Duration::minutes(3)) // 3 minutes
            .execute(&mut **txn)
            .await?;

            Ok(Some(token_id))
        }
        Err(error) => {
            if matches!(error, sqlx::Error::RowNotFound) {
                return Ok(None);
            }

            Err(AppError::from(error))
        }
    }
}

pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(post);
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{
        constants::{
            redis_namespaces::RedisNamespace,
            session_cookie::SESSION_COOKIE_NAME,
        },
        test_utils::{
            RedisTestContext,
            assert_form_error_response,
            assert_response_body_text,
            assert_toast_error_response,
            exceed_resource_lock_attempts,
            get_resource_lock_attempts,
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
        get,
        services,
        test,
    };
    use argon2::{
        PasswordHasher,
        password_hash::{
            SaltString,
            rand_core::OsRng,
        },
    };
    use redis::AsyncCommands;
    use serde_json::json;
    use sqlx::PgPool;
    use std::net::{
        Ipv4Addr,
        SocketAddr,
        SocketAddrV4,
    };
    use storiny_macros::test_context;
    use uuid::Uuid;

    /// Returns the device and session data present in the session for testing.
    #[get("/get-login-details")]
    pub async fn get(session: Session) -> impl Responder {
        let location = session.get::<ClientLocation>("location").unwrap();
        let device = session.get::<ClientDevice>("device").unwrap();
        let domain = session.get::<String>("domain").unwrap();

        HttpResponse::Ok().json(json!({
            "location": location,
            "device": device,
            "domain": domain
        }))
    }

    /// Returns a sample email and hashed password.
    pub fn get_sample_email_and_password() -> (String, String, String) {
        let password = "sample";
        let email = "someone@example.com";
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        (email.to_string(), password_hash, password.to_string())
    }

    #[sqlx::test]
    async fn can_login_using_valid_credentials(pool: PgPool) -> sqlx::Result<()> {
        let mut conn = pool.acquire().await?;
        let app = init_app_for_test(post, pool, false, false, None).await.0;

        let (email, password_hash, password) = get_sample_email_and_password();

        // Insert the user.
        sqlx::query(
            r#"
INSERT INTO users (name, username, email, password, email_verified)
VALUES ($1, $2, $3, $4, TRUE)
"#,
        )
        .bind("Sample user".to_string())
        .bind("sample_user".to_string())
        .bind(email.to_string())
        .bind(password_hash)
        .execute(&mut *conn)
        .await?;

        let req = test::TestRequest::post()
            .uri("/v1/auth/login")
            .set_json(Request {
                email: email.to_string(),
                password: password.to_string(),
                remember_me: true,
                code: None,
                blog_domain: None,
            })
            .to_request();
        let res = test::call_service(&app, req).await;

        assert!(res.status().is_success());
        assert_response_body_text(
            res,
            &serde_json::to_string(&Response {
                result: "success".to_string(),
                is_first_login: true, // Should be `true`.
                blog_token: None,
            })
            .unwrap_or_default(),
        )
        .await;

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
    async fn can_login_using_a_recovery_code(pool: PgPool) -> sqlx::Result<()> {
        let mut conn = pool.acquire().await?;
        let app = init_app_for_test(post, pool, false, false, None).await.0;

        let (email, password_hash, password) = get_sample_email_and_password();

        // Insert the user.
        sqlx::query(
            r#"
INSERT INTO users (id, name, username, email, password, email_verified, mfa_enabled)
VALUES ($1, $2, $3, $4, $5, TRUE, TRUE)
"#,
        )
        .bind(1_i64)
        .bind("Sample user".to_string())
        .bind("sample_user".to_string())
        .bind(email.to_string())
        .bind(password_hash)
        .execute(&mut *conn)
        .await?;

        // Insert a recovery code.
        sqlx::query(
            r#"
INSERT INTO mfa_recovery_codes(code, user_id)
VALUES ($1, $2)
"#,
        )
        .bind("0".repeat(12))
        .bind(1_i64)
        .execute(&mut *conn)
        .await?;

        let req = test::TestRequest::post()
            .uri("/v1/auth/login")
            .set_json(Request {
                email: email.to_string(),
                password: password.to_string(),
                remember_me: true,
                code: Some("0".repeat(12)),
                blog_domain: None,
            })
            .to_request();
        let res = test::call_service(&app, req).await;

        assert!(res.status().is_success());
        assert_response_body_text(
            res,
            &serde_json::to_string(&Response {
                result: "success".to_string(),
                is_first_login: true,
                blog_token: None,
            })
            .unwrap_or_default(),
        )
        .await;

        // Should mark the recovery code as used.
        let result = sqlx::query(
            r#"
SELECT used_at FROM mfa_recovery_codes
WHERE code = $1 AND user_id = $2
"#,
        )
        .bind("0".repeat(12))
        .bind(1_i64)
        .fetch_one(&mut *conn)
        .await?;

        assert!(result.get::<Option<OffsetDateTime>, _>("used_at").is_some());

        Ok(())
    }

    #[sqlx::test]
    async fn can_login_using_an_authentication_code(pool: PgPool) -> sqlx::Result<()> {
        let mut conn = pool.acquire().await?;
        let app = init_app_for_test(post, pool, false, false, None).await.0;
        let (email, password_hash, password) = get_sample_email_and_password();

        let mfa_secret = Secret::generate_secret();

        // Insert the user.
        sqlx::query(
            r#"
INSERT INTO users (
    name,
    username,
    email,
    password,
    email_verified,
    mfa_enabled,
    mfa_secret
)
VALUES ($1, $2, $3, $4, TRUE, TRUE, $5)
"#,
        )
        .bind("Sample user".to_string())
        .bind("sample_user".to_string())
        .bind(email.to_string())
        .bind(password_hash)
        .bind(mfa_secret.to_encoded().to_string())
        .execute(&mut *conn)
        .await?;

        // Generate an authentication code.
        let totp = generate_totp(mfa_secret.to_bytes().unwrap(), "sample_user").unwrap();

        let req = test::TestRequest::post()
            .uri("/v1/auth/login")
            .set_json(Request {
                email: email.to_string(),
                password: password.to_string(),
                remember_me: true,
                code: Some(totp.generate_current().unwrap()),
                blog_domain: None,
            })
            .to_request();
        let res = test::call_service(&app, req).await;

        assert!(res.status().is_success());
        assert_response_body_text(
            res,
            &serde_json::to_string(&Response {
                result: "success".to_string(),
                is_first_login: true,
                blog_token: None,
            })
            .unwrap_or_default(),
        )
        .await;

        Ok(())
    }

    #[sqlx::test]
    async fn can_return_is_first_login_flag(pool: PgPool) -> sqlx::Result<()> {
        let mut conn = pool.acquire().await?;
        let app = init_app_for_test(post, pool, false, false, None).await.0;

        let (email, password_hash, password) = get_sample_email_and_password();

        // Insert the user with a non-empty `last_login_at`.
        sqlx::query(
            r#"
INSERT INTO users (name, username, email, password, email_verified, last_login_at)
VALUES ($1, $2, $3, $4, TRUE, NOW())
"#,
        )
        .bind("Sample user".to_string())
        .bind("sample_user".to_string())
        .bind(email.to_string())
        .bind(password_hash)
        .execute(&mut *conn)
        .await?;

        let req = test::TestRequest::post()
            .uri("/v1/auth/login")
            .set_json(Request {
                email: email.to_string(),
                password: password.to_string(),
                remember_me: true,
                code: None,
                blog_domain: None,
            })
            .to_request();
        let res = test::call_service(&app, req).await;

        assert!(res.status().is_success());
        assert_response_body_text(
            res,
            &serde_json::to_string(&Response {
                result: "success".to_string(),
                is_first_login: false, // Should be false.
                blog_token: None,
            })
            .unwrap_or_default(),
        )
        .await;

        Ok(())
    }

    #[sqlx::test]
    async fn can_reject_a_login_request_with_invalid_email(pool: PgPool) -> sqlx::Result<()> {
        let mut conn = pool.acquire().await?;
        let app = init_app_for_test(post, pool, false, false, None).await.0;

        let (email, password_hash, password) = get_sample_email_and_password();

        // Insert the user.
        sqlx::query(
            r#"
INSERT INTO users (name, username, email, password)
VALUES ($1, $2, $3, $4)
"#,
        )
        .bind("Sample user".to_string())
        .bind("sample_user".to_string())
        .bind(email.to_string())
        .bind(password_hash)
        .execute(&mut *conn)
        .await?;

        let req = test::TestRequest::post()
            .uri("/v1/auth/login")
            .set_json(Request {
                email: "some_invalid_email@example.com".to_string(),
                password: password.to_string(),
                remember_me: true,
                code: None,
                blog_domain: None,
            })
            .to_request();
        let res = test::call_service(&app, req).await;

        assert!(res.status().is_client_error());
        assert_toast_error_response(res, "Invalid e-mail or password").await;

        Ok(())
    }

    #[sqlx::test]
    async fn can_reject_a_login_request_with_missing_password(pool: PgPool) -> sqlx::Result<()> {
        let mut conn = pool.acquire().await?;
        let app = init_app_for_test(post, pool, false, false, None).await.0;
        let (email, _, password) = get_sample_email_and_password();

        // Insert the user.
        sqlx::query(
            r#"
INSERT INTO users (name, username, email)
VALUES ($1, $2, $3)
"#,
        )
        .bind("Sample user".to_string())
        .bind("sample_user".to_string())
        .bind(email.to_string())
        .execute(&mut *conn)
        .await?;

        let req = test::TestRequest::post()
            .uri("/v1/auth/login")
            .set_json(Request {
                email: email.to_string(),
                password: password.to_string(),
                remember_me: true,
                code: None,
                blog_domain: None,
            })
            .to_request();
        let res = test::call_service(&app, req).await;

        assert!(res.status().is_client_error());
        assert_toast_error_response(res, "Invalid e-mail or password").await;

        Ok(())
    }

    #[sqlx::test]
    async fn can_reject_a_login_request_when_the_user_is_temporarily_suspended(
        pool: PgPool,
    ) -> sqlx::Result<()> {
        let mut conn = pool.acquire().await?;
        let app = init_app_for_test(post, pool, false, false, None).await.0;

        let (email, password_hash, password) = get_sample_email_and_password();
        let mut flags = Flag::new(0);
        flags.add_flag(UserFlag::TemporarilySuspended);

        // Insert the user
        sqlx::query(
            r#"
INSERT INTO users (name, username, email, password, public_flags)
VALUES ($1, $2, $3, $4, $5)
"#,
        )
        .bind("Sample user".to_string())
        .bind("sample_user".to_string())
        .bind(email.to_string())
        .bind(password_hash)
        .bind(flags.get_flags() as i32)
        .execute(&mut *conn)
        .await?;

        let req = test::TestRequest::post()
            .uri("/v1/auth/login")
            .set_json(Request {
                email: email.to_string(),
                password: password.to_string(),
                remember_me: true,
                code: None,
                blog_domain: None,
            })
            .to_request();
        let res = test::call_service(&app, req).await;

        assert!(res.status().is_success());
        assert_response_body_text(
            res,
            &serde_json::to_string(&Response {
                result: "suspended".to_string(),
                is_first_login: true,
                blog_token: None,
            })
            .unwrap(),
        )
        .await;

        Ok(())
    }

    #[sqlx::test]
    async fn can_reject_a_login_request_when_the_user_is_permanently_suspended(
        pool: PgPool,
    ) -> sqlx::Result<()> {
        let mut conn = pool.acquire().await?;
        let app = init_app_for_test(post, pool, false, false, None).await.0;

        let (email, password_hash, password) = get_sample_email_and_password();
        let mut flags = Flag::new(0);
        flags.add_flag(UserFlag::PermanentlySuspended);

        // Insert the user
        sqlx::query(
            r#"
INSERT INTO users (name, username, email, password, public_flags)
VALUES ($1, $2, $3, $4, $5)
"#,
        )
        .bind("Sample user".to_string())
        .bind("sample_user".to_string())
        .bind(email.to_string())
        .bind(password_hash)
        .bind(flags.get_flags() as i32)
        .execute(&mut *conn)
        .await?;

        let req = test::TestRequest::post()
            .uri("/v1/auth/login")
            .set_json(Request {
                email: email.to_string(),
                password: password.to_string(),
                remember_me: true,
                code: None,
                blog_domain: None,
            })
            .to_request();
        let res = test::call_service(&app, req).await;

        assert!(res.status().is_success());
        assert_response_body_text(
            res,
            &serde_json::to_string(&Response {
                result: "suspended".to_string(),
                is_first_login: true,
                blog_token: None,
            })
            .unwrap(),
        )
        .await;

        Ok(())
    }

    #[sqlx::test]
    async fn can_reject_a_login_request_when_the_user_is_deactivated(
        pool: PgPool,
    ) -> sqlx::Result<()> {
        let mut conn = pool.acquire().await?;
        let app = init_app_for_test(post, pool, false, false, None).await.0;

        let (email, password_hash, password) = get_sample_email_and_password();

        // Insert the user
        sqlx::query(
            r#"
INSERT INTO users (name, username, email, password)
VALUES ($1, $2, $3, $4)
"#,
        )
        .bind("Sample user".to_string())
        .bind("sample_user".to_string())
        .bind(email.to_string())
        .bind(password_hash)
        .execute(&mut *conn)
        .await?;

        // Deactivate the user.
        sqlx::query(
            r#"
UPDATE users
SET deactivated_at = NOW()
WHERE email = $1
"#,
        )
        .bind(email.to_string())
        .execute(&mut *conn)
        .await?;

        let req = test::TestRequest::post()
            .uri("/v1/auth/login")
            .set_json(Request {
                email: email.to_string(),
                password: password.to_string(),
                remember_me: true,
                code: None,
                blog_domain: None,
            })
            .to_request();
        let res = test::call_service(&app, req).await;

        assert!(res.status().is_success());
        assert_response_body_text(
            res,
            &serde_json::to_string(&Response {
                result: "deactivated".to_string(),
                is_first_login: true,
                blog_token: None,
            })
            .unwrap(),
        )
        .await;

        Ok(())
    }

    #[sqlx::test]
    async fn can_reject_a_login_request_when_the_user_is_soft_deleted(
        pool: PgPool,
    ) -> sqlx::Result<()> {
        let mut conn = pool.acquire().await?;
        let app = init_app_for_test(post, pool, false, false, None).await.0;

        let (email, password_hash, password) = get_sample_email_and_password();

        // Insert the user.
        sqlx::query(
            r#"
INSERT INTO users (name, username, email, password)
VALUES ($1, $2, $3, $4)
"#,
        )
        .bind("Sample user".to_string())
        .bind("sample_user".to_string())
        .bind(email.to_string())
        .bind(password_hash)
        .execute(&mut *conn)
        .await?;

        // Soft-delete the user
        sqlx::query(
            r#"
UPDATE users
SET deleted_at = NOW()
WHERE email = $1
"#,
        )
        .bind(email.to_string())
        .execute(&mut *conn)
        .await?;

        let req = test::TestRequest::post()
            .uri("/v1/auth/login")
            .set_json(Request {
                email: email.to_string(),
                password: password.to_string(),
                remember_me: true,
                code: None,
                blog_domain: None,
            })
            .to_request();
        let res = test::call_service(&app, req).await;

        assert!(res.status().is_success());
        assert_response_body_text(
            res,
            &serde_json::to_string(&Response {
                result: "held_for_deletion".to_string(),
                is_first_login: true,
                blog_token: None,
            })
            .unwrap(),
        )
        .await;

        Ok(())
    }

    #[sqlx::test]
    async fn can_reject_a_login_request_if_the_email_is_not_verified(
        pool: PgPool,
    ) -> sqlx::Result<()> {
        let mut conn = pool.acquire().await?;
        let app = init_app_for_test(post, pool, false, false, None).await.0;

        let (email, password_hash, password) = get_sample_email_and_password();

        // Insert the user.
        sqlx::query(
            r#"
INSERT INTO users (name, username, email, password)
VALUES ($1, $2, $3, $4)
"#,
        )
        .bind("Sample user".to_string())
        .bind("sample_user".to_string())
        .bind(email.to_string())
        .bind(password_hash)
        .execute(&mut *conn)
        .await?;

        let req = test::TestRequest::post()
            .uri("/v1/auth/login")
            .set_json(Request {
                email: email.to_string(),
                password: password.to_string(),
                remember_me: true,
                code: None,
                blog_domain: None,
            })
            .to_request();
        let res = test::call_service(&app, req).await;

        assert!(res.status().is_success());
        assert_response_body_text(
            res,
            &serde_json::to_string(&Response {
                result: "email_confirmation".to_string(),
                is_first_login: true,
                blog_token: None,
            })
            .unwrap(),
        )
        .await;

        Ok(())
    }

    #[sqlx::test]
    async fn can_reject_a_login_request_for_a_missing_authentication_code(
        pool: PgPool,
    ) -> sqlx::Result<()> {
        let mut conn = pool.acquire().await?;
        let app = init_app_for_test(post, pool, false, false, None).await.0;

        let (email, _, password) = get_sample_email_and_password();

        // Insert the user.
        sqlx::query(
            r#"
INSERT INTO users (name, username, email, mfa_enabled)
VALUES ($1, $2, $3, TRUE)
"#,
        )
        .bind("Sample user".to_string())
        .bind("sample_user".to_string())
        .bind(email.to_string())
        .execute(&mut *conn)
        .await?;

        let req = test::TestRequest::post()
            .uri("/v1/auth/login")
            .set_json(Request {
                email: email.to_string(),
                password: password.to_string(),
                remember_me: true,
                code: None,
                blog_domain: None,
            })
            .to_request();
        let res = test::call_service(&app, req).await;

        assert!(res.status().is_client_error());
        assert_toast_error_response(res, "Missing authentication code").await;

        Ok(())
    }

    #[sqlx::test]
    async fn can_reject_a_login_request_for_an_authentication_code_with_invalid_length(
        pool: PgPool,
    ) -> sqlx::Result<()> {
        let mut conn = pool.acquire().await?;
        let app = init_app_for_test(post, pool, false, false, None).await.0;

        let (email, _, password) = get_sample_email_and_password();

        // Insert the user.
        sqlx::query(
            r#"
INSERT INTO users (name, username, email, mfa_enabled)
VALUES ($1, $2, $3, TRUE)
"#,
        )
        .bind("Sample user".to_string())
        .bind("sample_user".to_string())
        .bind(email.to_string())
        .execute(&mut *conn)
        .await?;

        let req = test::TestRequest::post()
            .uri("/v1/auth/login")
            .set_json(Request {
                email: email.to_string(),
                password: password.to_string(),
                remember_me: true,
                code: Some("0".repeat(7)),
                blog_domain: None,
            })
            .to_request();
        let res = test::call_service(&app, req).await;

        assert!(res.status().is_client_error());
        assert_form_error_response(res, vec![("code", "Invalid authentication code")]).await;

        Ok(())
    }

    #[sqlx::test]
    async fn can_send_a_non_persistent_cookie_if_remember_me_is_set_to_false(
        pool: PgPool,
    ) -> sqlx::Result<()> {
        let mut conn = pool.acquire().await?;
        let app = init_app_for_test(services![get, post], pool, false, false, None)
            .await
            .0;

        let (email, password_hash, password) = get_sample_email_and_password();

        // Insert the user.
        sqlx::query(
            r#"
INSERT INTO users (name, username, email, password, email_verified)
VALUES ($1, $2, $3, $4, TRUE)
"#,
        )
        .bind("Sample user".to_string())
        .bind("sample_user".to_string())
        .bind(email.to_string())
        .bind(password_hash)
        .execute(&mut *conn)
        .await?;

        let req = test::TestRequest::post()
            .uri("/v1/auth/login")
            .set_json(Request {
                email: email.to_string(),
                password: password.to_string(),
                remember_me: false,
                code: None,
                blog_domain: None,
            })
            .to_request();
        let res = test::call_service(&app, req).await;

        let cookie_value = res
            .response()
            .cookies()
            .find(|cookie| cookie.name() == SESSION_COOKIE_NAME)
            .unwrap();

        assert!(res.status().is_success());
        // Should be non-persistent.
        assert!(cookie_value.max_age().is_none());

        Ok(())
    }

    #[sqlx::test]
    async fn can_send_a_persistent_cookie_if_remember_me_is_set_to_true(
        pool: PgPool,
    ) -> sqlx::Result<()> {
        let mut conn = pool.acquire().await?;
        let app = init_app_for_test(services![get, post], pool, false, false, None)
            .await
            .0;

        let (email, password_hash, password) = get_sample_email_and_password();

        // Insert the user.
        sqlx::query(
            r#"
INSERT INTO users (name, username, email, password, email_verified)
VALUES ($1, $2, $3, $4, TRUE)
"#,
        )
        .bind("Sample user".to_string())
        .bind("sample_user".to_string())
        .bind(email.to_string())
        .bind(password_hash)
        .execute(&mut *conn)
        .await?;

        let req = test::TestRequest::post()
            .uri("/v1/auth/login")
            .set_json(Request {
                email: email.to_string(),
                password: password.to_string(),
                remember_me: true,
                code: None,
                blog_domain: None,
            })
            .to_request();
        let res = test::call_service(&app, req).await;

        let cookie_value = res
            .response()
            .cookies()
            .find(|cookie| cookie.name() == SESSION_COOKIE_NAME)
            .unwrap();

        assert!(res.status().is_success());
        // Should be persistent.
        assert!(cookie_value.max_age().is_some());

        Ok(())
    }

    #[sqlx::test]
    async fn can_restore_and_login_a_soft_deleted_user_on_bypass(pool: PgPool) -> sqlx::Result<()> {
        let mut conn = pool.acquire().await?;
        let app = init_app_for_test(services![get, post], pool, false, false, None)
            .await
            .0;

        let (email, password_hash, password) = get_sample_email_and_password();

        // Insert the user
        sqlx::query(
            r#"
INSERT INTO users (name, username, email, password, email_verified)
VALUES ($1, $2, $3, $4, TRUE)
"#,
        )
        .bind("Sample user".to_string())
        .bind("sample_user".to_string())
        .bind(email.to_string())
        .bind(password_hash)
        .execute(&mut *conn)
        .await?;

        // Soft-delete the user.
        sqlx::query(
            r#"
UPDATE users
SET deleted_at = NOW()
WHERE email = $1
"#,
        )
        .bind(email.to_string())
        .execute(&mut *conn)
        .await?;

        let req = test::TestRequest::post()
            .uri("/v1/auth/login?bypass=true")
            .set_json(Request {
                email: email.to_string(),
                password: password.to_string(),
                remember_me: true,
                code: None,
                blog_domain: None,
            })
            .to_request();
        let res = test::call_service(&app, req).await;

        assert!(res.status().is_success());
        assert_response_body_text(
            res,
            &serde_json::to_string(&Response {
                result: "success".to_string(),
                is_first_login: true,
                blog_token: None,
            })
            .unwrap_or_default(),
        )
        .await;

        // User should be restored.
        let user_result = sqlx::query(
            r#"
SELECT deleted_at FROM users
WHERE email = $1
"#,
        )
        .bind(email.to_string())
        .fetch_one(&mut *conn)
        .await?;

        assert!(
            user_result
                .get::<Option<OffsetDateTime>, _>("deleted_at")
                .is_none()
        );

        Ok(())
    }

    #[sqlx::test]
    async fn can_reactivate_and_login_a_deactivated_user_on_bypass(
        pool: PgPool,
    ) -> sqlx::Result<()> {
        let mut conn = pool.acquire().await?;
        let app = init_app_for_test(services![get, post], pool, false, false, None)
            .await
            .0;

        let (email, password_hash, password) = get_sample_email_and_password();

        // Insert the user.
        sqlx::query(
            r#"
INSERT INTO users (name, username, email, password, email_verified)
VALUES ($1, $2, $3, $4, TRUE)
"#,
        )
        .bind("Sample user".to_string())
        .bind("sample_user".to_string())
        .bind(email.to_string())
        .bind(password_hash)
        .execute(&mut *conn)
        .await?;

        // Deactivate the user.
        sqlx::query(
            r#"
UPDATE users
SET deactivated_at = NOW()
WHERE email = $1
"#,
        )
        .bind(email.to_string())
        .execute(&mut *conn)
        .await?;

        let req = test::TestRequest::post()
            .uri("/v1/auth/login?bypass=true")
            .set_json(Request {
                email: email.to_string(),
                password: password.to_string(),
                remember_me: true,
                code: None,
                blog_domain: None,
            })
            .to_request();
        let res = test::call_service(&app, req).await;

        assert!(res.status().is_success());
        assert_response_body_text(
            res,
            &serde_json::to_string(&Response {
                result: "success".to_string(),
                is_first_login: true,
                blog_token: None,
            })
            .unwrap_or_default(),
        )
        .await;

        // User should be reactivated.
        let user_result = sqlx::query(
            r#"
SELECT deactivated_at FROM users
WHERE email = $1
"#,
        )
        .bind(email.to_string())
        .fetch_one(&mut *conn)
        .await?;

        assert!(
            user_result
                .get::<Option<OffsetDateTime>, _>("deactivated_at")
                .is_none()
        );

        Ok(())
    }

    // Blog login

    #[sqlx::test]
    async fn can_handle_invalid_blog(pool: PgPool) -> sqlx::Result<()> {
        let mut conn = pool.acquire().await?;
        let app = init_app_for_test(post, pool, false, false, None).await.0;

        let (email, password_hash, password) = get_sample_email_and_password();

        // Insert the user.
        sqlx::query(
            r#"
INSERT INTO users (name, username, email, password, email_verified)
VALUES ($1, $2, $3, $4, TRUE)
"#,
        )
        .bind("Sample user".to_string())
        .bind("sample_user".to_string())
        .bind(email.to_string())
        .bind(password_hash)
        .execute(&mut *conn)
        .await?;

        let req = test::TestRequest::post()
            .uri("/v1/auth/login")
            .set_json(Request {
                email: email.to_string(),
                password: password.to_string(),
                remember_me: true,
                code: None,
                blog_domain: Some("test.com".to_string()),
            })
            .to_request();
        let res = test::call_service(&app, req).await;

        assert!(res.status().is_success());
        assert_response_body_text(
            res,
            &serde_json::to_string(&Response {
                result: "success".to_string(),
                is_first_login: true, // Should be `true`.
                blog_token: None,
            })
            .unwrap_or_default(),
        )
        .await;

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
    async fn can_handle_blog_login(pool: PgPool) -> sqlx::Result<()> {
        let mut conn = pool.acquire().await?;
        let app = init_app_for_test(post, pool, false, false, None).await.0;

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

        // With `remember_me` = false

        let req = test::TestRequest::post()
            .uri("/v1/auth/login")
            .set_json(Request {
                email: email.to_string(),
                password: password.to_string(),
                remember_me: false,
                code: None,
                blog_domain: Some("test.com".to_string()),
            })
            .to_request();
        let res = test::call_service(&app, req).await;

        assert!(res.status().is_success());

        let json = serde_json::from_str::<Response>(&res_to_string(res).await).unwrap();

        assert!(json.blog_token.is_some());
        assert_eq!(json.result, "success".to_string());

        // Should insert a blog login token.
        let result = sqlx::query(
            r#"
SELECT is_persistent_session
FROM blog_login_tokens
WHERE blog_id = $1
"#,
        )
        .bind(blog_id)
        .fetch_all(&mut *conn)
        .await?;

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].get::<bool, _>("is_persistent_session"), false);

        // With `remember_me` = true

        let req = test::TestRequest::post()
            .uri("/v1/auth/login")
            .set_json(Request {
                email: email.to_string(),
                password: password.to_string(),
                remember_me: true,
                code: None,
                blog_domain: Some("test.com".to_string()),
            })
            .to_request();
        let res = test::call_service(&app, req).await;

        assert!(res.status().is_success());

        let json = serde_json::from_str::<Response>(&res_to_string(res).await).unwrap();

        assert!(json.blog_token.is_some());
        assert_eq!(json.result, "success".to_string());

        // `is_persistent_session` should be true, and old token should get deleted.
        let result = sqlx::query(
            r#"
SELECT is_persistent_session
FROM blog_login_tokens
WHERE blog_id = $1
"#,
        )
        .bind(blog_id)
        .fetch_all(&mut *conn)
        .await?;

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].get::<bool, _>("is_persistent_session"), true);

        Ok(())
    }

    mod serial {
        use super::*;

        #[test_context(RedisTestContext)]
        #[sqlx::test]
        async fn can_reject_a_login_request_for_an_invalid_password(
            ctx: &mut RedisTestContext,
            pool: PgPool,
        ) -> sqlx::Result<()> {
            let mut conn = pool.acquire().await?;
            let app = init_app_for_test(post, pool, false, false, None).await.0;

            let (email, password_hash, _) = get_sample_email_and_password();

            // Insert the user.
            sqlx::query(
                r#"
INSERT INTO users (name, username, email, password)
VALUES ($1, $2, $3, $4)
"#,
            )
            .bind("Sample user".to_string())
            .bind("sample_user".to_string())
            .bind(email.to_string())
            .bind(password_hash)
            .execute(&mut *conn)
            .await?;

            let req = test::TestRequest::post()
                .uri("/v1/auth/login")
                .set_json(Request {
                    email: email.to_string(),
                    password: "some_invalid_password".to_string(),
                    remember_me: true,
                    code: None,
                    blog_domain: None,
                })
                .to_request();
            let res = test::call_service(&app, req).await;

            assert!(res.status().is_client_error());
            assert_toast_error_response(res, "Invalid e-mail or password").await;

            // Should increment the login attempts.
            let result = get_resource_lock_attempts(&ctx.redis_pool, ResourceLock::Login, &email)
                .await
                .unwrap();

            assert_eq!(result, 1);

            Ok(())
        }

        #[test_context(RedisTestContext)]
        #[sqlx::test]
        async fn can_reject_a_login_request_for_an_invalid_recovery_code(
            ctx: &mut RedisTestContext,
            pool: PgPool,
        ) -> sqlx::Result<()> {
            let mut conn = pool.acquire().await?;
            let app = init_app_for_test(post, pool, false, false, None).await.0;
            let (email, _, password) = get_sample_email_and_password();

            // Insert the user.
            sqlx::query(
                r#"
INSERT INTO users (name, username, email, mfa_enabled)
VALUES ($1, $2, $3, TRUE)
"#,
            )
            .bind("Sample user".to_string())
            .bind("sample_user".to_string())
            .bind(email.to_string())
            .execute(&mut *conn)
            .await?;

            let req = test::TestRequest::post()
                .uri("/v1/auth/login")
                .set_json(Request {
                    email: email.to_string(),
                    password: password.to_string(),
                    remember_me: true,
                    code: Some("0".repeat(12)),
                    blog_domain: None,
                })
                .to_request();
            let res = test::call_service(&app, req).await;

            assert!(res.status().is_client_error());
            assert_form_error_response(res, vec![("code", "Invalid authentication code")]).await;

            // Should increment the login attempts.
            let result = get_resource_lock_attempts(&ctx.redis_pool, ResourceLock::Login, &email)
                .await
                .unwrap();

            assert_eq!(result, 1);

            Ok(())
        }

        #[test_context(RedisTestContext)]
        #[sqlx::test]
        async fn can_reject_a_login_request_for_an_invalid_authentication_code(
            ctx: &mut RedisTestContext,
            pool: PgPool,
        ) -> sqlx::Result<()> {
            let mut conn = pool.acquire().await?;
            let app = init_app_for_test(post, pool, false, false, None).await.0;

            let (email, _, password) = get_sample_email_and_password();
            let mfa_secret = Secret::generate_secret();

            // Insert the user
            sqlx::query(
                r#"
INSERT INTO users (name, username, email, mfa_enabled, mfa_secret)
VALUES ($1, $2, $3, TRUE, $4)
"#,
            )
            .bind("Sample user".to_string())
            .bind("sample_user".to_string())
            .bind(email.to_string())
            .bind(mfa_secret.to_encoded().to_string())
            .execute(&mut *conn)
            .await?;

            let req = test::TestRequest::post()
                .uri("/v1/auth/login")
                .set_json(Request {
                    email: email.to_string(),
                    password: password.to_string(),
                    remember_me: true,
                    code: Some("0".repeat(6)),
                    blog_domain: None,
                })
                .to_request();
            let res = test::call_service(&app, req).await;

            assert!(res.status().is_client_error());
            assert_form_error_response(res, vec![("code", "Invalid authentication code")]).await;

            // Should increment the login attempts.
            let result = get_resource_lock_attempts(&ctx.redis_pool, ResourceLock::Login, &email)
                .await
                .unwrap();

            assert_eq!(result, 1);

            Ok(())
        }

        #[test_context(RedisTestContext)]
        #[sqlx::test]
        async fn can_reject_a_login_request_for_a_used_recovery_code(
            ctx: &mut RedisTestContext,
            pool: PgPool,
        ) -> sqlx::Result<()> {
            let mut conn = pool.acquire().await?;
            let app = init_app_for_test(post, pool, false, false, None).await.0;

            let (email, password_hash, password) = get_sample_email_and_password();

            // Insert the user
            sqlx::query(
                r#"
INSERT INTO users (id, name, username, email, password, email_verified, mfa_enabled)
VALUES ($1, $2, $3, $4, $5, TRUE, TRUE)
"#,
            )
            .bind(1_i64)
            .bind("Sample user".to_string())
            .bind("sample_user".to_string())
            .bind(email.to_string())
            .bind(password_hash)
            .execute(&mut *conn)
            .await?;

            // Insert a used recovery code.
            sqlx::query(
                r#"
INSERT INTO mfa_recovery_codes(code, user_id, used_at)
VALUES ($1, $2, NOW())
"#,
            )
            .bind("0".repeat(12))
            .bind(1_i64)
            .execute(&mut *conn)
            .await?;

            let req = test::TestRequest::post()
                .uri("/v1/auth/login")
                .set_json(Request {
                    email: email.to_string(),
                    password: password.to_string(),
                    remember_me: true,
                    code: Some("0".repeat(12)),
                    blog_domain: None,
                })
                .to_request();
            let res = test::call_service(&app, req).await;

            assert!(res.status().is_client_error());
            assert_form_error_response(res, vec![("code", "Invalid authentication code")]).await;

            // Should increment the login attempts.
            let result = get_resource_lock_attempts(&ctx.redis_pool, ResourceLock::Login, &email)
                .await
                .unwrap();

            assert_eq!(result, 1);

            Ok(())
        }

        #[test_context(RedisTestContext)]
        #[sqlx::test]
        async fn can_reject_a_login_request_on_exceeding_the_max_attempts(
            ctx: &mut RedisTestContext,
            pool: PgPool,
        ) -> sqlx::Result<()> {
            let app = init_app_for_test(post, pool, false, false, None).await.0;

            exceed_resource_lock_attempts(
                &ctx.redis_pool,
                ResourceLock::Login,
                "someone@example.com",
            )
            .await;

            let req = test::TestRequest::post()
                .uri("/v1/auth/login")
                .set_json(Request {
                    email: "someone@example.com".to_string(),
                    password: "bad_password".to_string(),
                    remember_me: true,
                    code: Some("0".repeat(12)),
                    blog_domain: None,
                })
                .to_request();
            let res = test::call_service(&app, req).await;

            assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);

            Ok(())
        }

        #[test_context(RedisTestContext)]
        #[sqlx::test]
        async fn can_reset_the_resource_lock_on_a_valid_login_request(
            ctx: &mut RedisTestContext,
            pool: PgPool,
        ) -> sqlx::Result<()> {
            let mut conn = pool.acquire().await?;
            let app = init_app_for_test(post, pool, false, false, None).await.0;

            let (email, password_hash, password) = get_sample_email_and_password();

            // Increment the resource lock.
            incr_resource_lock_attempts(&ctx.redis_pool, ResourceLock::Login, &email)
                .await
                .unwrap();

            let result = get_resource_lock_attempts(&ctx.redis_pool, ResourceLock::Login, &email)
                .await
                .unwrap();

            assert_eq!(result, 1);

            // Insert the user.
            sqlx::query(
                r#"
INSERT INTO users (name, username, email, password, email_verified)
VALUES ($1, $2, $3, $4, TRUE)
"#,
            )
            .bind("Sample user".to_string())
            .bind("sample_user".to_string())
            .bind(email.to_string())
            .bind(password_hash)
            .execute(&mut *conn)
            .await?;

            let req = test::TestRequest::post()
                .uri("/v1/auth/login")
                .set_json(Request {
                    email: email.to_string(),
                    password: password.to_string(),
                    remember_me: true,
                    code: None,
                    blog_domain: None,
                })
                .to_request();
            let res = test::call_service(&app, req).await;

            assert!(res.status().is_success());

            // Should reset the attempts.
            let result =
                get_resource_lock_attempts(&ctx.redis_pool, ResourceLock::Login, &email).await;

            assert!(result.is_none());

            Ok(())
        }

        #[test_context(RedisTestContext)]
        #[sqlx::test]
        async fn can_clear_overflowing_sessions_on_login(
            ctx: &mut RedisTestContext,
            pool: PgPool,
        ) -> sqlx::Result<()> {
            let redis_pool = &ctx.redis_pool;
            let mut redis_conn = redis_pool.get().await.unwrap();
            let mut conn = pool.acquire().await?;
            let (app, _, user_id) = init_app_for_test(post, pool, true, true, None).await;

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

            // Insert the user.
            sqlx::query(
                r#"
INSERT INTO users (id, name, username, email, password, email_verified)
VALUES ($1, $2, $3, $4, $5, TRUE)
"#,
            )
            .bind(user_id.unwrap())
            .bind("Sample user".to_string())
            .bind("sample_user".to_string())
            .bind(email.to_string())
            .bind(password_hash)
            .execute(&mut *conn)
            .await?;

            let req = test::TestRequest::post()
                .uri("/v1/auth/login")
                .set_json(Request {
                    email: email.to_string(),
                    password: password.to_string(),
                    remember_me: true,
                    code: None,
                    blog_domain: None,
                })
                .to_request();
            let res = test::call_service(&app, req).await;

            assert!(res.status().is_success());
            assert_response_body_text(
                res,
                &serde_json::to_string(&Response {
                    result: "success".to_string(),
                    is_first_login: true,
                    blog_token: None,
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
            let app = init_app_for_test(services![get, post], pool, false, false, None)
                .await
                .0;

            let (email, password_hash, password) = get_sample_email_and_password();

            // Insert the user
            sqlx::query(
                r#"
INSERT INTO users (name, username, email, password, email_verified)
VALUES ($1, $2, $3, $4, TRUE)
"#,
            )
            .bind("Sample user".to_string())
            .bind("sample_user".to_string())
            .bind(email.to_string())
            .bind(password_hash)
            .execute(&mut *conn)
            .await?;

            let req = test::TestRequest::post()
                .peer_addr(SocketAddr::from(SocketAddrV4::new(
                    Ipv4Addr::new(8, 8, 8, 8),
                    8080,
                )))
                .append_header(("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:40.0) Gecko/20100101 Firefox/40.0"))
                .append_header(("origin", "https://test.storiny.com"))
                .uri("/v1/auth/login")
                .set_json(Request {
                    email: email.to_string(),
                    password: password.to_string(),
                    remember_me: true,
                    code: None,
                    blog_domain: None
                })
                .to_request();
            let res = test::call_service(&app, req).await;

            let cookie_value = res
                .response()
                .cookies()
                .find(|cookie| cookie.name() == SESSION_COOKIE_NAME);

            assert!(res.status().is_success());
            assert!(cookie_value.is_some());

            let req = test::TestRequest::get()
                .cookie(cookie_value.unwrap())
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
            assert_eq!(client_session.domain, Some("test.storiny.com".to_string()));

            Ok(())
        }
    }
}
