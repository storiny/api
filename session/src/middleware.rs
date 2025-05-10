use crate::{
    Session,
    SessionStatus,
    config::{
        self,
        Configuration,
        CookieConfiguration,
        SessionLifecycle,
        SessionMiddlewareBuilder,
    },
    storage::{
        LoadError,
        SessionKey,
        SessionKeySource,
        SessionStore,
    },
};
use actix_utils::future::{
    Ready,
    ready,
};
use actix_web::{
    HttpResponse,
    body::MessageBody,
    cookie::{
        Cookie,
        CookieJar,
        Key,
    },
    dev::{
        ResponseHead,
        Service,
        ServiceRequest,
        ServiceResponse,
        Transform,
        forward_ready,
    },
    http::header::{
        AUTHORIZATION,
        HeaderValue,
        SET_COOKIE,
    },
};
use anyhow::{
    Context,
    anyhow,
};
use serde_json::{
    Map,
    Value,
};
use std::{
    convert::TryInto,
    fmt,
    future::Future,
    pin::Pin,
    rc::Rc,
};
use tracing::debug;

/// A middleware for session management.
///
/// [`SessionMiddleware`] takes care of a few jobs:
///
/// - Instructs the session storage backend to create/update/delete/retrieve the state attached to a
///   session according to its status and the operations that have been performed against it;
/// - Set/remove a cookie, on the client side, to enable a user to be consistently associated with
///   the same session across multiple HTTP requests.
#[derive(Clone)]
pub struct SessionMiddleware<Store: SessionStore> {
    storage_backend: Rc<Store>,
    configuration: Rc<Configuration>,
}

impl<Store: SessionStore> SessionMiddleware<Store> {
    /// Use [`SessionMiddleware::new`] to initialize the session framework using the default
    /// parameters.
    ///
    /// To create a new instance of [`SessionMiddleware`] you need to provide:
    /// - an instance of the session storage backend you wish to use (i.e. an implementation of
    ///   [`SessionStore`]);
    /// - a secret key, to sign or encrypt the content of client-side session cookie.
    pub fn new(store: Store, key: Key) -> Self {
        Self::builder(store, key).build()
    }

    /// A fluent API to configure [`SessionMiddleware`].
    ///
    /// It takes as input the two required inputs to create a new instance of [`SessionMiddleware`]:
    /// - an instance of the session storage backend you wish to use (i.e. an implementation of
    ///   [`SessionStore`]);
    /// - a secret key, to sign or encrypt the content of client-side session cookie.
    pub fn builder(store: Store, key: Key) -> SessionMiddlewareBuilder<Store> {
        SessionMiddlewareBuilder::new(store, config::default_configuration(key))
    }

    pub(crate) fn from_parts(store: Store, configuration: Configuration) -> Self {
        Self {
            storage_backend: Rc::new(store),
            configuration: Rc::new(configuration),
        }
    }
}

impl<S, B, Store> Transform<S, ServiceRequest> for SessionMiddleware<Store>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
    Store: SessionStore + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Transform = InnerSessionMiddleware<S, Store>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(InnerSessionMiddleware {
            service: Rc::new(service),
            configuration: Rc::clone(&self.configuration),
            storage_backend: Rc::clone(&self.storage_backend),
        }))
    }
}

/// Short-hand to create an `actix_web::Error` instance that will result in an `Internal Server
/// Error` response while preserving the error root cause (e.g. in logs).
fn e500<E: fmt::Debug + fmt::Display + 'static>(err: E) -> actix_web::Error {
    // We do not use `actix_web::error::ErrorInternalServerError` because we do not want to
    // leak internal implementation details to the caller.
    //
    // `actix_web::error::ErrorInternalServerError` includes the error Display representation
    // as body of the error responses, leading to messages like "There was an issue persisting
    // the session state" reaching API clients. We don't want that, we want opaque 500s.
    actix_web::error::InternalError::from_response(
        err,
        HttpResponse::InternalServerError().finish(),
    )
    .into()
}

pub static LIFECYCLE_KEY: &str = "lifecycle";
pub static EXTERNAL_BLOG_KEY: &str = "ext_blog";
pub static DOMAIN_KEY: &str = "domain";

#[doc(hidden)]
#[non_exhaustive]
pub struct InnerSessionMiddleware<S, Store: SessionStore + 'static> {
    service: Rc<S>,
    configuration: Rc<Configuration>,
    storage_backend: Rc<Store>,
}

impl<S, B, Store> Service<ServiceRequest> for InnerSessionMiddleware<S, Store>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    S::Future: 'static,
    Store: SessionStore + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);
        let storage_backend = Rc::clone(&self.storage_backend);
        let configuration = Rc::clone(&self.configuration);

        Box::pin(async move {
            let (session_key, key_source) =
                extract_session_key(&req, &configuration.cookie).unzip();
            let (session_key, session_state) =
                load_session_state(session_key, storage_backend.as_ref()).await?;

            let blog_domain = session_state.get(DOMAIN_KEY).map(|value| value.to_string());
            let mut session_lifecycle = SessionLifecycle::PersistentSession;

            if let Some(lifecycle) = session_state.get(LIFECYCLE_KEY) {
                let lifecycle = lifecycle
                    .as_i64()
                    .unwrap_or(SessionLifecycle::PersistentSession as i64);

                session_lifecycle = SessionLifecycle::from_i32(lifecycle as i32);
            }

            Session::set_session(&mut req, session_state, session_lifecycle);

            let mut res = service.call(req).await?;
            let (lifecycle, status, mut session_state) = Session::get_changes(&mut res);

            // We only insert the dynamic properties into the session if they already exist or are
            // non-empty to avoid creating sessions on every request.
            if session_key.is_some() || !session_state.is_empty() {
                session_state.insert(
                    LIFECYCLE_KEY.to_string(),
                    Value::from(lifecycle.clone() as i32),
                );
            }

            let can_set_cookie = key_source != Some(SessionKeySource::AuthorizationHeader);

            match session_key {
                None => {
                    // We do not create an entry in the session store if there is no state attached
                    // to a fresh session.
                    if !session_state.is_empty() {
                        let session_key = storage_backend
                            .save(session_state, &configuration.session.state_ttl)
                            .await
                            .map_err(e500)?;

                        if can_set_cookie {
                            set_session_cookie(
                                res.response_mut().head_mut(),
                                session_key,
                                &configuration.cookie,
                                lifecycle,
                                blog_domain,
                            )
                            .map_err(e500)?;
                        }
                    }
                }

                Some(session_key) => {
                    match status {
                        SessionStatus::Changed => {
                            let session_key = storage_backend
                                .update(
                                    session_key,
                                    session_state,
                                    &configuration.session.state_ttl,
                                )
                                .await
                                .map_err(e500)?;

                            if can_set_cookie {
                                set_session_cookie(
                                    res.response_mut().head_mut(),
                                    session_key,
                                    &configuration.cookie,
                                    lifecycle,
                                    blog_domain,
                                )
                                .map_err(e500)?;
                            }
                        }

                        SessionStatus::Purged => {
                            storage_backend.delete(&session_key).await.map_err(e500)?;

                            if can_set_cookie {
                                delete_session_cookie(
                                    res.response_mut().head_mut(),
                                    &configuration.cookie,
                                    blog_domain,
                                )
                                .map_err(e500)?;
                            }
                        }

                        SessionStatus::Renewed => {
                            storage_backend.delete(&session_key).await.map_err(e500)?;

                            let session_key = storage_backend
                                .save(session_state, &configuration.session.state_ttl)
                                .await
                                .map_err(e500)?;

                            if can_set_cookie {
                                set_session_cookie(
                                    res.response_mut().head_mut(),
                                    session_key,
                                    &configuration.cookie,
                                    lifecycle,
                                    blog_domain,
                                )
                                .map_err(e500)?;
                            }
                        }

                        SessionStatus::Unchanged => {}
                    };
                }
            }

            Ok(res)
        })
    }
}

/// Extracts session token from an `Authorization` header containing a Bearer token. Used for blogs
/// hosted on external domains.
///
/// Returns `Some(String)` if the header is a valid Bearer token and successfully parsed, `None`
/// otherwise.
///
/// * `header` - The `Authorization` header value expected in the form `Bearer <token>`.
fn extract_token_from_auth_header(header: &HeaderValue) -> Option<String> {
    // "Bearer *" length
    if header.len() < 8 {
        debug!("header is too short");
        return None;
    }

    let mut parts = header.to_str().ok()?.splitn(2, ' ');

    match parts.next() {
        Some("Bearer") => {}
        _ => {
            debug!("no bearer prefix");
            return None;
        }
    }

    let token = parts.next()?.to_string();

    Some(token)
}

/// Examines the authorization header and session cookie attached to the incoming request, if
/// present, and attempts to extract the session key. The order of preference is the authorization
/// header first, followed by the cookie as a fallback if the authorization header is not present.
///
/// It returns `None` if no session proof is found or if the session proof is considered invalid
/// (e.g., due to a failed signature check).
///
/// * `req` - The incoming [ServiceRequest] instance.
/// * `config` - The [CookieConfiguration] instance.
fn extract_session_key(
    req: &ServiceRequest,
    config: &CookieConfiguration,
) -> Option<(SessionKey, SessionKeySource)> {
    let (session_cookie, key_source) = if let Some(auth_header) = req.headers().get(AUTHORIZATION) {
        debug!("using authorization header");

        let token = extract_token_from_auth_header(auth_header)?;

        (
            Cookie::new(config.name.clone(), token),
            SessionKeySource::AuthorizationHeader,
        )
    } else {
        debug!("using cookie");

        let cookies = req.cookies().ok()?;
        let session_cookie = cookies
            .iter()
            .find(|&cookie| cookie.name() == config.name)
            .cloned()?;

        (session_cookie, SessionKeySource::Cookie)
    };

    let mut jar = CookieJar::new();
    jar.add_original(session_cookie);

    let verification_result = jar.signed(&config.key).get(&config.name);

    if verification_result.is_none() {
        tracing::warn!(
            "The session proof attached to the incoming request failed to pass cryptographic \
            checks (signature verification/decryption)."
        );
    }

    match verification_result?.value().to_owned().try_into() {
        Ok(session_key) => Some((session_key, key_source)),
        Err(err) => {
            tracing::warn!(
                error.message = %err,
                error.cause_chain = ?err,
                "Invalid session key, ignoring."
            );

            None
        }
    }
}

/// Loads the session state from session storage using the provided `session_key`.
///
/// * `session_key` - The session key for item.
/// * `storage_backend` - The session storage backend.
async fn load_session_state<Store: SessionStore>(
    session_key: Option<SessionKey>,
    storage_backend: &Store,
) -> Result<(Option<SessionKey>, Map<String, Value>), actix_web::Error> {
    if let Some(session_key) = session_key {
        match storage_backend.load(&session_key).await {
            Ok(state) => {
                if let Some(state) = state {
                    Ok((Some(session_key), state))
                } else {
                    // We discard the existing session key given that the state attached to it can
                    // no longer be found (e.g. it expired or we suffered some data loss in the
                    // storage). Regenerating the session key will trigger the `save` workflow
                    // instead of the `update` workflow if the session state is modified during the
                    // lifecycle of the current request.

                    tracing::debug!(
                        "No session state has been found for a valid session key, creating a new \
                        empty session."
                    );

                    Ok((None, Map::new()))
                }
            }

            Err(err) => match err {
                LoadError::Deserialization(err) => {
                    tracing::warn!(
                        error.message = %err,
                        error.cause_chain = ?err,
                        "Invalid session state, creating a new empty session."
                    );

                    Ok((Some(session_key), Map::new()))
                }

                LoadError::Other(err) => Err(e500(err)),
            },
        }
    } else {
        Ok((None, Map::new()))
    }
}

/// Attaches a signed session cookie to the outgoing response based on the provided session key
/// and cookie configuration.
///
/// * `response` - A mutable reference to the response head to which the `Set-Cookie` header will be
///   added.
/// * `session_key` - The session key to be stored in the cookie.
/// * `config` - The [CookieConfiguration] instance.
/// * `session_lifecycle` - Indicates whether the session should be persistent or session-based.
/// * `blog_domain` - The optional cookie domain for blogs hosted on external domains (`Set-Cookie`
///   header is mirrored via API proxy on the web server).
fn set_session_cookie(
    response: &mut ResponseHead,
    session_key: SessionKey,
    config: &CookieConfiguration,
    session_lifecycle: SessionLifecycle,
    blog_domain: Option<String>,
) -> Result<(), anyhow::Error> {
    let value: String = session_key.into();
    let mut cookie = Cookie::new(config.name.clone(), value);

    cookie.set_secure(config.secure);
    cookie.set_http_only(config.http_only);
    cookie.set_same_site(config.same_site);
    cookie.set_path(config.path.clone());

    // Check for a persistent session.
    if session_lifecycle == SessionLifecycle::PersistentSession {
        if let Some(max_age) = config.max_age {
            cookie.set_max_age(max_age);
        }
    }

    if let Some(domain) = blog_domain.or_else(|| config.domain.clone()) {
        cookie.set_domain(domain);
    }

    let mut jar = CookieJar::new();
    jar.signed_mut(&config.key).add(cookie);

    // Set cookie
    let cookie = jar
        .delta()
        .next()
        .ok_or(anyhow!("unable to sign the cookie"))?;
    let val = HeaderValue::from_str(&cookie.encoded().to_string())
        .context("Failed to attach a session cookie to the outgoing response")?;

    response.headers_mut().append(SET_COOKIE, val);

    Ok(())
}

/// Attaches a removal cookie to the outgoing response, effectively instructing the client
/// to delete the existing session cookie.
///
/// * `response` - A mutable reference to the response head to which the removal `Set-Cookie` header
///   will be added.
/// * `config` - The [CookieConfiguration] instance.
/// * `blog_domain` - The optional cookie domain for blogs hosted on external domains (`Set-Cookie`
///   header is mirrored via API proxy on the web server).
fn delete_session_cookie(
    response: &mut ResponseHead,
    config: &CookieConfiguration,
    blog_domain: Option<String>,
) -> Result<(), anyhow::Error> {
    let removal_cookie = Cookie::build(config.name.clone(), "")
        .path(config.path.clone())
        .secure(config.secure)
        .http_only(config.http_only)
        .same_site(config.same_site);

    let mut removal_cookie = if let Some(domain) = blog_domain.or_else(|| config.domain.clone()) {
        removal_cookie.domain(domain)
    } else {
        removal_cookie
    }
    .finish();

    removal_cookie.make_removal();

    let val = HeaderValue::from_str(&removal_cookie.to_string())
        .context("Failed to attach a session removal cookie to the outgoing response")?;
    response.headers_mut().append(SET_COOKIE, val);

    Ok(())
}
