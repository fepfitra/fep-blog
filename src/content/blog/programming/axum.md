---
title: "Axum Cheatsheet"
description: "From its examples"
date: "2025-6-4"
---
## Main
```bash
cargo add tokio --features full
```
```rust
#[tokio::main]
async fn main() {
    //CODE
}
```
## Hello World

```rust
#[tokio::main]
async fn main() {
    let app = Router::new().route("/", get(handler));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

async fn handler() -> Html<&'static str> {
    Html("<h1>Hello, World!</h1>")
}
```

## Trace
```bash
cargo add axum --features tracing
cargo add tracing-subscriber --features env-filter
cargo add tracing
```
```rust
// fn main (on top)
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("{}=debug", env!("CARGO_CRATE_NAME")).into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // INIT REPO

    // INIT ROUTES

    // START SERVER
```

## Repo
```bash
cargo add serde --features derive
cargo add uuid --features serde,v4
```
```rust
// fn main
    let user_repo = InMemoryUserRepo::default();


#[derive(Debug, Serialize, Clone)]
struct User {
    id: Uuid,
    name: String,
}

trait UserRepo: Send + Sync {
    fn get_user(&self, id: Uuid) -> Option<User>;
    fn save_user(&self, user: &User);
}

#[derive(Debug, Clone, Default)]
struct InMemoryUserRepo {
    map: Arc<Mutex<HashMap<Uuid, User>>>,
}

impl UserRepo for InMemoryUserRepo {
    fn get_user(&self, id: Uuid) -> Option<User> {
        self.map.lock().unwrap().get(&id).cloned()
    }

    fn save_user(&self, user: &User) {
        self.map.lock().unwrap().insert(user.id, user.clone());
    }
}
```

## Inject repo 

We generally have two ways to inject dependencies:

1. Using trait objects (`dyn SomeTrait`)
    - Pros
        - Likely leads to simpler code due to fewer type parameters.
    - Cons
        - Less flexible because we can only use object safe traits
        - Small amount of additional runtime overhead due to dynamic dispatch.
          This is likely to be negligible.
2. Using generics (`T where T: SomeTrait`)
    - Pros
        - More flexible since all traits can be used.
        - No runtime overhead.
    - Cons:
        - Additional type parameters and trait bounds can lead to more complex code and
          boilerplate.

Using trait objects is recommended unless you really need generics.

### With dyn
```rust
// fn main
    let using_dyn = Router::new()
        .route("/users/{id}", get(get_user_dyn))
        .route("/users", post(create_user_dyn))
        .with_state(AppStateDyn {
            user_repo: Arc::new(user_repo.clone()),
        });
...
    axum::serve(listener, using_dyn).await.unwrap();
...

#[derive(Deserialize)]
struct UserParams {
    name: String,
}

#[derive(Clone)]
struct AppStateDyn {
    user_repo: Arc<dyn UserRepo>,
}

async fn create_user_dyn(
    State(state): State<AppStateDyn>,
    Json(params): Json<UserParams>,
) -> Json<User> {
    let user = User {
        id: Uuid::new_v4(),
        name: params.name,
    };

    state.user_repo.save_user(&user);
    Json(user)
}

async fn get_user_dyn(
    State(state): State<AppStateDyn>,
    Path(id): Path<Uuid>,
) -> Result<Json<User>, StatusCode> {
    match state.user_repo.get_user(id) {
        Some(user) => Ok(Json(user)),
        None => Err(StatusCode::NOT_FOUND),
    }
}
```

### With generics
```rust
// fn main
    let using_generic = Router::new()
        .route("/users/{id}", get(get_user_generic::<InMemoryUserRepo>))
        .route("/users", post(create_user_generic::<InMemoryUserRepo>))
        .with_state(AppStateGeneric { user_repo });
...
    axum::serve(listener, using_generic).await.unwrap();
...

#[derive(Clone)]
struct AppStateGeneric<T> {
    user_repo: T,
}

async fn create_user_generic<T>(
    State(state): State<AppStateGeneric<T>>,
    Json(params): Json<UserParams>,
) -> Json<User>
where
    T: UserRepo,
{
    let user = User {
        id: Uuid::new_v4(),
        name: params.name,
    };

    state.user_repo.save_user(&user);

    Json(user)
}

async fn get_user_generic<T>(
    State(state): State<AppStateGeneric<T>>,
    Path(id): Path<Uuid>,
) -> Result<Json<User>, StatusCode>
where
    T: UserRepo,
{
    match state.user_repo.get_user(id) {
        Some(user) => Ok(Json(user)),
        None => Err(StatusCode::NOT_FOUND),
    }
}

```

## Group routes
```rust
// fn main
    let app = Router::new()
        .nest("/dyn", using_dyn)
        .nest("/generic", using_generic);
...
    axum::serve(listener, app).await.unwrap();
...
```

## Cors

see https://docs.rs/tower-http/latest/tower_http/cors/index.html
for more details

pay attention that for some request types like posting content-type: application/json
it is required to add ".allow_headers([http::header::CONTENT_TYPE])"
or see this issue https://github.com/tokio-rs/axum/issues/849

```rust
// fn main 
    let app = Router::new().route("/json", get(json)).layer(
        CorsLayer::new()
            .allow_origin("http://localhost:3000".parse::<HeaderValue>().unwrap())
            .allow_methods([Method::GET]),
        );
```

## Gracefull shutdown
Graceful shutdown will wait for outstanding requests to complete. Add a timeout so requests don't hang forever.
```bash
cargo add tower-http --features timeout,trace
```
```rust
// fn main
    let app = Router::new()
        .route("/slow", get(|| sleep(Duration::from_secs(5))))
        .route("/forever", get(std::future::pending::<()>))
        .layer((
            TraceLayer::new_for_http(),
            TimeoutLayer::new(Duration::from_secs(10)), //here
        ));
...
    axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await
            .unwrap();
...


async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
```

## Error handling
```bash
cargo add anyhow
```
```rust
struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        tracing::error!("Unhandled error: {}", self.0);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Something went wrong: {}", self.0),
        )
        .into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

//------------------
async fn get_user(
    State(state): State<AppStateDyn>,
    Path(id): Path<Uuid>,
) -> Result<Json<User>, AppError> {
    match state.user_repo.get_user(id) {
        Some(user) => Ok(Json(user)),
        None => Err(AppError(anyhow::anyhow!("User not found"))),
    }
}
```

## Global 404 Handler
```rust
// fn main
    let app = app.fallback(handler_404);
...
async fn handler_404() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, "nothing to see here")
}
```

## JWT
```bash
cargo add jsonwebtoken
cargo add chrono
cargo add axum-extra --features typed-header
```

### Keys
```rust
struct Keys {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl Keys {
    fn new(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}

static KEYS: LazyLock<Keys> = LazyLock::new(|| {
    let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    Key.new(secret.as_bytes())
});

#[tokio::main]
async fn main() {
    println!("JWT Encoding Key: {:?}", KEYS);
}
```

### AuthError Enum
```rust
#[derive(Debug)]
enum AuthError {
    WrongCredentials,
    MissingCredentials,
    TokenCreation,
    InvalidToken,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message) = match self {
            AuthError::WrongCredentials => (StatusCode::UNAUTHORIZED, "Wrong credentials"),
            AuthError::MissingCredentials => (StatusCode::BAD_REQUEST, "Missing credentials"),
            AuthError::TokenCreation => (StatusCode::INTERNAL_SERVER_ERROR, "Token creation error"),
            AuthError::InvalidToken => (StatusCode::BAD_REQUEST, "Invalid token"),
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}
```

### AuthPayload and AuthBody
```rust
#[derive(Debug, Deserialize)]
struct AuthPayload {
    client_id: String,
    client_secret: String,
}

#[derive(Debug, Serialize)]
struct AuthBody {
    access_token: String,
    token_type: String,
}

impl AuthBody {
    fn new(token: String) -> Self {
        Self {
            access_token: token,
            token_type: "Bearer".to_string(),
        }
    }
}

```
### Claims
```rust
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    company: String,
    exp: usize,
}

impl Display for Claims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Email: {}\nCompany: {}", self.sub, self.company)
    }
}

impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = AuthError;
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::InvalidToken)?;
        let token_data = decode::<Claims>(bearer.token(), &KEYS.decoding, &Validation::default())
            .map_err(|_| AuthError::InvalidToken)?;
        Ok(token_data.claims)
    }
}

```

### Protected
```rust
//fn main
    let app = Router::new().route("/protected", get(protected));
...

async fn protected(claims: Claims) -> Result<String, AuthError> {
    Ok(format!(
        "Welcome to the protected area :)\nYour data:\n{claims}",
    ))
}
```
### Authorize
```rust
// fn main
    let app = Router::new()
        .route("/protected", get(protected))
        .route("/authorize", post(authorize));
...

async fn authorize(Json(payload): Json<AuthPayload>) -> Result<Json<AuthBody>, AuthError> {
    if payload.client_id.is_empty() || payload.client_secret.is_empty() {
        return Err(AuthError::MissingCredentials);
    }
    if payload.client_id != "foo" || payload.client_secret != "bar" {
        return Err(AuthError::WrongCredentials);
    }

    let claims = Claims {
        sub: "b@b.com".to_owned(),
        company: "FooBar Inc.".to_owned(),
        exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
    };

    let token = encode(&Header::default(), &claims, &KEYS.encoding)
        .map_err(|_| AuthError::TokenCreation)?;

    Ok(Json(AuthBody::new(token)))
}
```

### Test
```bash
token=$(curl -s -w '\n' -H 'Content-Type: application/json' -d '{"client_id":"foo","client_secret":"bar"}' http://localhost:3000/authorize)
echo $token

token=$(echo $token | jq -r .access_token)
echo $token

curl -s -w '\n' -H 'Content-Type: application/json' -H "Authorization: Bearer $token" http://localhost:3000/protected
```

## Oauth
### Memory Store (example)
```rust
// fn main
    let store = MemoryStore::new();
```

### AppError
```rust
#[derive(Debug)]
struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        tracing::error!("Application error: {:#}", self.0);
        (StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong").into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}
```

### AppState
```rust
// fn main
    let app_state = AppState {
        store,
        oauth_client,
    };
//---
#[derive(Clone)]
struct AppState {
    store : MemoryStore,
    oauth_client: BasicClient,
}

impl FromRef<AppState> for MemoryStore {
    fn from_ref(state: &AppState) -> Self {
        state.store.clone()
    }
}

impl FromRef<AppState> for BasicClient {
    fn from_ref(state: &AppState) -> Self {
        state.oauth_client.clone()
    }
}
```

### AuthRedirect
```rust
struct AuthRedirect;

impl IntoResponse for AuthRedirect {
    fn into_response(self) -> Response {
        Redirect::temporary("/auth/discord").into_response()
    }
}
```
### User data
```rust
#[derive(Debug, Serialize, Deserialize)]
struct User {
    id: String,
    avatar: Option<String>,
    username: String,
    discriminator: String,
}

impl<S> FromRequestParts<S> for User
where
    MemoryStore: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthRedirect;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let store = MemoryStore::from_ref(state);

        let cookies = parts
            .extract::<TypedHeader<headers::Cookie>>()
            .await
            .map_err(|e| match *e.name() {
                header::COOKIE => match e.reason() {
                    TypedHeaderRejectionReason::Missing => AuthRedirect,
                    _ => panic!("unexpected error getting Cookie header(s): {e}"),
                },
                _ => panic!("unexpected error getting cookies: {e}"),
            })?;
        let session_cookie = cookies.get(COOKIE_NAME).ok_or(AuthRedirect)?;

        let session = store
            .load_session(session_cookie.to_string())
            .await
            .unwrap()
            .ok_or(AuthRedirect)?;

        let user = session.get::<User>("user").ok_or(AuthRedirect)?;

        Ok(user)
    }
}

impl<S> OptionalFromRequestParts<S> for User
where
    MemoryStore: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        match <User as FromRequestParts<S>>::from_request_parts(parts, state).await {
            Ok(res) => Ok(Some(res)),
            Err(AuthRedirect) => Ok(None),
        }
    }
}
```

### index
```rust
//fn main
    let app = Router::new().route("/", get(index)).with_state(app_state);
//---

async fn index(user: Option<User>) -> impl IntoResponse {
    match user {
        Some(u) => format!(
            "Hey {}! You're logged in!\nYou may now access `/protected`.\nLog out with `/logout`.",
            u.username
        ),
        None => "You're not logged in.\nVisit `/auth/discord` to do so.".to_string(),
    }
}

```

### discord auth
```rust
// fn main
    let app = Router::new()
        .route("/", get(index))
        .route("/auth/discord", get(discord_auth))
        .with_state(app_state);
// ---

async fn discord_auth(
    State(client): State<BasicClient>,
    State(store): State<MemoryStore>,
) -> Result<impl IntoResponse, AppError> {
    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("identify".to_string()))
        .url();
    let mut session = Session::new();
    session
        .insert(CSRF_TOKEN, &csrf_token)
        .context("failed to insert CSRF token into session")?;

    let cookie = store
        .store_session(session)
        .await
        .context("failed to store session")?
        .context("unexpected error retrieving CSRF cookie value")?;

    let cookie = format!("{COOKIE_NAME}={cookie}; SameSite=Lax; HttpOnly; Secure; Path=/");
    let mut headers = HeaderMap::new();

    headers.insert(
        SET_COOKIE,
        cookie.parse().context("failed to parse cookie")?,
    );

    Ok((headers, Redirect::to(auth_url.as_ref())))
}
```

### AuthRequest
```rust
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AuthRequest {
    code: String,
    state: String,
}
```

### Authorized
```rust
// fn main
    let app = Router::new()
        .route("/", get(index))
        .route("/auth/discord", get(discord_auth))
        .route("/auth/authorized", get(auth_authorized))
        .with_state(app_state);
//---
async fn csrf_token_validation_workflow(
    auth_request: &AuthRequest,
    cookies: &headers::Cookie,
    store: &MemoryStore,
) -> Result<(), AppError> {
    let cookie = cookies
        .get(COOKIE_NAME)
        .context("unexpected error getting cookie name")?
        .to_string();
    let session = match store
        .load_session(cookie)
        .await
        .context("failed to load session")?
    {
        Some(session) => session,
        None => return Err(AppError(anyhow::anyhow!("Session not found").into())),
    };

    let stored_csrf_token = session
        .get::<CsrfToken>(CSRF_TOKEN)
        .context("CSRF token not found")?
        .to_owned();

    store
        .destroy_session(session)
        .await
        .context("failed to destroy old session")?;

    if *stored_csrf_token.secret() != auth_request.state {
        return Err(AppError(anyhow::anyhow!("CSRF token mismatch").into()));
    }

    Ok(())
}

async fn auth_authorized(
    Query(query): Query<AuthRequest>,
    State(store): State<MemoryStore>,
    State(oauth_client): State<BasicClient>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
) -> Result<impl IntoResponse, AppError> {
    csrf_token_validation_workflow(&query, &cookies, &store).await?;
    let token = oauth_client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .request_async(async_http_client)
        .await
        .context("failed in sending request request to authorization server")?;
    let client = reqwest::Client::new();
    let user_data: User = client
        .get("https://discordapp.com/api/users/@me")
        .bearer_auth(token.access_token().secret())
        .send()
        .await
        .context("failed to send request to Discord API")?
        .json()
        .await
        .context("failed to deserialize user data from Discord API")?;

    let mut session = Session::new();
    session
        .insert("user", &user_data)
        .context("failed to insert user data into session")?;

    let cookie = store
        .store_session(session)
        .await
        .context("failed to store session")?
        .context("unexpected error retrieving cookie value")?;

    let cookie = format!("{COOKIE_NAME}={cookie}; SameSite=Lax; HttpOnly; Secure; Path=/");

    let mut headers = HeaderMap::new();
    headers.insert(
        SET_COOKIE,
        cookie.parse().context("failed to parse cookie")?,
    );

    Ok((headers, Redirect::to("/").into_response()))
}

```

### Protected
```rust
// fn main
    let app = Router::new()
        .route("/", get(index))
        .route("/auth/discord", get(discord_auth))
        .route("/auth/authorized", get(auth_authorized))
        .route("/protected", get(protected))
        .with_state(app_state);
//---
async fn protected(user: User) -> impl IntoResponse {
    format!("Welcome to the protected area :)\nHere's your info:\n{user:?}")
}
```

### Logout
```rust
// fn main
    let app = Router::new()
        .route("/", get(index))
        .route("/auth/discord", get(discord_auth))
        .route("/auth/authorized", get(auth_authorized))
        .route("/protected", get(protected))
        .route("/logout", get(logout))
        .with_state(app_state);
//---
async fn logout(
    State(store): State<MemoryStore>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
) -> Result<impl IntoResponse, AppError> {
    let cookie = cookies
        .get(COOKIE_NAME)
        .context("unexpected error getting cookie name")?;

    let session = match store
        .load_session(cookie.to_string())
        .await
        .context("failed to load session")?
    {
        Some(session) => session,
        None => return Ok(Redirect::to("/")),
    };

    store
        .destroy_session(session)
        .await
        .context("failed to destroy session")?;
    Ok(Redirect::to("/"))
}

```
