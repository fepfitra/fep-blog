---
title: "Axum Cheatsheet"
description: "From its examples"
date: "2025-6-3"
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
