pub mod route {
    use axum::{middleware, Extension, Router};
    use axum::routing::{delete, get, post, put};
    use tower::ServiceBuilder;
    use crate::authentication::handlers::user::auth_test::auth_test;
    use crate::authentication::handlers::user::change_credentials::change_password::change_password;
    use crate::authentication::handlers::user::change_credentials::change_username::change_username;
    use crate::authentication::handlers::user::delete::delete_user;
    use crate::authentication::handlers::user::login::login;
    use crate::authentication::handlers::user::new::create_new_user;
    use crate::authentication::handlers::user::refresh::access_token::refresh_access_token;
    use crate::authentication::handlers::user::refresh::refresh_token::refresh_refresh_token;
    use crate::authentication::middleware::user::auth::auth_middleware;
    use crate::authentication::middleware::user::refresh_auth::refresh_token_auth_middleware;
    use crate::authentication::models::appstate::AppstateWrapper;


    /// returns the default router
    /// - `version`: specifies the api version | for example 'v1' or 'v2'
    pub fn get_default_router(appstate: AppstateWrapper, version: &str) -> Router {
        // public routes are accessible without any authentication or authorization
        let pub_routes = Router::new()
            .route("/new", post(create_new_user))
            .route("/login", post(login))
            .route("/refresh/refresh_token", post(refresh_refresh_token))
            .with_state(appstate.clone());

        // protected routes require access-token-authentication
        let protected_routes = Router::new()
            .route("/auth_test", get(auth_test))
            .route("/delete", delete(delete_user))
            .route("/change/password", put(change_password))
            .route("/change/username", put(change_username))
            .layer(
                ServiceBuilder::new()
                    .layer(middleware::from_fn(auth_middleware))
                    .layer(Extension(appstate.clone()))
            );

        // refresh token protected routes require - as the name implies - refresh-token-authentication
        let refresh_token_protected_routes = Router::new()
            .route("/refresh/access_token", get(refresh_access_token))
            .layer(
                ServiceBuilder::new()
                    .layer(middleware::from_fn(refresh_token_auth_middleware))
                    .layer(Extension(appstate.clone()))
            );

        // put them together
        let prefix = format!("/{}/user", version);
        let app = Router::new()
            .nest(&prefix, protected_routes)
            .nest(&prefix, refresh_token_protected_routes)
            .layer(Extension(appstate.clone()))
            .nest(&prefix, pub_routes)
            .with_state(appstate);

        app
    }
}



// router


