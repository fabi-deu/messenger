pub mod authentication {
    pub mod lib;
    pub mod handlers  {
        pub mod user {
            pub mod change_credentials {
                pub mod change_password;
                pub mod change_username;
            }
            pub mod refresh {
                pub mod access_token;
                pub mod refresh_token;
            }
            pub mod delete;
            pub mod new;
            pub mod login;
            pub mod auth_test;
        }
    }

    pub mod middleware {
        pub mod user {
            pub mod auth;
            pub mod refresh_auth;
        }
    }

    pub mod models {
        pub mod user;
        pub mod auth_user;
        pub mod user_permission;
        pub mod appstate;
    }

    pub(crate) mod util {
        pub(crate) mod cookies;
        pub(crate) mod jwt {
            pub(crate) mod general;
            pub(crate) mod access_token;
            pub(crate) mod refresh_token;
            pub(crate) mod claims;
        }

        pub mod validation;
        pub(crate) mod hashing;
    }
}

pub mod ws {

}

pub mod templates {
    pub mod wrapper;
}