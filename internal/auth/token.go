package auth

// APITokenPrefix identifies an OpenWatch API service-account token in an
// Authorization: Bearer header. The identity binder routes bearer values
// carrying this prefix to the API-token authenticator (the rest are JWTs).
// "owk" = OpenWatch Key.
const APITokenPrefix = "owk_"
