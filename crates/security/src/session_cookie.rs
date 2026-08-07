//! Production session cookie（§16.5）。
//!
//! `__Host-operune-session`：`Secure`、`HttpOnly`、`SameSite=Strict`、`Path=/`、
//! **不设置 `Domain`**（`__Host-` 前缀契约要求）。使用 cookie 0.18.1 构造，
//! 不自写 cookie 解析器（§22.6）；解析 cookie 由 web-admin 直接用同一 crate
//! 完成，本模块只负责构造与属性校验。

use cookie::{Cookie, Expiration, SameSite};
use time::{Duration, OffsetDateTime};

use crate::token::SessionToken;

/// production session cookie 名称（§16.5）。
pub const SESSION_COOKIE_NAME: &str = "__Host-operune-session";

/// 构造 production session cookie（§16.5 属性全部固定）。
///
/// 值使用 bearer token 的 URL-safe 编码（§16.5 浏览器传输格式）。
/// `expires_at` 为 absolute expiry 时刻（与 [`crate::session::SessionPolicy`]
/// 的 absolute lifetime 一致），`max_age` 为 cookie 的 Max-Age。
pub fn build_session_cookie(
    token: &SessionToken,
    expires_at: OffsetDateTime,
    max_age: Duration,
) -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE_NAME, token.to_url_safe_string()))
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Strict)
        .path("/")
        .expires(expires_at)
        .max_age(max_age)
        .build()
}

/// 构造 logout 用的删除 cookie（§16.5）：过期时刻为 UNIX_EPOCH，`Max-Age=0`。
pub fn build_session_cookie_removal() -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE_NAME, ""))
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Strict)
        .path("/")
        .expires(Expiration::DateTime(OffsetDateTime::UNIX_EPOCH))
        .max_age(Duration::ZERO)
        .build()
}

/// 校验 cookie 的 production 属性（§16.5），用于构造后自检与测试。
pub fn validate_production_cookie(cookie: &Cookie<'_>) -> Result<(), SessionCookieError> {
    if cookie.name() != SESSION_COOKIE_NAME {
        return Err(SessionCookieError::NameMismatch);
    }
    if cookie.secure() != Some(true) {
        return Err(SessionCookieError::NotSecure);
    }
    if cookie.http_only() != Some(true) {
        return Err(SessionCookieError::NotHttpOnly);
    }
    if cookie.same_site() != Some(SameSite::Strict) {
        return Err(SessionCookieError::SameSiteNotStrict);
    }
    if cookie.path() != Some("/") {
        return Err(SessionCookieError::PathNotRoot);
    }
    if cookie.domain().is_some() {
        return Err(SessionCookieError::DomainSet);
    }
    Ok(())
}

/// production session cookie 属性校验错误（§16.5）。
#[derive(Debug, thiserror::Error)]
pub enum SessionCookieError {
    /// 名称不是 `__Host-operune-session`。
    #[error("cookie 名称必须是 {SESSION_COOKIE_NAME}")]
    NameMismatch,
    /// 缺少 `Secure`。
    #[error("cookie 必须设置 Secure")]
    NotSecure,
    /// 缺少 `HttpOnly`。
    #[error("cookie 必须设置 HttpOnly")]
    NotHttpOnly,
    /// `SameSite` 不是 `Strict`。
    #[error("cookie 必须设置 SameSite=Strict")]
    SameSiteNotStrict,
    /// `Path` 不是 `/`。
    #[error("cookie 必须设置 Path=/")]
    PathNotRoot,
    /// 设置了 `Domain`（`__Host-` 契约禁止）。
    #[error("cookie 不得设置 Domain")]
    DomainSet,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::SessionToken;

    fn ok_or_fail<T, E: std::fmt::Debug>(result: Result<T, E>, what: &str) -> T {
        assert!(
            result.is_ok(),
            "{what} 应成功，实际 Err: {:?}",
            result.as_ref().err()
        );
        match result {
            Ok(value) => value,
            Err(_) => unreachable!("上面的断言已保证 is_ok"),
        }
    }

    fn base_time() -> OffsetDateTime {
        some_or_fail(
            OffsetDateTime::UNIX_EPOCH.checked_add(Duration::days(400)),
            "base time",
        )
    }

    fn some_or_fail<T>(option: Option<T>, what: &str) -> T {
        assert!(option.is_some(), "{what} 应存在");
        match option {
            Some(value) => value,
            None => unreachable!("上面的断言已保证 is_some"),
        }
    }

    #[test]
    fn session_cookie_name_is_host_prefixed() {
        // `__Host-` 前缀：要求 Secure、Path=/、无 Domain（§16.5）。
        assert_eq!(SESSION_COOKIE_NAME, "__Host-operune-session");
    }

    #[test]
    fn production_cookie_has_required_attributes() {
        let token = ok_or_fail(SessionToken::generate(), "generate");
        let now = base_time();
        let expires = some_or_fail(now.checked_add(Duration::minutes(30)), "expires");
        let cookie = build_session_cookie(&token, expires, Duration::minutes(30));

        // 构造后自检（同一套规则）。
        ok_or_fail(validate_production_cookie(&cookie), "validate built cookie");

        // 渲染检查：所有必需属性出现在 Set-Cookie 值中，且无 Domain。
        let rendered = cookie.to_string();
        assert!(rendered.starts_with(&format!("{SESSION_COOKIE_NAME}=")));
        assert!(rendered.contains("Secure"), "缺少 Secure: {rendered}");
        assert!(rendered.contains("HttpOnly"), "缺少 HttpOnly: {rendered}");
        assert!(
            rendered.contains("SameSite=Strict"),
            "缺少 SameSite=Strict: {rendered}"
        );
        assert!(rendered.contains("Path=/"), "缺少 Path=/: {rendered}");
        assert!(
            !rendered.to_ascii_lowercase().contains("domain"),
            "不得出现 Domain: {rendered}"
        );

        // 用 cookie crate 往返解析（不自写解析器，§22.6）。
        let parsed = ok_or_fail(Cookie::parse(rendered), "parse");
        assert_eq!(parsed.name(), SESSION_COOKIE_NAME);
        assert_eq!(parsed.value(), token.to_url_safe_string());
        assert_eq!(parsed.secure(), Some(true));
        assert_eq!(parsed.http_only(), Some(true));
        assert_eq!(parsed.same_site(), Some(SameSite::Strict));
        assert_eq!(parsed.path(), Some("/"));
        assert_eq!(parsed.domain(), None);
        assert_eq!(parsed.max_age(), Some(Duration::minutes(30)));
        assert_eq!(parsed.expires_datetime(), Some(expires));
    }

    #[test]
    fn removal_cookie_expires_in_the_past() {
        let cookie = build_session_cookie_removal();
        ok_or_fail(
            validate_production_cookie(&cookie),
            "validate removal cookie",
        );
        let parsed = ok_or_fail(Cookie::parse(cookie.to_string()), "parse");
        assert_eq!(parsed.name(), SESSION_COOKIE_NAME);
        assert_eq!(parsed.expires_datetime(), Some(OffsetDateTime::UNIX_EPOCH));
        assert_eq!(parsed.max_age(), Some(Duration::ZERO));
        assert_eq!(parsed.domain(), None);
    }

    #[test]
    fn validation_rejects_attribute_deviations() {
        // 手工构造偏离 §16.5 的 cookie，验证校验器各分支。
        let token = ok_or_fail(SessionToken::generate(), "generate");

        let no_secure = Cookie::build((SESSION_COOKIE_NAME, token.to_url_safe_string()))
            .http_only(true)
            .same_site(SameSite::Strict)
            .path("/")
            .build();
        assert!(matches!(
            validate_production_cookie(&no_secure),
            Err(SessionCookieError::NotSecure)
        ));

        let with_domain = Cookie::build((SESSION_COOKIE_NAME, token.to_url_safe_string()))
            .secure(true)
            .http_only(true)
            .same_site(SameSite::Strict)
            .path("/")
            .domain("example.com")
            .build();
        assert!(matches!(
            validate_production_cookie(&with_domain),
            Err(SessionCookieError::DomainSet)
        ));

        let wrong_name = Cookie::build(("operune-session", token.to_url_safe_string()))
            .secure(true)
            .http_only(true)
            .same_site(SameSite::Strict)
            .path("/")
            .build();
        assert!(matches!(
            validate_production_cookie(&wrong_name),
            Err(SessionCookieError::NameMismatch)
        ));
    }
}
