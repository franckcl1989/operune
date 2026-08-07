use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{DomainError, ValueKind};

/// 路径长度上界（字节）。结构性上界：防止不可信 Component 声明无界路径
/// （§19.1 输入不可信）。
pub(crate) const MAX_PATH_LEN: usize = 4096;

/// 受校验的制品相对路径（§18.7 staging / quarantine / content-addressed 制品
/// 空间；§21.3 Web assets 以 `ContentDigest + asset path` 为缓存事实）。
///
/// 不变量（validate-on-construct，§13.3；构造时校验并归一化一次）：
/// - 非空，且归一化后至少含一个非空段；
/// - 相对路径：拒绝前导 `/`（绝对路径）；
/// - 拒绝 `.` / `..` 段：目录穿越直接拒绝而不是静默归一化，fail closed
///   （§32 安全测试：install 输入与 web asset path 无 traversal）；
/// - 分隔符统一为 `/`；拒绝 `\`（路径是跨平台持久语义，不因宿主 OS 而异；
///   宿主文件系统解析由平台 adapter 负责，§9.4 / §18.7）；
/// - 无控制字符；
/// - 长度 ≤ 4096 字节。
///
/// 归一化：连续分隔符折叠（`a//b` → `a/b`），尾部 `/` 去除（`a/` → `a`）。
///
/// 错误：解析失败返回 [`DomainError::InvalidValue`]。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ArtifactPath(String);

impl ArtifactPath {
    /// 解析并校验（§13.3 边界解析一次；内部保持归一化强类型）。
    pub fn new(value: impl Into<String>) -> Result<ArtifactPath, DomainError> {
        let value = value.into();
        validate_path(&value)?;
        Ok(ArtifactPath(normalize(&value)))
    }

    /// 归一化后的路径视图（只读，`/` 分隔、无 `.`/`..` 段、相对路径）。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn validate_path(value: &str) -> Result<(), DomainError> {
    if value.is_empty() {
        return Err(DomainError::invalid_value(
            ValueKind::ArtifactPath,
            "must not be empty",
        ));
    }
    if value.len() > MAX_PATH_LEN {
        return Err(DomainError::invalid_value(
            ValueKind::ArtifactPath,
            format!("must not exceed {MAX_PATH_LEN} bytes"),
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(DomainError::invalid_value(
            ValueKind::ArtifactPath,
            "must not contain control characters",
        ));
    }
    if value.contains('\\') {
        return Err(DomainError::invalid_value(
            ValueKind::ArtifactPath,
            "backslash is not a valid path separator; use '/'",
        ));
    }
    if value.starts_with('/') {
        return Err(DomainError::invalid_value(
            ValueKind::ArtifactPath,
            "must be relative (no leading '/')",
        ));
    }
    // 段级检查：`.` 与 `..` 直接拒绝（目录穿越，fail closed）。
    for segment in value.split('/') {
        if segment == "." || segment == ".." {
            return Err(DomainError::invalid_value(
                ValueKind::ArtifactPath,
                format!("path segment {segment:?} is not allowed (directory traversal)"),
            ));
        }
    }
    Ok(())
}

/// 折叠连续分隔符、去除首尾空段（`validate_path` 已保证相对且无 `.`/`..`）。
fn normalize(value: &str) -> String {
    value
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<&str>>()
        .join("/")
}

impl fmt::Display for ArtifactPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for ArtifactPath {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl Serialize for ArtifactPath {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ArtifactPath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ok;
    use proptest::prelude::*;

    #[test]
    fn accepts_plain_paths() {
        for path in [
            "a",
            "a/b",
            "a/b/c.wasm",
            "assets/icon.svg",
            "dir/with space",
            "数据/表.json",
        ] {
            let parsed = ok(ArtifactPath::new(path), path);
            assert_eq!(parsed.as_str(), path, "{path:?} must be accepted unchanged");
        }
    }

    #[test]
    fn normalizes_slashes() {
        assert_eq!(ok(ArtifactPath::new("a//b"), "a//b").as_str(), "a/b");
        assert_eq!(ok(ArtifactPath::new("a///b/"), "a///b/").as_str(), "a/b");
        assert_eq!(ok(ArtifactPath::new("a/"), "a/").as_str(), "a");
        assert_eq!(ok(ArtifactPath::new("a////"), "a////").as_str(), "a");
    }

    #[test]
    fn rejects_absolute_paths() {
        for path in ["/", "/abs", "/etc/passwd", "//x", "///y"] {
            assert!(
                matches!(
                    ArtifactPath::new(path),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::ArtifactPath,
                        ..
                    })
                ),
                "{path:?} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_traversal() {
        for path in [
            ".",
            "..",
            "../x",
            "a/../b",
            "a/./b",
            "a/..",
            "a/b/../../../c",
        ] {
            assert!(
                matches!(
                    ArtifactPath::new(path),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::ArtifactPath,
                        ..
                    })
                ),
                "{path:?} must be rejected (traversal)"
            );
        }
    }

    #[test]
    fn rejects_backslash_and_control() {
        for path in ["\\", "a\\b", "a/b\\c", "a\nb", "a\tb", "a\u{0}b"] {
            assert!(
                matches!(
                    ArtifactPath::new(path),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::ArtifactPath,
                        ..
                    })
                ),
                "{path:?} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_empty() {
        assert!(matches!(
            ArtifactPath::new(""),
            Err(DomainError::InvalidValue {
                kind: ValueKind::ArtifactPath,
                ..
            })
        ));
    }

    #[test]
    fn length_boundary() {
        let segment_4095 = "a".repeat(MAX_PATH_LEN - 1);
        let segment_4096 = "a".repeat(MAX_PATH_LEN);
        let segment_4097 = "a".repeat(MAX_PATH_LEN + 1);
        assert!(ArtifactPath::new(segment_4095).is_ok());
        assert!(ArtifactPath::new(segment_4096).is_ok());
        assert!(matches!(
            ArtifactPath::new(segment_4097),
            Err(DomainError::InvalidValue {
                kind: ValueKind::ArtifactPath,
                ..
            })
        ));
    }

    #[test]
    fn serde_roundtrip() {
        let path = ok(ArtifactPath::new("assets/icon.svg"), "path");
        let json = ok(serde_json::to_string(&path), "serialize");
        assert_eq!(json, "\"assets/icon.svg\"");
        assert_eq!(
            ok(serde_json::from_str::<ArtifactPath>(&json), "deserialize"),
            path
        );
    }

    #[test]
    fn serde_rejects_invalid() {
        // 反序列化边界同样执行校验（§13.3）。
        assert!(serde_json::from_str::<ArtifactPath>("\"../x\"").is_err());
        assert!(serde_json::from_str::<ArtifactPath>("\"/abs\"").is_err());
    }

    proptest! {
        #[test]
        fn parsed_path_is_normalized_relative_and_idempotent(s in prop::collection::vec(any::<char>(), 0..64)) {
            let s: String = s.into_iter().collect();
            if let Ok(path) = ArtifactPath::new(&s) {
                let normalized = path.as_str();
                prop_assert!(!normalized.is_empty());
                prop_assert!(!normalized.starts_with('/'));
                prop_assert!(!normalized.contains('\\'));
                prop_assert!(normalized.split('/').all(|seg| seg != "." && seg != ".."));
                // 归一化幂等：解析结果再解析得到同一路径。
                prop_assert_eq!(
                    normalized.parse::<ArtifactPath>().map(|p| p.as_str().to_string()),
                    Ok(normalized.to_string())
                );
            }
        }
    }
}
