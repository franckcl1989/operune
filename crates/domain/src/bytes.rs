//! 有界字节的结构性包装（crate 内部共享，§13.3 validate-on-construct）。

use crate::error::{DomainError, ValueKind};

/// 有界字节缓冲（结构性上界）。
///
/// 不变量（validate-on-construct，§13.3）：`len(data) <= max`。用于
/// [`StateValue`](crate::StateValue) / [`ConfigValue`](crate::ConfigValue) /
/// event payload 等"平台不透明的有界字节"形态（§41.2：Config/State/Secret
/// 三分离——每个公开类型都是独立 newtype，不共享本包装的类型身份）。
///
/// 上限是 Domain 侧的结构性硬界（防止无界输入，§19.1）；宿主侧策略上限
/// （§7.4）必须不高于该界，属 application/适配层配置。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct BoundedBytes {
    data: Vec<u8>,
}

impl BoundedBytes {
    /// 构造并校验（validate-on-construct，§13.3）：超过 `max` 字节即失败。
    pub(crate) fn new(data: Vec<u8>, max: usize, kind: ValueKind) -> Result<Self, DomainError> {
        if data.len() > max {
            return Err(DomainError::invalid_value(
                kind,
                format!("must not exceed {max} bytes"),
            ));
        }
        Ok(Self { data })
    }

    /// 原始字节视图（只读）。
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// 字节数。
    pub(crate) fn len(&self) -> usize {
        self.data.len()
    }

    /// 是否为空（空值是合法值：如空 state value / 空配置快照）。
    pub(crate) fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// 取出底层字节（存储层 / 适配层边界输出，§13.3）。
    pub(crate) fn into_vec(self) -> Vec<u8> {
        self.data
    }
}
