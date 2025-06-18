use std::sync::Arc;

/// 流式处理返回结果
#[derive(Debug)]
pub struct StreamingResult {
    /// 已处理的字节数（原始字节数）
    pub bytes_processed: u64,
    /// 如果配置了 keep_in_memory，则包含完整数据，否则为 None
    pub buffer: Option<Vec<u8>>,
}

/// 默认缓冲区大小（64KB）
const DEFAULT_BUFFER_SIZE: usize = 65536;

/// 流式加密配置
#[derive(Clone)]
pub struct StreamingConfig {
    /// 缓冲区大小
    pub buffer_size: usize,

    /// 是否在处理过程中显示进度
    pub show_progress: bool,

    /// 是否在内存中保留完整密文/明文
    pub keep_in_memory: bool,

    /// 可选的进度回调
    pub progress_callback: Option<Arc<dyn Fn(u64, Option<u64>) + Send + Sync>>,

    /// 可选的总字节数，用于进度计算
    pub total_bytes: Option<u64>,
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            buffer_size: DEFAULT_BUFFER_SIZE,
            show_progress: false,
            keep_in_memory: false,
            progress_callback: None,
            total_bytes: None,
        }
    }
}

/// 为 StreamingConfig 添加 builder 方法：设置总字节数
impl StreamingConfig {
    /// 设置总字节大小（用于进度回调）
    pub fn with_total_bytes(mut self, total: u64) -> Self {
        self.total_bytes = Some(total);
        self
    }
    /// 设置缓冲区大小
    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }
    /// 设置是否在控制台显示进度
    pub fn with_show_progress(mut self, show: bool) -> Self {
        self.show_progress = show;
        self
    }
    /// 设置是否在内存保留完整数据
    pub fn with_keep_in_memory(mut self, keep: bool) -> Self {
        self.keep_in_memory = keep;
        self
    }
    /// 设置进度回调
    pub fn with_progress_callback(mut self, callback: Arc<dyn Fn(u64, Option<u64>) + Send + Sync>) -> Self {
        self.progress_callback = Some(callback);
        self
    }
}