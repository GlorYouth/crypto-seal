/// 流式处理返回结果
#[derive(Debug)]
pub struct StreamingResult {
    /// 已处理的字节数（原始字节数）
    pub bytes_processed: u64,
    /// 如果配置了 keep_in_memory，则包含完整数据，否则为 None
    pub buffer: Option<Vec<u8>>,
}

