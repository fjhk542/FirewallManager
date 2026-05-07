namespace FirewallManager
{
    /// <summary>
    /// 本地化服务接口
    /// 定义国际化文本获取的标准接口
    /// </summary>
    public interface ILocalizationService
    {
        /// <summary>
        /// 获取翻译文本
        /// </summary>
        /// <param name="key">文本键值，格式为 "section.key"</param>
        /// <param name="args">格式化参数</param>
        /// <returns>翻译后的文本</returns>
        string GetText(string key, params object[] args);

        /// <summary>
        /// 设置当前语言
        /// </summary>
        /// <param name="languageCode">语言代码（如 "en", "zh"）</param>
        void SetLanguage(string languageCode);

        /// <summary>
        /// 获取当前语言
        /// </summary>
        /// <returns>当前语言代码</returns>
        string GetCurrentLanguage();
    }
}
