namespace FirewallManager
{
    /// <summary>
    /// 本地化服务实现类
    /// 包装 LangManager 静态类，实现 ILocalizationService 接口
    /// </summary>
    public class LocalizationService : ILocalizationService
    {
        /// <summary>
        /// 获取翻译文本
        /// </summary>
        /// <param name="key">文本键值，格式为 "section.key"</param>
        /// <param name="args">格式化参数</param>
        /// <returns>翻译后的文本</returns>
        public string GetText(string key, params object[] args)
        {
            return LangManager.GetText(key, args);
        }

        /// <summary>
        /// 设置当前语言
        /// </summary>
        /// <param name="languageCode">语言代码（如 "en", "zh"）</param>
        public void SetLanguage(string languageCode)
        {
            LangManager.SetLanguage(languageCode);
        }

        /// <summary>
        /// 获取当前语言
        /// </summary>
        /// <returns>当前语言代码</returns>
        public string GetCurrentLanguage()
        {
            return LangManager.GetCurrentLanguage();
        }
    }
}