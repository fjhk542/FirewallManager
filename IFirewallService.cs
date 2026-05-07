using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace FirewallManager
{
    /// <summary>
    /// 防火墙服务接口
    /// 定义防火墙操作的标准接口
    /// </summary>
    public interface IFirewallService : IDisposable
    {
        /// <summary>
        /// 初始化防火墙组件
        /// </summary>
        /// <returns>是否初始化成功</returns>
        bool InitializeFirewallComponents();

        /// <summary>
        /// 检查防火墙规则是否存在
        /// </summary>
        /// <param name="ruleName">规则名称</param>
        /// <returns>规则是否存在</returns>
        bool CheckRuleExists(string ruleName);

        /// <summary>
        /// 为可执行文件创建防火墙规则
        /// </summary>
        /// <param name="exePath">可执行文件路径</param>
        /// <returns>是否创建成功</returns>
        bool CreateRuleForExe(string exePath);

        /// <summary>
        /// 删除防火墙规则
        /// </summary>
        /// <param name="ruleName">规则名称</param>
        /// <returns>是否删除成功</returns>
        bool DeleteRule(string ruleName);

        /// <summary>
        /// 删除所有由本程序创建的防火墙规则
        /// </summary>
        /// <returns>删除的规则数量</returns>
        int ClearAllRules();

        /// <summary>
        /// 更新防火墙规则
        /// 扫描指定路径并为所有可执行文件创建规则
        /// </summary>
        /// <param name="monitoredTargets">监控目标列表</param>
        /// <param name="cancellationToken">取消令牌</param>
        /// <param name="updateUI">UI更新回调</param>
        /// <returns>处理结果，包含添加的规则数和跳过的规则数</returns>
        Task<(int addedCount, int skippedCount)> UpdateFirewallRules(List<dynamic> monitoredTargets, CancellationToken cancellationToken, Action<object, string> updateUI);

        /// <summary>
        /// 获取规则详情
        /// </summary>
        /// <param name="ruleName">规则名称</param>
        /// <returns>规则对象，如果不存在则返回 null</returns>
        dynamic GetRuleDetails(string ruleName);

        /// <summary>
        /// 获取所有由本程序创建的规则名称
        /// </summary>
        /// <returns>规则名称列表</returns>
        List<string> GetAllRuleNames();
    }
}
