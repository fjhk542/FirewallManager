using System;

namespace FirewallManager
{
    /// <summary>
    /// 防火墙动作枚举
    /// </summary>
    public enum FirewallAction
    {
        /// <summary>
        /// 阻止
        /// </summary>
        Block = 0,
        
        /// <summary>
        /// 允许
        /// </summary>
        Allow = 1
    }

    /// <summary>
    /// 防火墙协议枚举
    /// </summary>
    public enum FirewallProtocol
    {
        /// <summary>
        /// 所有协议
        /// </summary>
        Any = 256,
        
        /// <summary>
        /// TCP协议
        /// </summary>
        Tcp = 6,
        
        /// <summary>
        /// UDP协议
        /// </summary>
        Udp = 17
    }

    /// <summary>
    /// 防火墙方向枚举
    /// </summary>
    public enum FirewallDirection
    {
        /// <summary>
        /// 入站
        /// </summary>
        Inbound = 1,
        
        /// <summary>
        /// 出站
        /// </summary>
        Outbound = 2
    }

    /// <summary>
    /// 工作状态枚举
    /// </summary>
    public enum WorkState
    {
        /// <summary>
        /// 空闲
        /// </summary>
        Idle,
        
        /// <summary>
        /// 运行中
        /// </summary>
        Running,
        
        /// <summary>
        /// 暂停
        /// </summary>
        Paused,
        
        /// <summary>
        /// 停止中
        /// </summary>
        Stopping
    }
}
