# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-04-21

### Added
- 新增粘贴路径功能，支持从剪贴板粘贴多个路径
- 完善日志系统，详细记录所有操作
- 支持查看和管理日志
- 日志文件自动管理和清理
- 支持文件路径哈希值，避免同名文件冲突

### Changed
- 优化用户界面，调整按钮布局
- 优化日志窗口布局，按钮位于底部
- 改进扫描算法，提高扫描效率
- 优化多线程处理，减少资源占用
- 改进规则检查逻辑，确保规则状态准确

### Fixed
- 修复扫描过程中可能出现的崩溃问题
- 修复规则删除时的线程安全问题
- 修复日志查看窗口的显示问题
- 修复清空规则后更新时的计数问题
- 修复手动删除规则后更新时的状态同步问题

## [1.0.0] - 2025-12-17

### Added
- 初始版本发布
- 支持为单个可执行文件创建防火墙规则
- 支持扫描文件夹，为所有可执行文件批量创建防火墙规则
- 支持删除单个或所有防火墙规则
- 支持监控指定文件夹，自动为新添加的可执行文件创建规则
- 支持暂停、恢复和终止扫描过程
- 实时显示扫描进度
- 支持托盘图标，方便后台运行
- 支持白名单管理
- 支持查看规则详情

### Changed

### Fixed
