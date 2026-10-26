# SpaceAtlas JSON 报告字段规范

本文适用于 `python -m storage_inspector` 输出的单份 JSON 文档。当前 `schema_version` 为整数 `1`；它标识报告结构，与软件版本无关。JSON 使用双空格缩进，非 ASCII 字符可写为 Unicode 转义，解析后的字符串值不变。对象键顺序不属于契约。

## 版本与兼容

- 先检查顶层 `schema_version` 和 `report_type`，再读取相应字段。版本作用于所有内层对象，内层没有独立版本。
- 无 `schema_version` 的历史报告属于未版本化格式，不自动认定为版本 1；旧报告仍可按旧约定人工查看。本工具没有报告导入或自动迁移功能。
- 同一版本允许新增字段；读取方应忽略不认识的字段。删除/改名字段、改变字段类型或既有语义需要提升整数版本。遇到未知版本或报告类型，应提示不支持而非假定兼容。枚举说明中列出的是版本 1 的当前取值，读取方应保留未知值并提示，不将其当作成功状态。
- 本次在原 JSON 顶层增加两个字段，原字段位置、值的含义和退出码保持原样。严格拒绝额外字段的旧读取方需要更新。
- 字段总是存在，除非明确标为“可选”。空数组表示没有条目；`null` 表示未开始扫描等特定状态，不能当作零占用。空汇总列表也可能因为未启用相应选项，不能据此推断目录为空。
- 字节数和计数是非负整数；接收方须保留整数精度，尤其是使用 JavaScript 等数字类型的客户端。`note`、错误消息是面向人的说明，措辞不作为稳定机器接口。

## 公共顶层字段

| 字段 | JSON 类型 | 含义 |
| --- | --- | --- |
| `schema_version` | integer | 当前为 `1`。 |
| `report_type` | string | `path_scan`、`application_inventory` 或 `application_scan`。 |
| `partial` | boolean | 当前报告存在已知缺口；各报告类型的判定见下文。 |
| `note` | string | 当前统计范围与限制说明。 |

`--path` 输出公共字段与“扫描对象”的字段（`partial` 只出现一次）。`--list-apps` 输出公共字段与“应用清单字段”。`--app` 输出公共字段与“单应用字段”。

## 扫描对象

用于 `path_scan` 的顶层以及 `application_scan.scan`。`path` 是显式目标经绝对路径规范化后的路径；不通过解析链接扩大目标。

| 字段 | JSON 类型 | 含义 |
| --- | --- | --- |
| `path` | string | 扫描目标绝对路径，可为目录或单文件。 |
| `logical_bytes` | integer | 已计入普通文件的逻辑字节数，硬链接去重；不代表磁盘分配量或可清理容量。 |
| `file_count` | integer | 已计入且去重后的普通文件数，零字节文件也计数。 |
| `skipped` | integer | 遇到的链接、离线/召回属性项或特殊文件数；不估算其后代数量。 |
| `duplicates` | integer | 因文件身份重复而未再次计入的普通文件条目数。 |
| `error_count` | integer | 扫描读取错误总数，不受明细上限影响。 |
| `errors` | array of object | 前 100 条扫描错误，结构见“扫描错误”；数组长度可能小于总数。 |
| `stop_reason` | string or null | `max_files`、`max_seconds`、`interrupted`；没有提前停止则为 `null`。 |
| `largest_files` | array of object | 开启 `--top-files` 时的前 N 个已计入文件，结构见“大文件条目”。 |
| `excluded_directories` | integer | 实际遇到并按目录名排除的普通目录数，不包含未访问后代。 |
| `exclude_dirs` | array of string | 规范化、去重、排序后的目录排除名称；可以有规则但没有命中。 |
| `extension_summary` | array of object | 开启 `--by-extension` 后的已计入文件分组，结构见“扩展名分组”。 |
| `directory_summary` | array of object | 开启 `--by-directory` 后的一级目录分组，结构见“目录分组”。 |
| `skip_reason_counts` | object | 原因字符串到计数的映射；键对应“跳过明细”的 reason，未发生的原因不输出。 |
| `skip_details` | array of object | 按遇到顺序保留前 100 个跳过项，结构见“跳过明细”。 |
| `skip_details_omitted` | integer | 超过明细上限而省略的跳过项数量。 |
| `partial` | boolean | 有读取错误、跳过项、实际排除目录或提前停止时为真；硬链接正常去重不会单独使它为真。 |

`skipped = sum(skip_reason_counts.values()) = len(skip_details) + skip_details_omitted`。启用对应分组时，组内 `logical_bytes` / `file_count` 之和等于扫描对象中的总值；只代表已观测范围。`partial: false` 也不意味着扫描是原子快照。

## 扫描错误

| 字段 | JSON 类型 | 含义 |
| --- | --- | --- |
| `path` | string | 读取失败的文件或目录路径。 |
| `message` | string | 系统错误说明，可能随平台和语言变化。 |

## 大文件条目

| 字段 | JSON 类型 | 含义 |
| --- | --- | --- |
| `path` | string | 首次计入的文件绝对路径。 |
| `logical_bytes` | integer | 文件逻辑字节数。 |

按字节数降序，同大小按路径字符串降序。部分扫描的排行仅覆盖已计入文件。

## 扩展名分组

| 字段 | JSON 类型 | 含义 |
| --- | --- | --- |
| `extension` | string | 文件名最后一个后缀，经 casefold；无后缀为 `""`。 |
| `logical_bytes` | integer | 本组已计入逻辑字节数。 |
| `file_count` | integer | 本组已计入普通文件数。 |

按字节数降序，同大小按扩展名字符串升序。文件名后缀不验证真实内容类型。

## 目录分组

| 字段 | JSON 类型 | 含义 |
| --- | --- | --- |
| `path` | string | 组对应的绝对路径。 |
| `kind` | string | `directory`：一级子目录及后代；`direct_files`：根目录直属文件；`file`：显式目标是单文件。 |
| `logical_bytes` | integer | 本组已计入逻辑字节数。 |
| `file_count` | integer | 本组已计入普通文件数。 |

按字节数降序，同大小按路径字符串升序。只列出至少计入一个文件的组。跨目录硬链接仅归于首次计入路径所在组；缺席的组不能当作零占用。

## 跳过明细

| 字段 | JSON 类型 | 含义 |
| --- | --- | --- |
| `path` | string | 遇到的跳过项绝对路径。 |
| `reason` | string | 一个主要原因：`symbolic_link`、`reparse_point`、`offline`、`recall_on_open`、`recall_on_data_access`、`special_file`。 |

同一项只选择一个主要原因，优先级和处理边界见 [使用说明](storage-inspector.md#跳过原因与路径明细)。原因不是完整文件属性，也不能据此判断实际本地落盘量。

## 应用清单字段

| 字段 | JSON 类型 | 含义 |
| --- | --- | --- |
| `applications` | array of object | 已读取的应用条目，结构见“应用条目”。 |
| `error_count` | integer | 注册表读取错误总数。 |
| `errors` | array of object | 前 100 条注册表错误，结构见“注册表错误”。 |
| `missing_locations` | array of string | 不存在的卸载根键位置；缺失本身不记读取错误。 |
| `source` | string | 当前为 `Windows uninstall registry`。 |

清单 `partial` 为 `error_count > 0`。无读取错误不代表枚举了所有安装方式；空清单遇到错误时不能当作未安装软件。按名称 casefold、版本、规范化安装路径、app_id 排序。

## 应用条目

| 字段 | JSON 类型 | 含义 |
| --- | --- | --- |
| `app_id` | string | 当前清单身份 ID；版本/安装路径变化可能改变 ID，不是跨升级的稳定追踪键。 |
| `name` | string | 注册表显示名称。 |
| `publisher` | string | 发行商，缺失时为空字符串。 |
| `version` | string | 应用版本，缺失时为空字符串。 |
| `install_location` | string | 声明的安装位置，缺失时为空字符串，不代表应用全部数据位置。 |
| `uninstall_command` | string | 注册表中读取的卸载命令文本；仅作为数据输出，从不执行。 |
| `source` | string | 当前为 `注册表`。 |

## 注册表错误

| 字段 | JSON 类型 | 含义 |
| --- | --- | --- |
| `location` | string | 注册表位置或枚举索引位置。 |
| `operation` | string | 失败阶段：当前为 `open_root`、`query_root`、`read_entry` 或 `read_value[N]`。 |
| `message` | string | 系统错误说明。 |
| `winerror` | integer or null | 系统提供的 Windows 错误编号；未提供时为 `null`。 |

## 单应用字段

| 字段 | JSON 类型 | 含义 |
| --- | --- | --- |
| `requested_app_id` | string | 用户传入的应用 ID，包含未找到的 ID。 |
| `scope` | string | 当前为 `install_location_only`，只统计声明安装目录。 |
| `application` | object or null | 唯一选中的“应用条目”；没有唯一匹配则为 `null`。 |
| `scan` | object or null | “扫描对象”；扫描前拒绝目标或无法读取根目录时为 `null`，不生成零占用假报告。 |
| `inventory` | object | 选取应用时的清单诊断，结构见“内层清单诊断”。 |
| `error` | string | 可选；仅在无法开始安装目录扫描时出现。 |

顶层 `partial` 在清单有读取错误、扫描有缺口或无法开始扫描时为真。即使 `scan.partial` 为假，清单错误仍可使顶层为真；调用者应检查顶层。扫描中的访问失败放在 `scan.errors`，不添加顶层 `error`。

## 内层清单诊断

| 字段 | JSON 类型 | 含义 |
| --- | --- | --- |
| `partial` | boolean | 应用清单是否存在读取错误。 |
| `error_count` | integer | 注册表错误总数。 |
| `errors` | array of object | 前 100 条“注册表错误”。 |
| `missing_locations` | array of string | 未找到的卸载根键。 |

## CSV 模式的状态报告

`--format csv` 的 stdout 不是 JSON；列契约为 `path,size,modified`，依次表示绝对路径、逻辑字节数和 UTC ISO 8601 修改时间（六位小数、`Z` 后缀；未知为空）。列值保留原路径，不进行公式转义。详见 [CSV 使用说明](storage-inspector.md#csv-文件明细)。

stderr 在结束时输出一行 JSON，沿用本文的版本和路径/单应用字段，并额外包含 `csv` 对象：`rows_written` 为成功写入的记录数，`missing_modified` 为无法表示修改时间的文件数，均为非负整数。后者非零使顶层 `partial` 为真，应用内层扫描状态不受该导出字段影响。默认 JSON 不添加此对象。

CSV 完整退出 0，部分结果或参数错误退出 2，中断退出 130，输出失败退出 1。参数错误、扫描前中断或输出失败可能没有 JSON 状态；输出过程中中断也不保证最后一条 CSV 或状态完整。不能仅凭表头或已有行判断完整性。

## NDJSON 文件事件

`--format ndjson` 是与默认 JSON 文档不同的流式容器，遵循同一 `schema_version: 1` 字段约定。用于 `--path` / `--app`，不用于 `--list-apps`。每个计入的去重普通文件输出一行，按遍历顺序，不保证排序；硬链接仅输出首次计入的路径。每行独立 JSON，不包含表头或空行。

| 字段 | JSON 类型 | 含义 |
| --- | --- | --- |
| `schema_version` | integer | 当前为 `1`；约束此事件及结束报告的兼容语义。 |
| `event` | string | 固定为 `file`。 |
| `path` | string | 计入文件的绝对路径；Unicode、引号及换行通过 JSON 转义保留。 |
| `size` | integer | 非负逻辑字节数，不代表实际分配量或可清理容量。 |
| `modified` | string or null | UTC ISO 8601，六位小数、Z 后缀；不可表示或缺失为 null。 |

## NDJSON 结束事件

正常结束或可报告的部分扫描仅输出一个结束事件，位于所有文件事件之后；空目录仅有此行。新可选字段可增补；解析器应忽略未知字段。新增事件类型时解析器不得把未知事件当作 file 或结束信号；改变既有字段含义/类型须按版本兼容约定处理。

| 字段 | JSON 类型 | 含义 |
| --- | --- | --- |
| `schema_version` | integer | 当前为 `1`，与 report.schema_version 一致。 |
| `event` | string | 固定为 `summary`。 |
| `exit_code` | integer | 输出此事件时预计退出码：0 完整、2 部分、130 扫描中断；最终进程退出状态仍须检查。 |
| `report` | object | 与对应路径/应用 JSON 报告相同的字段，额外包含 ndjson 诊断对象。 |

`report.ndjson` 包含非负整数 `files_written`（成功写入并刷新到输出流的文件事件数）与 `missing_modified`（修改时间不可表示的计数）。后者非零使 report.partial 为真，完整扫描退出码由 0 变为 2；应用内层 scan.partial 仍只反映扫描缺口。正常情况下 files_written 等于路径报告 file_count 或应用报告 scan.file_count；中断发生在记录形成与写出之间时可能更少，仍明确标记部分结果。

`report` 保留跳过/错误/排除及停止原因；启用可选排行/分组时也保留相应字段。被拒绝的应用目标输出 summary（report.scan 为 null、partial 为真），不伪造空扫描。默认 JSON 与 CSV 不新增 ndjson 字段。

扫描期间 Ctrl+C：在可以安全形成报告时输出 partial=true、exit_code=130 的结束事件。初始化/注册表读取阶段中断没有结束事件；记录写入或刷新时中断退出 130，不追加 summary，因为尾行可能已损坏。写入/刷新失败退出 1，不重试或继续扫描。若 summary 已写入但最终刷新失败，行内 exit_code 可能仍为 0，进程却非零，不能仅凭结束行认定成功。强制终止也可能留下无结束事件或不完整行。

完整流必须满足：每行可解析、最后一个事件为 summary、report.partial=false、结束事件 exit_code=0 且进程退出码为 0。即便已有每行均合法，缺 summary 也不完整。输出采用 ASCII JSON 转义（同时兼容 UTF-8），每条事件换行并立即刷新；底层 Windows 文本流可能使用 CRLF。刷新不是磁盘持久化保证。

## 退出码与无报告情形

下表为默认 JSON 模式；CSV 模式见上节。

| 退出码 | 输出 |
| --- | --- |
| `0` | JSON 报告完整（范围仍受上述限制）；`--help` 则输出用法文本。 |
| `2` | 扫描/清单部分结果输出带版本的 JSON；参数无效或平台不支持时仅 stderr 错误，不输出 JSON。 |
| `130` | 遍历中断时输出带版本的部分报告；报告尚未形成时中断则仅 stderr 提示。 |

不要只凭退出码 2 断定存在 JSON，需检查 stdout。强制终止或输出过程再次中断不保证完整 JSON。报告包含本机路径、应用信息和卸载命令，分享前应脱敏。
