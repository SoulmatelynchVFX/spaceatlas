# 璃盘：只读基础工具

这是从个人存储分析原型中整理出的独立基础模块。目前提供 Windows 应用清单、指定路径统计及按应用 ID 查看安装目录占用，不包含网页界面、全盘应用归属、规则知识库、历史数据库或 AI 建议。

Python 3.11+，无需第三方依赖。在仓库根目录运行：

```powershell
# 只读取卸载注册表，不扫描应用目录，不执行卸载命令
python -m storage_inspector --list-apps

# 仅在明确指定后遍历一个文件或目录
python -m storage_inspector --path "D:\Example"

# 将下面的 ID 替换成 --list-apps 返回的当前 app_id
python -m storage_inspector --app registry.REPLACE_WITH_APP_ID
```

默认结果为标准输出中的 JSON，也可显式选择 CSV 或 NDJSON，不自动保存报告。不带参数只显示用法。程序不读取扫描文件正文，不清理扫描源或调用外部服务；仅在显式 --output 时创建报告，并清理自身临时报告，--force 可替换指定的已有报告目标。

每份 JSON 报告的顶层带有 `schema_version`（当前为整数 `1`）和 `report_type`：`--path` 为 `path_scan`，`--list-apps` 为 `application_inventory`，`--app` 为 `application_scan`。版本适用于整个文档，内层 `scan` 不重复添加版本字段。字段类型、空值、兼容规则及错误输出边界见 [报告字段规范](schema.md)。

## 中断扫描

`--path` 或 `--app` 的目录遍历期间按一次 Ctrl+C，收到中断后会关闭活动目录迭代器，并输出已有观测数据：`stop_reason` 为 `interrupted`，`partial` 为真，退出码为 130。应用模式的停止原因位于 `scan.stop_reason`，顶层也会标记部分结果。零文件的中断结果不代表目录为空，中断不是访问错误，不增加 `error_count`。

若中断发生在应用清单读取或扫描初始化阶段，还没有可返回的扫描报告，只在标准错误输出提示并返回 130。清理或输出阶段再次中断、强制终止进程时，不保证报告完整；阻塞的系统调用也可能延迟响应。本版不保存续扫状态，重新运行会重新遍历。

## 如何理解结果

### 限制单次扫描

`--path` 和 `--app` 支持可选的文件数及时长限制，可分别使用或同时使用：

```powershell
python -m storage_inspector --path "D:\Example" --max-files 10000 --max-seconds 5
python -m storage_inspector --app registry.REPLACE_WITH_APP_ID --max-seconds 5
```

不指定时保留原有完整遍历行为。`--max-files` 必须为正整数，限制计入的去重普通文件数，不是目录数；`--max-seconds` 必须为有限正数，仅约束目录统计阶段，不包含读取应用清单的时间。纯清单模式 `--list-apps` 不接受这些参数。

触及上限时保留当前统计，`stop_reason` 为 `max_files` 或 `max_seconds`，`partial` 为真，退出码为 2；应用模式还会在 `scan` 中显示停止原因。这不是完整总量，也不是可清理容量。即使恰好计入最后一个文件，触及上限仍保守标为部分结果；未触发限制时 `stop_reason` 为 `null`，但读取错误或跳过项仍可能使 `partial` 为真。

时长为软限制：在遍历步骤之间检查，不能中断已阻塞的系统调用。目录按需逐项枚举，提前停止会关闭已打开的目录迭代器。不同遍历顺序可能得到不同的部分结果；本版不提供断点续扫。

### 大文件排行

```powershell
python -m storage_inspector --path "D:\Example" --top-files 10
python -m storage_inspector --app registry.REPLACE_WITH_APP_ID --top-files 5 --max-seconds 5
```

`--top-files N` 接受正整数，仅用于 `--path` 和 `--app`。`largest_files`（应用模式为 `scan.largest_files`）列出至多 N 条记录，每条包含绝对 `path` 和 `logical_bytes`。按逻辑长度降序，同大小按路径字符串降序；硬链接只保留首次计入的路径。空目录或未指定该选项时列表为空。

排行在原有扫描中收集，不二次遍历、不读取文件正文；排行候选只保留至多 N 项（原有硬链接去重集合仍随文件数增长）。排行不会减少总量统计的文件数，也不改变链接、离线项及访问错误的处理。触及时长/数量限制、Ctrl+C 或有跳过/错误时，它仅表示已观测文件的排行，不保证覆盖全部大文件。文件大小不是可清理容量，列表不是删除建议；分享报告前应脱敏其中的完整文件路径。

### 排除指定目录

```powershell
python -m storage_inspector --path "D:\Example" --exclude-dir .git --exclude-dir node_modules
python -m storage_inspector --app registry.REPLACE_WITH_APP_ID --exclude-dir cache --top-files 10
```

`--exclude-dir NAME` 可重复指定，仅用于 `--path` 和 `--app`。在任意层级按单个目录名匹配，统一使用 Unicode `casefold` 不区分大小写；不接受路径、通配符、`.`、`..`、控制字符、Windows 文件名禁用字符及末尾点/空格。不展开环境变量，不读取 `.gitignore`，无默认排除项。显式选择的扫描根目录不因自身名称匹配而被排除；同名普通文件仍然计入。

扫描会读取目录项元数据以判断类型，但不枚举被排除目录及其后代。`exclude_dirs` 记录去重排序后的规范化规则；`excluded_directories` 仅计数实际遇到并排除的普通目录，不估算其内部文件数或大小。被排除目录内的嵌套匹配不额外计数；链接及离线属性项仍优先归入 `skipped`，读取元数据失败仍归入错误。应用模式的这些字段位于 `scan`。

只要实际排除了目录，`partial` 就为真，正常结束退出码为 2；`stop_reason` 保持 `null`，除非另有数量/时长限制或中断。规则未命中时不会仅因配置规则而标为部分结果。排除部分不会计入占用总量、文件数量或大文件排行，未扫描的占用不代表零；这不是完整占用，也不是隐私隔离或安全沙箱。

### 按扩展名汇总

```powershell
python -m storage_inspector --path "D:\Example" --by-extension
python -m storage_inspector --app registry.REPLACE_WITH_APP_ID --by-extension --exclude-dir cache
```

`--by-extension` 仅用于 `--path` 或 `--app`。输出 `extension_summary`（应用模式为 `scan.extension_summary`），每项包含 `extension`、`logical_bytes`、`file_count`。按逻辑字节数降序，同大小按扩展名字符串升序；未开启或没有计入文件时列表为空，零字节文件仍计数。

分组取文件名最后一个扩展名并使用 Unicode `casefold` 合并大小写，例如 `.TXT` 与 `.txt` 合并、`archive.tar.gz` 归入 `.gz`。无扩展名文件（如 `README`、`.env`）归入空字符串 `""`，`.config.json` 归入 `.json`；父目录名称不影响分组。这只是文件名线索，不读取正文，不验证真实类型、所属应用或清理安全性。

在同一次扫描中汇总，无额外遍历；额外内存随不同扩展名数量增长。分组沿用总量统计的硬链接去重：不同后缀的硬链接只归入首次计入路径的分组，遍历顺序变化可能改变归组。排除目录、链接/离线项及访问失败的文件不计入；受限或中断扫描只反映已观测范围，不能据此推断未扫描文件的分布。

### 按一级子目录汇总

```powershell
python -m storage_inspector --path "D:\Example" --by-directory --top-files 10
python -m storage_inspector --app registry.REPLACE_WITH_APP_ID --by-directory --by-extension
```

`--by-directory` 仅用于 `--path` 和 `--app`，输出 `directory_summary`（应用模式为 `scan.directory_summary`）。每项包含绝对 `path`、`kind`、`logical_bytes`、`file_count`，按逻辑字节数降序，同大小按路径字符串升序。一级子目录及其全部已观测后代归为一组，`kind` 为 `directory`；根目录直属文件归为路径等于扫描根的 `direct_files` 组，不包含子目录占用。显式扫描单文件时只有一个 `file` 组。

只列出至少计入一个普通文件的分组，零字节文件仍计数。未开启或没有计入文件时列表为空；空目录、全被去重的目录、被排除或无法读取的目录不会以零占用条目出现。目录缺席不代表不存在或没有占用，应结合扫描的 `partial`、错误和排除计数理解。分组不单独判定完整性；受限或中断扫描的分组也仅代表已观测范围。

汇总在原有遍历中完成，不重新扫描各个子目录，额外内存随实际出现的分组数增长。跨目录硬链接沿用全局去重，仅归入首次计入路径所在组，遍历顺序可能影响分组占用；因此分组不是各目录独立扫描的大小，也不能据此推算删除目录能释放多少空间。分组路径仍属于本机信息，分享前须脱敏。

### 跳过原因与路径明细

路径扫描自动输出 `skip_reason_counts`、`skip_details`、`skip_details_omitted`；应用安装目录扫描时位于 `scan` 中，无需新参数。每条明细包含绝对 `path` 和一个主要 `reason`。保留按遍历顺序遇到的前 100 条，总数继续计入 `skipped` 和各原因计数，超过上限的条数计入 `skip_details_omitted`，不挤占原有的 100 条访问错误明细额度。

| reason | 含义 |
|---|---|
| `symbolic_link` | 元数据显示为符号链接 |
| `reparse_point` | Windows 重解析点属性（包括 junction 等，不判断具体子类型） |
| `offline` | 离线属性 |
| `recall_on_open` | 打开时需召回的属性 |
| `recall_on_data_access` | 访问数据时需召回的属性 |
| `special_file` | 不属于普通文件或目录的其他文件类型 |

同一项只计一次：符号链接优先，其次按上表属性顺序选择首个命中原因；无这些标记的特殊类型使用 `special_file`。主要原因不是完整属性清单，不能仅据此认定属于某个云服务。判断只使用已经读取的元数据，不跟随链接、不打开文件正文，不为补明细重扫。

访问失败仍在 `errors` / `error_count`；主动排除仍在 `exclude_dirs` / `excluded_directories`，硬链接去重仍在 `duplicates`，不混入跳过明细。中断或触及限制时保留已收集明细，未遍历项及被跳过目录的后代不生成虚假记录。明细条数不是遗漏文件总数，更不是可释放容量；`--app` 若在扫描前拒绝不安全安装根目录，仍返回 `scan: null` 和原有错误说明。新增路径也需在分享报告前脱敏。

### 统计边界

- `--app` 只扫描精确匹配 ID 的 `InstallLocation`，不是整盘搜索，也不根据卸载命令推导路径。只接受本地盘符下的绝对目录，拒绝盘符根、网络/设备路径、相对路径、环境变量和链接/离线根目录。没有安装位置、ID 无效或目录无法读取时返回 JSON 错误及退出码 2，不以零占用冒充成功。
- 应用结果的 `scope` 为 `install_location_only`，`application` 为所选清单项，`scan` 为该目录的统计或 `null`，`inventory` 保留清单读取诊断。清单或目录统计有缺口时顶层 `partial` 为真。缓存、用户数据及其他盘上的文件未自动计入；目录内也可能有共享文件，不能把多个应用结果直接相加。

- 应用清单来自 HKLM/HKCU 卸载项及 HKLM 的 WOW6432Node 项，隐藏系统组件不列出。不同版本或安装位置分别保留；仅名称、发行商、版本和规范化安装路径都相同的记录合并。缺少安装路径的记录按注册表键分别保留，不猜测属于哪个已知安装。
- `app_id` 由上述身份字段生成，不依赖枚举顺序。与旧版仅按名称和发行商生成的 ID 不兼容；版本、路径或未知安装的注册表键变化也会改变 ID，不应用它追踪跨升级历史。
- 应用清单新增 `partial`、`error_count`、`errors` 和 `missing_locations`。根键不存在会列入 `missing_locations`，不视为权限错误；读取失败会返回部分结果及退出码 2，保留最多 100 条错误明细。没有错误也不代表覆盖了全部安装方式或注册表视图。
- 未注册的软件、便携应用和无法读取的注册表项可能缺失。安装位置仅是线索，不代表应用全部数据；本版不做应用占用汇总。
- `logical_bytes` 是观测到的文件逻辑长度，不是实际磁盘分配量，更不是可清理容量。
- 单次统计按文件身份去重硬链接；跳过遇到的符号链接、Windows reparse point（含 junction）及离线/召回属性项，不主动读取云占位文件正文。
- `partial` 表示存在读取错误、跳过/排除项或扫描提前停止。错误总数完整计数，明细最多保留 100 条。完整统计退出码为 0，部分结果及参数错误为 2（中断为 130）。
- 扫描不是原子快照，文件同时变化可能影响结果；链接检查也不提供针对恶意并发替换的沙箱保证。不要在不可信进程持续改写的目录上运行。

JSON 会包含本机应用信息和绝对路径，不要直接提交或公开。需要保存时将报告放在已忽略的 `.runtime/` 目录，分享前自行脱敏。

## CSV 文件明细

```powershell
python -m storage_inspector --path "D:\Example" --format csv
python -m storage_inspector --app registry.REPLACE_WITH_APP_ID --format csv --max-files 10000
```

CSV 仅用于 `--path` / `--app`，与 `--by-extension`、`--by-directory`、`--top-files` 互斥。可组合扫描上限和目录排除；默认 JSON 不变。

- stdout：UTF-8、无 BOM、CRLF 记录分隔，首行为 `path,size,modified`。空目录只有表头。路径为绝对路径，大小是逻辑字节数，修改时间为 UTC ISO 8601（例如 `2024-01-01T00:00:00.000000Z`）。时间不可用时留空，不猜测日期。
- stderr：扫描结束时输出一行带 `schema_version` 的 JSON 状态，沿用原扫描字段，另含 `csv.rows_written` 和 `csv.missing_modified`。未知时间使顶层 `partial` 为真；应用模式内层 `scan.partial` 仍仅描述扫描缺口。没有结束状态不能推断 CSV 完整。
- 退出码：完整为 0；部分扫描、未知时间或参数错误为 2；扫描中断为 130；CSV 写入失败为 1。参数错误在输出表头前拒绝；写入失败可能仅留下部分 CSV，不输出成功状态。中断发生在输出记录内部时，不保证最后一条记录完整。

记录沿用同一次扫描及其硬链接去重、链接/离线跳过、排除和上限规则；不重新读取元数据、不读取文件正文。按遍历顺序输出，不排序、不收集全部文件明细；硬链接去重索引仍随已见文件数增长。扫描不是原子快照。

CSV 的逗号、引号、换行由标准库转义，保留路径原值。**CSV 引号转义不等于电子表格公式注入防护**；导入时明确选择 UTF-8，并将路径列按文本处理，不对不可信文件名启用公式或自动转换。

可显式使用 `--output` 保存 CSV，状态仍写入 stderr；详见下方安全保存报告。自行使用 shell 重定向时将 stdout 和 stderr 分开，不使用 `2>&1`；检查退出码及状态。输出目标必须放在扫描树之外，避免 shell 提前创建报告文件后被计入扫描。Windows PowerShell 的文本重定向可能改变编码，需核对所用 shell 的行为，且不受 --output 的覆盖保护。报告含本机绝对路径，勿直接提交或公开。

格式实现参考 Python 3.11 [csv](https://docs.python.org/3.11/library/csv.html) 与 [datetime](https://docs.python.org/3.11/library/datetime.html) 文档。

## NDJSON 流式事件

```powershell
python -m storage_inspector --path "D:\Example" --format ndjson
python -m storage_inspector --app registry.REPLACE_WITH_APP_ID --format ndjson --max-files 10000
```

仅用于显式 `--path` / `--app`，不接受 `--list-apps`。stdout 逐行输出带 schema_version 的 file 事件（path、size、modified），每行写完立即刷新；最后输出 summary（exit_code、report），空目录只有 summary。普通运行 stderr 为空，参数或输出异常写入 stderr。格式和精确字段见 [事件契约](schema.md#ndjson-文件事件)。

修改时间是 UTC ISO 8601，未知为 null，并令 report.partial=true、退出码 2。已有跳过/排除、访问错误、扫描上限和中断语义保留；一次 Ctrl+C 的可报告扫描中断结束事件为 130。输出自身中断不追加 summary，避免把损坏尾行与汇总拼接；写入/刷新失败为 1。参数错误为 2，初始化中断为 130，这些情形可能没有任何事件。

消费者必须检查最后的 summary、report.partial、事件 exit_code 与最终进程退出码，不能只逐行解析成功就认为完整。末次刷新失败时即便看到 exit_code=0 的 summary 也必须以失败进程状态为准。按遍历顺序输出，不排序；不读取文件正文、不二次读取元数据、不缓存全部文件记录。可与 --max-files、--max-seconds、--exclude-dir 及三个排行/分组选项组合；分组与排行只在结束报告中出现，沿用原口径。

**内存边界**：仅文件事件输出缓存不随记录数量积累，单行大小仍取决于路径长度；现有精确硬链接去重 seen 集合随不同文件身份数量增长，目录遍历栈随深度增长，开启分组/排行也有各自开销。不是整体常量内存扫描，应用模式读取清单也需要内存。

内存测试分三层：用按需生成的普通字符串隔离输出器，验证 1000/100000 条事件的缓存边界；用故意保留全部事件的错误实现确认同一断言能失败；再分别记录原生路径处理下关闭/开启输出的扫描基线，以及唯一 inode 去重场景的峰值。pathlib 的进程级字符串驻留表也可能扩容，不能把无 inode 的扫描总峰值当成输出器独占内存，或把不同运行的峰值相减当作精确归属。测试不禁用字符串驻留、不创建十万个真实文件，也不作 NTFS 实际内存承诺。

不自动保存；可使用下节 --output 安全写出，或自行重定向到扫描树外。保留 stderr 与退出码，不使用 2>&1 混合输出。标准流通过 ASCII JSON 转义保留 Unicode 路径，消费者按 JSON 解码；shell 文本重定向可能另行改变文件编码，且不受 --output 的覆盖保护。报告包含绝对路径及应用信息，分享前脱敏。

## 安全保存报告

```powershell
# D:\Reports 必须已存在；不能放在 D:\Example 的扫描范围内
python -m storage_inspector --path "D:\Example" --output "D:\Reports\scan.json"
python -m storage_inspector --path "D:\Example" --format csv --output "D:\Reports\files.csv"
python -m storage_inspector --path "D:\Example" --format ndjson --output "D:\Reports\events.ndjson"
# 只有确定可替换该报告时才使用 --force
python -m storage_inspector --path "D:\Example" --output "D:\Reports\scan.json" --force
```

`--output PATH` 仅由用户显式指定，支持三种格式；后缀不决定格式，仍由 `--format` 决定。JSON 的应用清单也可导出，CSV/NDJSON 仍不支持清单模式。文件编码固定 UTF-8、无 BOM，stdout 不重复报告；CSV 的版本化状态仍在 stderr。`--force` 单独使用是参数错误（退出 2）。未指定 --output 时保持原有标准流行为。

安全规则：

- 父目录须已存在，不自动建目录；输出目标及父目录不能是链接、Windows 重解析点、离线/召回项，目标不能是目录、特殊文件或多硬链接文件。
- 保守要求输出位于扫描根及其所有后代之外，即使目标不存在也拒绝扫描树内路径；扫描整个卷时须将报告放在另一卷。应用模式以声明的安装目录为边界。这样最终文件和同目录临时文件都不进入本次扫描，也不用从源统计中隐式扣除它们。
- 默认拒绝覆盖。显式 --force 只允许替换范围外的普通单链接文件，不识别其内容是否确实是旧报告，使用者应核对路径。扫描源即使 --force 也不会覆盖。
- Windows 拒绝网络/设备路径、备用数据流、末尾点/空格等歧义路径；拒绝含 .. 的输出路径，不展开环境变量。
- 先在目标同目录写随机临时文件，刷新并同步后关闭，再检查父目录身份和目标元数据。新目标使用不覆盖的发布操作；已有目标使用同目录替换。权限、写入、同步或替换失败返回 1，旧目标不会因预先截断而丢失。临时文件正常退出时清理；清理失败会报告，强制杀进程可能留下 `.spaceatlas-*.tmp`。

部分扫描（上限、跳过、权限缺口）仍保存完整结构的部分报告，退出 2；可报告的遍历中断保存 partial 报告并退出 130。初始化中断或输出本身中断不提交临时报告，已有目标保留。因此有文件不等于扫描成功；须核对 partial、NDJSON summary 和最终退出码。CSV 状态可能在最终文件替换前写出，若随后保存失败，以进程失败状态和错误提示为准。

这些检查针对本机正常使用和可检测的并发变化，不是面对恶意进程持续替换路径的安全沙箱。检查与文件系统操作间仍有竞争窗口，尤其 --force 不提供跨进程锁；导出期间不要由其他程序移动父目录或修改目标。文件系统/权限不支持所需操作时失败，不降级为直接清空旧文件；不承诺断电后的目录持久性或保留旧目标 ACL。扫描只读边界保持不变。

## 验证

```powershell
python -m unittest discover -s tests -p "test_report_output.py" -v
python -m unittest discover -s tests -p "test_ndjson*.py" -v
python -m unittest discover -s tests -p "test_csv_output.py" -v
python -m unittest discover -s tests -p "test_report_schema.py" -v
python -m unittest discover -s tests -p "test_storage_inspector.py" -v
python -m unittest discover -s tests -p "test_inventory.py" -v
python -m unittest discover -s tests -p "test_app_scan.py" -v
python -m unittest discover -s tests -p "test_scan_limits.py" -v
python -m unittest discover -s tests -p "test_scan_interrupt.py" -v
python -m unittest discover -s tests -p "test_top_files.py" -v
python -m unittest discover -s tests -p "test_exclude_dirs.py" -v
python -m unittest discover -s tests -p "test_extension_summary.py" -v
python -m unittest discover -s tests -p "test_directory_summary.py" -v
python -m unittest discover -s tests -p "test_skip_details.py" -v
```

测试只使用临时合成文件及模拟错误，不扫描真实应用数据，不执行清理。完整原型的后续功能尚未作为这个基础模块发布。
