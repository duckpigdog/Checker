# Kunlun-M（Kunlun-Mirror）代码审计原理解析（基于本目录源码）

> 结论先行：Kunlun-M 是一套以 **“规则驱动的静态语义分析（AST + 反向回溯）”** 为核心的白盒扫描系统。整体流程是：
> 1) 用规则（CVI）做 **快速定位候选点**（regex / 文件名 / 特定模式），2) 对候选点进入 **AST 语义引擎**，3) 对敏感点参数做 **递归回溯**（跨函数、跨 include），4) 综合 **tamper（净化/输入控制）** 判定为漏洞/已修复/疑似，5) 将结果与回溯链写入数据库并可导出。

---

## 1. 代码结构与入口

- 工具入口脚本：[kunlun.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/kunlun.py)
  - 初始化 Django 环境后调用 `core.main()`（见 [kunlun.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/kunlun.py#L8-L21)）。
- 主入口在 [core/__init__.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/__init__.py) 的 `main()`：
  - CLI 子命令：`init / config / scan / show / console / plugin / web`（见 [core/__init__.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/__init__.py#L52-L147)）。
  - `scan` 子命令最终调用 `cli.start(...)`（见 [core/__init__.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/__init__.py#L249-L313)）。

**代码：入口脚本（kunlun.py）**

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re
import sys

# for django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Kunlun_M.settings')

import django

django.setup()

from core import main


if __name__ == '__main__':

    sys.argv[0] = re.sub(r'(-script\.pyw?|\.exe)?$', '', sys.argv[0])
    sys.exit(main())
```

**代码：CLI 主入口与 scan 调度（core/__init__.py:main）**

```python
def main():
    try:
        # arg parse
        t1 = time.time()
        parser = argparse.ArgumentParser(prog=__title__, description=__introduction__.format(detail="Main Program"), epilog=__epilog__, formatter_class=argparse.RawDescriptionHelpFormatter, usage=argparse.SUPPRESS)

        subparsers = parser.add_subparsers()

        # init
        parser_group_init = subparsers.add_parser('init', help='Kunlun-M init before use.')
        parser_group_init.add_argument('init', choices=['initialize', 'checksql'], default='init', help='check and migrate SQL')
        parser_group_init.add_argument('appname', choices=['index', 'dashboard', 'backend', 'api'],  nargs='?', default='index',
                                       help='Check App name')
        parser_group_init.add_argument('migrationname', default='migrationname',  nargs='?', help='Check migration name')

        # load config into database
        parser_group_core = subparsers.add_parser('config', help='config for rule&tamper', description=__introduction__.format(detail='config for rule&tamper'), epilog=__database_epilog__, formatter_class=argparse.RawDescriptionHelpFormatter, usage=argparse.SUPPRESS, add_help=True)
        parser_group_core.add_argument('load', choices=['load', 'recover', 'loadtamper', 'retamper'], default=False, help='operate for rule&tamper')

        parser_group_scan = subparsers.add_parser('scan', help='scan target path', description=__introduction__.format(detail='scan target path'), epilog=__scan_epilog__, formatter_class=argparse.RawDescriptionHelpFormatter, add_help=True)
        parser_group_scan.add_argument('-t', '--target', dest='target', action='store', default='', metavar='<target>', help='file, folder')
        parser_group_scan.add_argument('-f', '--format', dest='format', action='store', default='csv', metavar='<format>', choices=['html', 'json', 'csv', 'xml'], help='vulnerability output format (formats: %(choices)s)')
        parser_group_scan.add_argument('-o', '--output', dest='output', action='store', default='', metavar='<output>', help='vulnerability output STREAM, FILE')
        parser_group_scan.add_argument('-r', '--rule', dest='special_rules', action='store', default=None, metavar='<rule_id>', help='specifies rules e.g: 1000, 1001')
        parser_group_scan.add_argument('-tp', '--tamper', dest='tamper_name', action='store', default=None, metavar='<tamper_name>', help='tamper repair function e.g: wordpress')
        parser_group_scan.add_argument('-l', '--log', dest='log', action='store', default=None, metavar='<log>', help='log name')
        parser_group_scan.add_argument('-lan', '--language', dest='language', action='store', default=None, help='set target language')
        parser_group_scan.add_argument('-b', '--blackpath', dest='black_path', action='store', default=None, help='black path list')

        # for api
        parser_group_scan.add_argument('-a', '--api', dest='api', action='store_true', default=False,
                                       help='without any output for shell')
        parser_group_scan.add_argument('-y', '--yes', dest='yes', action='store_true', default=False,
                                       help='without any output for shell')
        parser_group_scan.add_argument('-np', '--newpro', dest='newpro', action='store_true', default=False,
                                       help='Default use new project for scan task.')
        parser_group_scan.add_argument('--origin', dest='origin', action='store', default=None, metavar='<origin>', help='project origin')
        parser_group_scan.add_argument('-des', '--description', dest='description', action='store', default=None, metavar='<description>', help='project description')

        # for log
        parser_group_scan.add_argument('-d', '--debug', dest='debug', action='store_true', default=False, help='open debug mode')

        # for scan profile
        parser_group_scan.add_argument('-uc', '--unconfirm', dest='unconfirm', action='store_true', default=False, help='show unconfirmed vuls')
        parser_group_scan.add_argument('-upc', '--unprecom', dest='unprecom', action='store_true', default=False, help='without Precompiled')

        # for vendor vuln scan
        parser_group_scan.add_argument('--without-vendor', dest='without_vendor', action='store_true', default=False, help='without scan vendor vuln (default open)')

        # args = parser.parse_args()
        args = parser.parse_known_args()[0]

        # log
        log(logging.INFO)

        # 其余需要验证
        args = parser.parse_args()

        if hasattr(args, "debug") and args.debug:
            logger.setLevel(logging.DEBUG)

        if not hasattr(args, "target") or args.target == '':
            parser.print_help()
            exit()

        # for api close log
        if hasattr(args, "api") and args.api:
            log_rm()

        cli.start(args.target, args.format, args.output, args.special_rules, sid, args.language, args.tamper_name, args.black_path, args.unconfirm, args.unprecom)

        logger.info('[INIT] Done! Consume Time:{ct}s'.format(ct=t2 - t1))

    except KeyboardInterrupt:
        logger.warning("[KunLun-M] Stop Kunlun-M.")
        sys.exit(0)

    except Exception as e:
        exc_msg = traceback.format_exc()
        logger.warning(exc_msg)
```

---

## 2. 扫描主流程（从目标目录到漏洞结果）

主流程在 [core/cli.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/cli.py) 的 `start()`（见 [cli.start](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/cli.py#L183-L276)）：

1. **收集文件**
   - `Directory(...).collect_files()` 统计与收集目标文件列表（见 [cli.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/cli.py#L226-L228)）。
   - 支持 `.kunlunmignore` 黑名单（见 [cli.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/cli.py#L211-L213) 与 [Pretreatment.get_path](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/pretreatment.py#L55-L68)）。

2. **语言/框架识别**
   - `Detection(target_directory, files)` 用 `rules/languages.xml` + `rules/frameworks.xml` + 依赖文件来推断（见 [detection.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/detection.py#L46-L116)）。

3. **AST 预处理（预编译）**
   - `ast_object.init_pre(...); ast_object.pre_ast_all(...)` 将目标文件解析为 AST 并缓存（见 [cli.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/cli.py#L251-L254)）。
   - `Pretreatment` 会按语言分别处理：
     - PHP：基于 `phply` 生成 AST 节点列表，并额外提取 `define()` 常量（见 [pretreatment.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/pretreatment.py#L101-L153)）。
     - JavaScript：基于 `esprima`（同文件后续分支）。
     - Chrome Ext：解包 `.crx`、解析 `manifest.json` 并把子 JS/HTML 加入队列（见 [pretreatment.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/pretreatment.py#L154-L259)）。
   - AST 获取统一接口：`ast_object.get_nodes(filepath, ...)`（见 [pretreatment.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/pretreatment.py#L388-L414)）。

4. **规则扫描**
   - `scan(...)` 会加载规则、并发执行每条规则（见 [core/engine.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/engine.py#L164-L213)）。
   - 每条规则由 `SingleRule.process()` 负责：先 “命中候选点”，再做“语义验证”（见 [SingleRule.process](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/engine.py#L524-L617)）。

5. **结果落库与导出**
   - 对每条最终漏洞写 `ScanResult`，并把回溯链（ResultFlow）逐节点写入数据库（见 [core/engine.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/engine.py#L241-L262)）。
   - CLI 最后可 `write_to_file(..., format=html/json/csv/xml)` 导出（见 [utils/export.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/utils/export.py#L119-L203)）。
   - Web Dashboard 与 API 在 `web/` 目录下，扫描任务/结果均来自数据库模型（见 [README.md](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/README.md#L159-L185)）。

**代码：CLI start()（收集文件 → 预编译 AST → 扫描 → 导出）**

```python
def start(target, formatter, output, special_rules, a_sid=None, language=None, tamper_name=None, black_path=None, is_unconfirm=False, is_unprecom=False):
    """
    Start CLI
    :param black_path: 
    :param tamper_name:
    :param language: 
    :param target: File, FOLDER, GIT
    :param formatter:
    :param output:
    :param special_rules:
    :param a_sid: all scan id
    :return:
    """
    global ast_object
    # generate single scan id
    s_sid = get_sid(target)
    r = Running(a_sid)
    data = (s_sid, target)
    r.init_list(data=target)
    r.list(data)

    report = '?sid={a_sid}'.format(a_sid=a_sid)
    d = r.status()
    d['report'] = report
    r.status(d)

    task_id = a_sid

    # 加载 kunlunmignore
    load_kunlunmignore()

    # parse target mode and output mode
    pa = ParseArgs(target, formatter, output, special_rules, language, black_path, a_sid=None)
    target_mode = pa.target_mode
    output_mode = pa.output_mode
    black_path_list = pa.black_path_list

    # target directory
    try:
        logger.info('[CLI] Target Mode: {}'.format(target_mode))
        target_directory = pa.target_directory(target_mode)
        logger.info('[CLI] Target : {d}'.format(d=target_directory))

        # static analyse files info
        files, file_count, time_consume = Directory(target_directory, black_path_list).collect_files()

        # vendor check
        project_id = get_and_check_scantask_project_id(task_id)
        Vendors(task_id, project_id, target_directory, files)

        # detection main language and framework
        if not language:
            dt = Detection(target_directory, files)
            main_language = dt.language
            main_framework = dt.framework
        else:
            main_language = pa.language
            main_framework = pa.language

        logger.info('[CLI] [STATISTIC] Language: {l} Framework: {f}'.format(l=",".join(main_language), f=main_framework))
        logger.info('[CLI] [STATISTIC] Files: {fc}, Extensions:{ec}, Consume: {tc}'.format(fc=file_count,
                                                                                           ec=len(files),
                                                                                           tc=time_consume))

        if pa.special_rules is not None:
            logger.info('[CLI] [SPECIAL-RULE] only scan used by {r}'.format(r=','.join(pa.special_rules)))

        # Pretreatment ast object
        ast_object.init_pre(target_directory, files)
        ast_object.pre_ast_all(main_language, is_unprecom=is_unprecom)

        # scan
        scan(target_directory=target_directory, a_sid=a_sid, s_sid=s_sid, special_rules=pa.special_rules,
             language=main_language, framework=main_framework, file_count=file_count, extension_count=len(files),
             files=files, tamper_name=tamper_name, is_unconfirm=is_unconfirm)

        # show result
        display_result(task_id)

    except KeyboardInterrupt as e:
        logger.error("[!] KeyboardInterrupt, exit...")
        exit()
    except Exception:
        result = {
            'code': 1002,
            'msg': 'Exception'
        }
        Running(s_sid).data(result)
        raise

    # 输出写入文件
    write_to_file(target=target, sid=s_sid, output_format=formatter, filename=output)
```

**代码：Pretreatment 预编译 AST 与 get_nodes()（PHP define 常量提取 + 按行截断）**

```python
async def pre_ast(self):

    while not self.target_queue.empty():

        fileext = self.target_queue.get()

        if not self.lan:
            break

        if fileext[0] in ext_dict['php'] and 'php' in self.lan:
            for filepath in fileext[1]['list']:
                all_nodes = []
                filepath = self.get_path(filepath)
                self.pre_result[filepath] = {}
                self.pre_result[filepath]['language'] = 'php'
                self.pre_result[filepath]['ast_nodes'] = []

                fi = codecs.open(filepath, "r", encoding='utf-8', errors='ignore')
                code_content = fi.read()
                fi.close()

                try:
                    if not self.is_unprecom:
                        parser = make_parser()
                        all_nodes = parser.parse(code_content, debug=False, lexer=lexer.clone(), tracking=True)
                    else:
                        all_nodes = []

                    self.pre_result[filepath]['ast_nodes'] = all_nodes

                except SyntaxError as e:
                    logger.warning('[AST] [ERROR] parser {} SyntaxError'.format(filepath))
                    continue

                except AssertionError as e:
                    logger.warning('[AST] [ERROR] parser {}: {}'.format(filepath, traceback.format_exc()))
                    continue

                except:
                    logger.warning('[AST] something error, {}'.format(traceback.format_exc()))
                    continue

                for node in all_nodes:
                    if isinstance(node, php.FunctionCall) and node.name == "define":
                        define_params = node.params

                        if define_params:
                            logger.debug(
                                "[AST][Pretreatment] new define {}={}".format(define_params[0].node,
                                                                              define_params[1].node))

                            key = define_params[0].node
                            if isinstance(key, php.Constant):
                                key = key.name

                            self.define_dict[key] = define_params[1].node

        gc.collect()

    return True

def get_nodes(self, filepath, vul_lineno=None, lan=None):
    filepath = os.path.normpath(filepath)

    if filepath in self.pre_result:
        if vul_lineno:
            if lan == 'javascript':
                backnodes = lambda: None
                backnodes.body = []
                allnodes = self.pre_result[filepath]['ast_nodes'].body if self.pre_result[filepath]['ast_nodes'] else []

                for node in allnodes:
                    if node.loc.start.line <= int(vul_lineno):
                        backnodes.body.append(node)

                return backnodes

        return self.pre_result[filepath]['ast_nodes']

    elif os.path.join(self.target_directory, filepath) in self.pre_result:
        return self.pre_result[os.path.join(self.target_directory, filepath)]['ast_nodes']

    else:
        logger.warning("[AST] file {} parser not found...".format(filepath))
        return False
```

**代码：规则并发扫描与结果落库（core/engine.py:scan）**

```python
def scan(target_directory, a_sid=None, s_sid=None, special_rules=None, language=None, framework=None, file_count=0,
         extension_count=0, files=None, tamper_name=None, is_unconfirm=False):
    r = Rule(language)
    vulnerabilities = r.vulnerabilities
    rules = r.rules(special_rules)
    find_vulnerabilities = []
    newcore_function_list = {}

    def store(result):
        if result is not None and isinstance(result, list) is True:
            for res in result:
                res.file_path = res.file_path
                find_vulnerabilities.append(res)
        else:
            logger.debug('[SCAN] [STORE] Not found vulnerabilities on this rule!')

    async def start_scan(target_directory, rule, files, language, tamper_name):
        result = scan_single(target_directory, rule, files, language, tamper_name, is_unconfirm, newcore_function_list)
        store(result)

    if len(rules) == 0:
        logger.critical('no rules!')
        return False
    logger.info('[PUSH] {rc} Rules'.format(rc=len(rules)))
    scan_list = []

    for idx, single_rule in enumerate(sorted(rules.keys())):
        r = getattr(rules[single_rule], single_rule)
        rule = r()

        if rule.status is False and len(rules) != 1:
            logger.info('[CVI_{cvi}] [STATUS] OFF, CONTINUE...'.format(cvi=rule.svid))
            continue

        scan_list.append(start_scan(target_directory, rule, files, language, tamper_name))

    loop = asyncio.get_event_loop()
    loop.run_until_complete(asyncio.gather(*scan_list))

    loop.stop()

    for idx, x in enumerate(find_vulnerabilities):
        trigger = '{fp}:{ln}'.format(fp=x.file_path.replace(target_directory, ""), ln=x.line_number)
        commit = u'@{author}'.format(author=x.commit_author)
        try:
            code_content = x.code_content[:50].strip()
        except AttributeError as e:
            code_content = x.code_content.decode('utf-8')[:100].strip()
        row = [idx + 1, x.id, x.rule_name, x.language, trigger, commit,
               code_content.replace('\r\n', ' ').replace('\n', ' '), x.analysis]

        is_unconfirm_result = False
        if "unconfirmed" in x.analysis.lower():
            is_unconfirm_result = True

        sr = check_update_or_new_scanresult(scan_task_id=a_sid, cvi_id=x.id, language=x.language,
                                            vulfile_path=trigger, source_code=code_content.replace('\r\n', ' ').replace('\n', ' '),
                                            result_type=x.analysis, is_unconfirm=is_unconfirm_result, is_active=True)

        if sr:
            for chain in x.chain:
                if type(chain) == tuple:
                    ResultFlow = get_resultflow_class(int(a_sid))
                    node_source = show_context(chain[2], chain[3], is_back=True)

                    rf = ResultFlow(vul_id=sr.id, node_type=chain[0], node_content=chain[1],
                                    node_path=chain[2], node_source=node_source, node_lineno=chain[3])
                    rf.save()

    for new_function_name in newcore_function_list:
        for svid in newcore_function_list[new_function_name]["svid"]:
            if new_function_name and newcore_function_list[new_function_name]["origin_func_name"]:

                nf = NewEvilFunc(svid=svid, scan_task_id=get_scan_id(), func_name=new_function_name,
                                 origin_func_name=newcore_function_list[new_function_name]["origin_func_name"])
                nf.save()

    return True
```

**代码：单规则执行（SingleRule.process）**

```python
def process(self):
    """
    Process Single Rule
    :return: SRV(Single Rule Vulnerabilities)
    """
    origin_results = self.origin_results()
    if origin_results == '' or origin_results is None:
        logger.debug('[CVI-{cvi}] [ORIGIN] NOT FOUND!'.format(cvi=self.sr.svid))
        return None

    origin_vulnerabilities = origin_results
    for index, origin_vulnerability in enumerate(origin_vulnerabilities):
        logger.debug('[CVI-{cvi}] [ORIGIN] {line}'.format(cvi=self.sr.svid, line=": ".join(list(origin_vulnerability))))
        if origin_vulnerability == ():
            logger.debug(' > continue...')
            continue
        vulnerability = self.parse_match(origin_vulnerability)
        if vulnerability is None:
            logger.debug('Not vulnerability, continue...')
            continue
        is_test = False
        datas = Core(self.target_directory, vulnerability, self.sr, 'project name',
                     ['whitelist1', 'whitelist2'], test=is_test, index=index,
                     files=self.files, languages=self.languages, tamper_name=self.tamper_name,
                     is_unconfirm=self.is_unconfirm).scan()

        data = ""

        if len(datas) == 3:
            is_vulnerability, reason, data = datas

            if "New Core" not in reason:
                code = "Code: {}".format(origin_vulnerability[2].strip(" "))
                file_path = os.path.normpath(origin_vulnerability[0])
                data.insert(1, ("NewScan", code, origin_vulnerability[0], origin_vulnerability[1]))

        elif len(datas) == 2:
            is_vulnerability, reason = datas
        else:
            is_vulnerability, reason = False, "Unpack error"

        if is_vulnerability:
            vulnerability.analysis = reason
            vulnerability.chain = data
            self.rule_vulnerabilities.append(vulnerability)
        else:
            if reason == 'New Core':
                new_rule_vulnerabilities = NewCore(self.sr, self.target_directory, data, self.files, 0,
                                                   languages=self.languages, tamper_name=self.tamper_name,
                                                   is_unconfirm=self.is_unconfirm,
                                                   newcore_function_list=self.newcore_function_list)

                if len(new_rule_vulnerabilities) > 0:
                    self.rule_vulnerabilities.extend(new_rule_vulnerabilities)

    return self.rule_vulnerabilities
```

---

## 3. 规则系统：Kunlun-M “知道要找什么”的方式

### 3.1 规则的组织与加载

- 规则文件：`rules/{language}/CVI_XXXX.py`（例如 [rules/php/CVI_1000.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/rules/php/CVI_1000.py)）。
- `Rule(lans)` 会把 `base + 指定语言` 的 `CVI_*.py` 全部 import 进内存（见 [core/rule.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/rule.py#L53-L76)）。
- `RuleCheck().load()` 会把规则配置同步到数据库 `Rules` 表（见 [RuleCheck](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/rule.py#L138-L191)）。

### 3.2 Match Mode：规则触发方式（候选点定位策略）

匹配模式定义在 [Kunlun_M/const.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/Kunlun_M/const.py#L15-L33)：

- `function-param-regex`：用“函数名（或语句类型）”定位敏感点，随后进入 AST 引擎对参数回溯验证（Kunlun-M 最核心的语义扫描模式之一）。
- `vustomize-match`：自定义正则捕获变量/表达式，再进入 AST 回溯验证（更灵活，依赖规则 `main()` 提取参数）。
- `only-regex`：只要命中正则就认为成立（更像“安全提示/危险用法扫描”，无数据流验证）。
- `regex-return-regex`、`special-crx-keyword-match`、`file-path-regex-match`：用于特定领域（Solidity、Chrome 扩展、敏感文件路径等）。

规则模板见 [rules/rule.template](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/rules/rule.template)。

**代码：Match-Mode 常量定义（Kunlun_M/const.py）**

```python
# Match-Mode
mm_function_param_controllable = 'function-param-regex'  # 函数正则匹配
mm_regex_param_controllable = 'vustomize-match'  # 自定义匹配
mm_regex_only_match = 'only-regex'
mm_regex_return_regex = 'regex-return-regex'
sp_crx_keyword_match = 'special-crx-keyword-match'  # crx特殊匹配
file_path_regex_match = 'file-path-regex-match'  # 文件名或者路径匹配
vendor_source_match = 'vendor_source_match'  # sca

match_modes = [
    mm_regex_only_match,
    mm_regex_param_controllable,
    mm_function_param_controllable,
    mm_regex_return_regex,
    sp_crx_keyword_match,
    file_path_regex_match,
    vendor_source_match,
]
```

---

## 4. “语义分析/回溯”是如何做的（核心原理）

Kunlun-M 的语义分析以 “候选点 -> AST 引擎验证” 为核心，具体分两条主路径：

### 4.1 路径 A：function-param-regex（直接定位 sink，再回溯参数）

在 [core/engine.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/engine.py#L883-L931)：

- 把规则中的 `match`（如 `print|die|printf|...`）拆成函数名列表；
- 调用 PHP 引擎 `php_scan_parser(...)`（见 [engine.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/engine.py#L891-L920)）。

PHP 的 `scan_parser()` 在 [core_engine/php/parser.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/core_engine/php/parser.py#L2295-L2335)：

- `ast_object.get_nodes(file_path)` 取到该文件 AST；
- 递归遍历 AST（`analysis(...)`），定位到目标函数调用（或特殊语句节点）；
- 对参数类型分派处理：变量、函数调用、二元表达式、数组访问、特殊节点等（见 [anlysis_function](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/core_engine/php/parser.py#L1617-L1676)）。
- 最终产出 `scan_results`，其 `code` 用于区分：
  - `1`：可控（确认漏洞）
  - `2`：被修复/净化（不可控）
  - `3`：疑似可控（可选展示）
  - `4`：触发 NewCore（自动生成新规则线索）
  - 其它：不可控或无法解析

**代码：Core.scan() 中对 function-param-regex 的分派（core/engine.py）**

```python
# Match for function-param-regex
if self.rule_match_mode == const.mm_function_param_controllable:
    rule_match = self.rule_match.strip('()').split('|')
    logger.debug('[RULE_MATCH] {r}'.format(r=rule_match))
    try:
        result = php_scan_parser(rule_match, self.line_number, self.file_path,
                                 repair_functions=self.repair_functions,
                                 controlled_params=self.controlled_list, svid=self.cvi)
        logger.debug('[AST] [RET] {c}'.format(c=result))
        if len(result) > 0:
            result_code_list = []

            for r in result:
                result_code_list.append(r['code'])

                if r['code'] == 1:  # 函数参数可控
                    return True, 'Function-param-controllable', r['chain']

            for r in result:
                if r['code'] == 4:  # 新规则生成
                    return False, 'New Core', r['source']

            for r in result:
                if r['code'] == 3:  # 疑似漏洞
                    if self.is_unconfirm:
                        return True, 'Unconfirmed Function-param-controllable', r['chain']
                    else:
                        return False, 'Unconfirmed Function-param-controllable', r['chain']

                elif r['code'] == 2:  # 漏洞修复
                    return False, 'Function-param-controllable but fixed', r['chain']

                else:  # 函数参数不可控
                    return False, 'Function-param-uncon', r['chain']

            logger.debug('[AST] [CODE] {code}'.format(code=result_code_list))
        else:
            logger.debug('[AST] Parser failed / vulnerability parameter is not controllable {r}'.format(r=result))
            return False, 'Can\'t parser'
    except Exception:
        exc_msg = traceback.format_exc()
        logger.warning(exc_msg)
        raise

**代码：PHP 引擎 scan_parser()（core_engine/php/parser.py）**

```python
def scan_parser(sensitive_func, vul_lineno, file_path, repair_functions=[], controlled_params=[], svid=0):
    """
    开始检测函数
    """
    try:
        global scan_results, is_repair_functions, is_controlled_params, scan_chain

        scan_chain = ['start']
        scan_results = []
        is_repair_functions = repair_functions
        is_controlled_params = controlled_params
        all_nodes = ast_object.get_nodes(file_path)

        for func in sensitive_func:
            back_node = []

            analysis(all_nodes, func, back_node, int(vul_lineno), file_path, function_params=None)

            if len(scan_results) > 0:
                logger.debug("[AST] Scan parser end for {}".format(scan_results))
                break

    except SyntaxError as e:
        logger.warning('[AST] [ERROR]:{e}'.format(e=traceback.format_exc()))

    return scan_results
```

### 4.2 路径 B：vustomize-match（先提取变量，再回溯变量来源）

`CAST.is_controllable_param()` 在 [core/cast.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/cast.py#L204-L259)：

- 先根据规则正则从候选行提取参数（`re.findall(self.rule, self.code)`）；
- 把参数交给规则 `main()` 做二次筛选/归一化；
- 对 PHP 变量调用 `php_anlysis_params(...)` 进入深度回溯（见 [cast.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/cast.py#L245-L259)）。

**代码：CAST.is_controllable_param()（vustomize-match → php_anlysis_params）**

```python
def is_controllable_param(self):
    """
    is controllable param
    :return:
    """
    param_name = re.findall(self.rule, self.code)

    if self.sr is not None:
        params = self.sr.main(param_name)

    if params is None:
        logger.debug("[AST] Not matching variables...")
        return False, -1, self.data, []

    for param_name in params:
        try:
            self.param_name = param_name
            logger.debug('[AST] Param: `{0}`'.format(param_name))
            regex_string = self.regex[self.language]['string']
            string = re.findall(regex_string, param_name)
            if len(string) >= 1 and string[0] != '':
                regex_get_variable_result = re.findall(self.regex[self.language]['variable'], param_name)
                len_regex_get_variable_result = len(regex_get_variable_result)
                if len_regex_get_variable_result >= 1:
                    param_name = regex_get_variable_result[0]
                    logger.info("[AST] String's variables: `{variables}`".format(
                        variables=','.join(regex_get_variable_result)))
                else:
                    logger.debug("[AST] String have variables: `No`")
                    return False, -1, self.data, []
            logger.debug("[AST] String have variables: `Yes`")

            if self.language == 'php':
                logger.debug("[AST] Is variable: `Yes`")
                logger.debug("[Deep AST] Start AST for param {param_name}".format(param_name=param_name))

                _is_co, _cp, expr_lineno, chain = php_anlysis_params(param_name, self.file_path, self.line, self.sr.vul_function, self.repair_functions, self.controlled_list, isexternal=True)

                if _is_co == 1:
                    logger.debug("[AST] Is assign string: `Yes`")
                    return True, _is_co, _cp, chain
                elif _is_co == 3:
                    pass
                elif _is_co == 4:
                    logger.info("[AST] New vul function {}()".format(_cp[0].name))
                    return False, _is_co, tuple([_is_co, _cp]), chain
                else:
                    continue

        except KeyboardInterrupt as e:
            raise

        except:
            logger.warning("[AST] Can't get `param`, check built-in rule..error details:\n{}".format(traceback.format_exc()))
            return False, -1, self.data, []

    if _is_co == 3:
        logger.info("[AST] can't find this param, Unconfirmed vulnerable..")
        return True, _is_co, _cp, chain

    return False, self.data, None, None
```

PHP 的 `anlysis_params()` 在 [core_engine/php/parser.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/core_engine/php/parser.py#L1555-L1615)：

- 从预处理缓存里取 AST：`all_nodes = ast_object.get_nodes(file_path)`；
- 只保留 `lineno <= vul_lineno` 的节点，模拟“只看漏洞点之前的赋值/调用”（减少误差与爆炸）；
- 调用 `deep_parameters_back(...)` 对变量递归回溯（见下节）。

**代码：PHP anlysis_params()（core_engine/php/parser.py）**

```python
def anlysis_params(param, file_path, vul_lineno, vul_function=None, repair_functions=None, controlled_params=None,
                   isexternal=False):
    """
    在cast调用时做中转数据预处理
    """
    global is_repair_functions, is_controlled_params, scan_chain
    count = 0
    function_params = None
    if repair_functions is not None:
        is_repair_functions = repair_functions

    if controlled_params is not None:
        is_controlled_params = controlled_params

    if type(param) is str and "->" in param:
        param_left = php.Variable(param.split("->")[0])
        param_right = param.split("->")[1]
        param = php.ObjectProperty(param_left, param_right)

    if isexternal:
        scan_chain = ['start']

    all_nodes = ast_object.get_nodes(file_path)

    while isinstance(param, php.Variable):
        param = param.name

    if type(param) is str:
        if not param.startswith("$"):
            is_co = -1
            cp = param
            expr_lineno = vul_lineno
            return is_co, cp, expr_lineno, scan_chain
    
        param = php.Variable(param)

    logger.debug("[AST] AST to find param {}".format(param))

    file_path = os.path.normpath(file_path)
    code = "find param {}".format(param)
    scan_chain.append(('NewFind', code, file_path, vul_lineno))

    vul_nodes = []
    for node in all_nodes:
        if node is not None and node.lineno <= int(vul_lineno):
            vul_nodes.append(node)

    is_co, cp, expr_lineno = deep_parameters_back(param, vul_nodes, function_params, count, file_path, vul_lineno,
                                                  vul_function=vul_function)

    return is_co, cp, expr_lineno, scan_chain
```

### 4.3 递归回溯与跨文件 include

最关键的递归函数：`deep_parameters_back()`（见 [parser.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/core_engine/php/parser.py#L1427-L1518)）：

- 先调用 `parameters_back(...)`（同文件更早定义）做一次回溯步进；
- 若回溯结果是 “未找到来源/不可判定”（例如 `is_co == 3`），则会尝试在 AST 中寻找 `Include` 节点：
  - 对 `include` 的路径表达式做拆解（尤其是 `BinaryOp` 拼接），对其中的变量再次递归回溯，尝试把路径中的变量补齐（见 [parser.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/core_engine/php/parser.py#L1453-L1480)）。
  - 拼接出可能的被包含文件路径，加载该文件 AST：`ast_object.get_nodes(file_path_name)`（见 [parser.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/core_engine/php/parser.py#L1498-L1514)）。
  - 在新文件 AST 中继续对同一变量递归回溯，实现 “跨文件追踪”。
- 递归深度有上限（`count > 20`）用于防止路径爆炸（见 [parser.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/core_engine/php/parser.py#L1446-L1449)）。

回溯链记录在全局 `scan_chain` 中，并最终落库为 ResultFlow（见 [core/engine.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/engine.py#L254-L262)）。

**代码：deep_parameters_back()（跨 include 递归回溯）**

```python
def deep_parameters_back(param, back_node, function_params, count, file_path, lineno=0, vul_function=None,
                         isback=False):
    """
    深度递归遍历
    """
    count += 1
    padding = {}

    is_co, cp, expr_lineno = parameters_back(param, back_node, function_params, lineno, vul_function=vul_function,
                                             file_path=file_path, isback=isback, parent_node=0)

    if count > 20:
        logger.warning("[Deep AST] depth too big, auto exit...")
        return is_co, cp, expr_lineno

    if is_co == 3 and back_node and type(back_node) is not bool:
        logger.debug("[Deep AST] try to find include, start deep AST for {}".format(cp))

        for node in back_node[::-1]:
            if isinstance(node, php.Include):
                if isinstance(node.expr, php.BinaryOp):
                    params = get_binaryop_params(node.expr, real_back=True)

                    for param in params:
                        if isinstance(param, php.Variable):
                            logger.debug("[AST][INCLUDE] The include file name has an unknown parameter {}.".format(param))

                            file_path = os.path.normpath(file_path)
                            code = "find {} in Include path {}".format(param, file_path)
                            scan_chain.append(('IncludePath', code, file_path, node.lineno))

                            is_co, ccp, expr_lineno = deep_parameters_back(param, back_node[:back_node.index(node)],
                                                                           function_params, count,
                                                                           file_path, lineno, vul_function=vul_function,
                                                                           isback=True)

                            if is_co == -1:
                                padding[get_node_name(param)] = ccp

                filename = get_filename(node, file_path)

                if isinstance(filename, list):
                    for i in filename:
                        if i in padding:
                            filename[filename.index(i)] = padding[i]

                    filename = "".join(filename)

                file_path_list = re.split(r"[\/\\]", file_path)
                file_path_list.pop()
                file_path_list.append(filename)
                if "not_found" in filename:
                    continue
                file_path_name = "/".join(file_path_list)

                try:
                    logger.debug("[Deep AST] open new file {file_path}".format(file_path=file_path_name))

                    all_nodes = ast_object.get_nodes(file_path_name)

                except:
                    logger.warning("[Deep AST] error to open new file...continue")
                    continue

                node = cp

                file_path = os.path.normpath(file_path)
                code = "find {} in Include {}".format(node, file_path_name)
                scan_chain.append(('Include', code, file_path, node.lineno))

                is_co, cp, expr_lineno = deep_parameters_back(node, all_nodes, function_params, count, file_path_name,
                                                              lineno, vul_function=vul_function, isback=isback)
                if is_co == -1 or is_co == 1:
                    break

    return is_co, cp, expr_lineno
```

---

## 5. “净化/已修复/可控输入”是如何建模的（tamper 机制）

Kunlun-M 并没有把 “sanitizer/source/sink” 全都硬编码在引擎里，而是用 tamper 配置把不同框架/项目的“修复函数”和“输入源”做可插拔化：

- 默认 PHP tamper 配置在 [rules/tamper/demo.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/rules/tamper/demo.py)：
  - `PHP_IS_REPAIR_DEFAULT`：把净化函数（如 `htmlspecialchars/mysql_real_escape_string/escapeshellarg` 等）映射到一组 CVI 规则 ID（见 [demo.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/rules/tamper/demo.py#L15-L27)）。
  - `PHP_IS_CONTROLLED_DEFAULT`：定义默认输入源（如 `$_GET`）（见 [demo.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/rules/tamper/demo.py#L29-L32)）。
- `Core.init_php_repair()` 会把默认 tamper 与 `-tp wordpress/thinkphp/...` 指定的 tamper 合并（见 [engine.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/engine.py#L786-L820)）。
- AST 引擎在回溯过程中会参考 `repair_functions` 与 `controlled_params`，把 “可控 / 已修复 / 疑似” 作为不同 `code` 输出（例如 PHP `scan_parser()` 的 `repair_functions/controlled_params` 入参，见 [parser.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/core_engine/php/parser.py#L2295-L2313)）。

这套设计的实际意义：
- 同一类漏洞在不同 CMS/框架里，输入源、过滤函数、封装函数差异很大；tamper 让 Kunlun-M 能“按目标适配”，降低误报。

**代码：tamper 默认配置（rules/tamper/demo.py）**

```python
PHP_IS_REPAIR_DEFAULT = {
    "urlencode": [1000, 10001, 10002],
    "rawurlencode": [1000, 10001, 10002],
    "htmlspecialchars": [1000, 10001, 10002],
    "htmlentities": [1000, 10001, 10002],
    "md5": [1000, 10001, 10002],
    "ldap_escape": [1010],
    "mysql_real_escape_string": [1004, 1005, 1006],
    "addslashes": [1004, 1005, 1006],
    "intval": [1000, 10001, 10002, 1004, 1005, 1006],
    "escapeshellcmd": [1009, 1011],
    "escapeshellarg": [1009, 1011],
}

PHP_IS_CONTROLLED_DEFAULT = [
    "$_GET",
]
```

**代码：Core.init_php_repair()（加载 tamper + 生成 repair_functions/controlled_list）**

```python
def init_php_repair(self):
    """
    初始化修复函数规则
    :return: 
    """
    if self.lan == "php":
        a = __import__('rules.tamper.demo', fromlist=['PHP_IS_REPAIR_DEFAULT'])
        self.repair_dict = getattr(a, 'PHP_IS_REPAIR_DEFAULT')

        b = __import__('rules.tamper.demo', fromlist=['PHP_IS_CONTROLLED_DEFAULT'])
        self.controlled_list = getattr(b, 'PHP_IS_CONTROLLED_DEFAULT')

    # 如果指定加载某个tamper，那么无视语言
    if self.tamper_name is not None:
        try:
            a = __import__('rules.tamper.' + self.tamper_name, fromlist=[self.tamper_name])
            a = getattr(a, self.tamper_name)
            self.repair_dict = self.repair_dict.copy()
            self.repair_dict.update(a.items())

            b = __import__('rules.tamper.' + self.tamper_name, fromlist=[self.tamper_name + "_controlled"])
            b = getattr(b, self.tamper_name + "_controlled")
            self.controlled_list += b

        except ImportError:
            logger.warning('[AST][INIT] tamper_name init error... No module named {}'.format(self.tamper_name))

    for key in self.repair_dict:
        if self.single_rule.svid in self.repair_dict[key]:
            self.repair_functions.append(key)
```

---

## 6. NewCore：自动生成“新的危险函数/规则线索”

Kunlun-M 有一套 “NewCore” 机制：当发现用户自定义函数/方法在参数可控时会导致敏感点（sink），引擎可以返回 `code == 4`，并进一步构造一条新的规则匹配，用于后续扫描中识别这个“新恶意函数”。

- PHP 新规则匹配串生成：`core_engine/php/engine.py:init_match_rule(...)`（见 [php/engine.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/core_engine/php/engine.py#L14-L98)）。
- `SingleRule.process()` 遇到 `'New Core'` 会进入 `NewCore(...)` 分支（见 [engine.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/engine.py#L574-L584)）。
- 最终会把新函数记录到数据库 `NewEvilFunc`（见 [core/engine.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/engine.py#L306-L313)）。

**代码：NewCore 新规则正则生成（core_engine/php/engine.py:init_match_rule）**

```python
def init_match_rule(data):
    """
    处理新生成规则初始化正则匹配
    :param data: 
    :return: 
    """

    try:
        object = data[0]
        match = ""

        if isinstance(object, php.Method) or isinstance(object, php.Function):
            function_params = object.params
            function_name = object.name
            param = data[1]
            index = 0
            for function_param in function_params:
                if function_param.name == param.name:
                    break
                index += 1

            match = "(?:\A|\s|\\b)" + function_name + "\s*\("
            for i in range(len(function_params)):
                if i != 0:
                    match += ","

                    if function_params[i].default is not None:
                        match += "?"

                if i == index:
                    match += "([^,\)]*)"
                else:
                    match += "[^,\)]*"

            match += "\)"

            match2 = "function\s+" + function_name
            vul_function = function_name
            origin_func_name = data[2]

        elif isinstance(object, php.Class):
            class_params = data[2]
            class_name = object.name
            param = data[1]
            index = 0

            for class_param in class_params:
                if class_param.name == param.name:
                    break
                index += 1

            match = "new\s*" + class_name + "\s*\("

            for i in range(len(class_params)):
                if i != 0:
                    match += ","

                    if class_params[i].default is not None:
                        match += "?"

                if i == index:
                    match += "([^,\)]*)"
                else:
                    match += "[^,\)]*"

            match += "\)"

            match2 = "class\s+" + class_name + "\s*{"
            vul_function = class_name
            origin_func_name = data[3]

    except:
        logger.error('[New Rule] Error to unpack function param, Something error')
        traceback.print_exc()
        match = None
        match2 = None
        index = 0
        vul_function = None
        origin_func_name = "None"

    return match, match2, vul_function, index, origin_func_name
```

---

## 7. 与 RIPS（PHP）相比：Kunlun-M 的“审计引擎差异点”

- RIPS（开源版）偏向“基于 token 的反向追踪”，并通过把 include 文件 token 内联实现跨文件追踪；
- Kunlun-M 偏向“基于 AST 的语义回溯”，并通过 `deep_parameters_back()` 在 include 场景下动态加载被包含文件 AST 继续回溯；
- Kunlun-M 的规则体系更“外置”：大量能力通过 `rules/` + `tamper/` 配置驱动，支持多语言与特定生态（JS、ChromeExt、Solidity、SCA vendor 扫描等）。

---

## 8. 最小化阅读路线（想快速读懂引擎就从这里看）

- 入口与 scan： [core/__init__.py:main](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/__init__.py#L52-L325) → [cli.start](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/cli.py#L183-L276)
- 预处理与 AST 缓存： [pretreatment.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/pretreatment.py)
- 规则调度与落库： [engine.py:scan](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/engine.py#L164-L337)
- 单规则执行： [engine.py:SingleRule.process](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/engine.py#L524-L617)
- PHP 语义回溯核心： [php/parser.py:scan_parser](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/core_engine/php/parser.py#L2295-L2335)，[php/parser.py:anlysis_params](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/core_engine/php/parser.py#L1555-L1615)，[php/parser.py:deep_parameters_back](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/core_engine/php/parser.py#L1427-L1518)
- tamper： [rules/tamper/demo.py](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/rules/tamper/demo.py)，[Core.init_php_repair](file:///d:/phpstudy_pro/WWW/rips/Kunlun-M/core/engine.py#L786-L820)

