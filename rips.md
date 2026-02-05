# RIPS 0.55（本目录源码）审计原理解析：它是如何“做代码审计”的

> 结论先行：开源版 RIPS 的核心是一套**基于 token 的静态污点分析（taint analysis）**引擎。它不执行 PHP，只把源码 `token_get_all()` 成 token 流，然后：
> 1) 识别“敏感调用”（sinks），2) 对 sink 的危险参数做**反向追踪**，3) 一路追到“用户可控输入”（sources）或“已净化”（sanitizers），4) 生成一棵可视化的追踪树并按漏洞类型归类输出。

---

## 1. 总体架构与入口

- 前端页面入口是 [index.php](file:///d:/phpstudy_pro/WWW/rips/index.php)，点击“扫描”会用 AJAX POST 请求 [main.php](file:///d:/phpstudy_pro/WWW/rips/main.php)（见 [script.js](file:///d:/phpstudy_pro/WWW/rips/js/script.js#L69-L150)）。
- 真正的扫描入口在 [main.php](file:///d:/phpstudy_pro/WWW/rips/main.php#L18-L185)：
  - 加载规则与核心库：`config/*.php` + `lib/*.php`
  - 枚举待扫描文件（目录递归/单文件）
  - 针对每个入口文件创建 `Scanner` 并 `parse()`：`$scan = new Scanner(...); $scan->parse();`（见 [main.php](file:///d:/phpstudy_pro/WWW/rips/main.php#L171-L179)）
- 核心类是 [Scanner](file:///d:/phpstudy_pro/WWW/rips/lib/scanner.php)；其产物写入全局 `$output`，最终由 [printer.php](file:///d:/phpstudy_pro/WWW/rips/lib/printer.php) 渲染（见 [main.php](file:///d:/phpstudy_pro/WWW/rips/main.php#L404-L407) 和 [printer.php](file:///d:/phpstudy_pro/WWW/rips/lib/printer.php#L354-L499)）。

**代码：前端发起扫描请求（script.js）**

```js
function scan(ignore_warning)
{
	var location = encodeURIComponent(document.getElementById("location").value);
	var subdirs = Number(document.getElementById("subdirs").checked);
	var	verbosity = document.getElementById("verbosity").value;
	var vector = document.getElementById("vector").value;
	var treestyle = document.getElementById("treestyle").value;
	var stylesheet = document.getElementById("css").value;
	
	var params = "loc="+location+"&subdirs="+subdirs+"&verbosity="+verbosity+"&vector="+vector+"&treestyle="+treestyle+"&stylesheet="+stylesheet;

	if(ignore_warning)
		params+="&ignore_warning=1";
	
	document.getElementById("scanning").style.backgroundImage="url(css/scanning.gif)";
	document.getElementById("scanning").innerHTML='scanning ...<div class="scanfile" id="scanfile"></div><div class="scanned" id="scanned"></div><div class="scanprogress" id="scanprogress"></div><div class="scantimeleft" id="scantimeleft"></div>'
	document.getElementById("scanning").style.display="block";
	
	prevDataLength = 0;
	nextLine = '';
	
	var a = true;
	stats_done = false;
	client = new XMLHttpRequest();
	client.onreadystatechange = function () 
	{ 
		if(this.readyState == 3 && !stats_done)
			handleResponse('scan');
		else if(this.readyState == 4 && this.status == 200 && a) 
		{
			if(!this.responseText.match(/^\s*warning:/))
			{
				document.getElementById("scanning").style.display="none";
				document.getElementById("options").style.display="";
				
				nostats = this.responseText.split("STATS_DONE.\n");
				if(nostats[1])
					result = nostats[1];
				else
					result = nostats[0];
				
				document.getElementById("result").innerHTML=(result);
				generateDiagram();
			}
			else
			{
				var amount = this.responseText.split(':')[1];
				var warning = "<div class=\"warning\">";
				warning+="<h2>警告</h2>";
				warning+="<p>你将要扫描 " + amount + " 个文件. ";
				warning+="数量数量和包含函数导致这可能需要一段时间。";
				warning+="作者建议只扫描项目的根目录而不使用子目录。</p>";
				warning+="<p>你确定要继续下去吗？</p>";	
				warning+="<input type=\"button\" class=\"Button\" value=\"continue\" onClick=\"scan(true);\"/>&nbsp;";
				warning+="<input type=\"button\" class=\"Button\" value=\"cancel\" onClick=\"document.getElementById('scanning').style.display='none';\"/>";
				warning+="</div>";
				document.getElementById("scanning").style.backgroundImage="none";
				document.getElementById("scanning").innerHTML=warning;
			}
			a=false;
		} 
		else if (this.readyState == 4 && this.status != 200) 
		{
			var warning = "<div class=\"warning\">";
			warning+="<h2>Network error (HTTP "+this.status+")</h2>";
			if(this.status == 0)
				warning+="<p>Could not access <i>main.php</i>. Make sure your webserver is running.</p>";
			else if(this.status == 404)
				warning+="<p>Could not access <i>main.php</i>. Make sure you copied all files.</p>";
			else if(this.status == 500)	
				warning+="<p>Scan aborted. Try to scan only one entry file at once or increase the <i>set_time_limit()</i> in </i>config/general.php</i>.</p>";
			warning+="</div>";
			document.getElementById("scanning").style.backgroundImage="none";
			document.getElementById("scanning").innerHTML=warning;
		}
	}
	client.open("POST", "main.php", true);
	client.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
	client.setRequestHeader("Content-length", params.length);
	client.setRequestHeader("Connection", "close");
	client.send(params);
}
```

**代码：后端扫描入口与调度（main.php）**

```php
###############################  INCLUDES  ################################

include('config/general.php');			// general settings
include('config/sources.php');			// tainted variables and functions
include('config/tokens.php');			// tokens for lexical analysis
include('config/securing.php');			// securing functions
include('config/sinks.php');			// sensitive sinks
include('config/info.php');				// interesting functions

include('lib/constructer.php'); 		// classes	
include('lib/filer.php');				// read files from dirs and subdirs
include('lib/tokenizer.php');			// prepare and fix token list
include('lib/analyzer.php');			// string analyzers
include('lib/scanner.php');				// provides class for scan
include('lib/printer.php');				// output scan result
include('lib/searcher.php');			// search functions

###############################  MAIN  ####################################

$start = microtime(TRUE);

$output = array();
$info = array();
$scanned_files = array();

if(!empty($_POST['loc']))
{		
	$location = realpath($_POST['loc']);
	
	if(is_dir($location))
	{
		$scan_subdirs = isset($_POST['subdirs']) ? $_POST['subdirs'] : false;
		$files = read_recursiv($location, $scan_subdirs);
		
		if(count($files) > WARNFILES && !isset($_POST['ignore_warning']))
			die('warning:'.count($files));
	}	
	else if(is_file($location) && in_array(substr($location, strrpos($location, '.')), $FILETYPES))
	{
		$files[0] = $location;
	}
	else
	{
		$files = array();
	}

	// SCAN
	if(empty($_POST['search']))
	{
		$user_functions = array();
		$user_functions_offset = array();
		$user_input = array();
		
		$file_sinks_count = array();
		$count_xss=$count_sqli=$count_fr=$count_fa=$count_fi=$count_exec=$count_code=$count_eval=$count_xpath=$count_ldap=$count_con=$count_other=$count_pop=$count_inc=$count_inc_fail=$count_header=$count_sf=$count_ri=0;
		
		$verbosity = isset($_POST['verbosity']) ? $_POST['verbosity'] : 1;
		$scan_functions = array();
		$info_functions = Info::$F_INTEREST;
		
		if($verbosity != 5)
		{
			switch($_POST['vector']) 
			{
				case 'xss':			$scan_functions = $F_XSS;			break;
				case 'httpheader':	$scan_functions = $F_HTTP_HEADER;	break;
				case 'fixation':	$scan_functions = $F_SESSION_FIXATION;	break;
				case 'code': 		$scan_functions = $F_CODE;			break;
				case 'ri': 			$scan_functions = $F_REFLECTION;	break;
				case 'file_read':	$scan_functions = $F_FILE_READ;		break;
				case 'file_affect':	$scan_functions = $F_FILE_AFFECT;	break;		
				case 'file_include':$scan_functions = $F_FILE_INCLUDE;	break;			
				case 'exec':  		$scan_functions = $F_EXEC;			break;
				case 'database': 	$scan_functions = $F_DATABASE;		break;
				case 'xpath':		$scan_functions = $F_XPATH;			break;
				case 'ldap':		$scan_functions = $F_LDAP;			break;
				case 'connect': 	$scan_functions = $F_CONNECT;		break;
				case 'other':		$scan_functions = $F_OTHER;			break;
				case 'unserialize':	{
									$scan_functions = $F_POP;				
									$info_functions = Info::$F_INTEREST_POP;
									$source_functions = array('unserialize');
									$verbosity = 2;
									} 
									break;
				case 'client':
					$scan_functions = array_merge(
						$F_XSS,
						$F_HTTP_HEADER,
						$F_SESSION_FIXATION
					);
					break;
				case 'server': 
					$scan_functions = array_merge(
						$F_CODE,
						$F_REFLECTION,
						$F_FILE_READ,
						$F_FILE_AFFECT,
						$F_FILE_INCLUDE,
						$F_EXEC,
						$F_DATABASE,
						$F_XPATH,
						$F_LDAP,
						$F_CONNECT,
						$F_POP,
						$F_OTHER
					); break;	
				case 'all': 
				default:
					$scan_functions = array_merge(
						$F_XSS,
						$F_HTTP_HEADER,
						$F_SESSION_FIXATION,
						$F_CODE,
						$F_REFLECTION,
						$F_FILE_READ,
						$F_FILE_AFFECT,
						$F_FILE_INCLUDE,
						$F_EXEC,
						$F_DATABASE,
						$F_XPATH,
						$F_LDAP,
						$F_CONNECT,
						$F_POP,
						$F_OTHER
					); break;
			}
		}	
		
		if($_POST['vector'] !== 'unserialize')
		{
			$source_functions = Sources::$F_OTHER_INPUT;
			if( $verbosity > 1 && $verbosity < 5 )
			{
				$source_functions = array_merge(Sources::$F_OTHER_INPUT, Sources::$F_FILE_INPUT, Sources::$F_DATABASE_INPUT);
			}
		}	
				
		$overall_time = 0;
		$timeleft = 0;
		$file_amount = count($files);		
		for($fit=0; $fit<$file_amount; $fit++)
		{
			$thisfile_start = microtime(TRUE);
			$file_scanning = $files[$fit];
			
			echo ($fit) . '|' . $file_amount . '|' . $file_scanning . '|' . $timeleft . '|' . "\n";
			@ob_flush();
			flush();

			$scan = new Scanner($file_scanning, $scan_functions, $info_functions, $source_functions);
			$scan->parse();
			$scanned_files[$file_scanning] = $scan->inc_map;
			
			$overall_time += microtime(TRUE) - $thisfile_start;
			$timeleft = round(($overall_time/($fit+1)) * ($file_amount - $fit+1),2);
		}
		echo "STATS_DONE.\n";
		@ob_flush();
		flush();
	}
}

// scan result
@printoutput($output, $_POST['treestyle']); 
```

---

## 2. 规则库（RIPS “知道要找什么”的来源）

RIPS 的规则分三大类：source / sink / sanitizer（以及一些 token 分组、info 提示）。

### 2.1 Sources：哪些东西算“用户输入/不可信”
定义在 [config/sources.php](file:///d:/phpstudy_pro/WWW/rips/config/sources.php)：
- `Sources::$V_USERINPUT`：`$_GET/$_POST/$_COOKIE/$_REQUEST/$_FILES/$_SERVER/...` 等超全局及 CLI 参数（见 [sources.php](file:///d:/phpstudy_pro/WWW/rips/config/sources.php#L20-L37)）
- `Sources::$V_SERVER_PARAMS`：`$_SERVER` 中哪些 key 被视为可控（HTTP_*、REQUEST_URI 等，见 [sources.php](file:///d:/phpstudy_pro/WWW/rips/config/sources.php#L39-L63)）
- `Sources::$F_*_INPUT`：把“读文件/读数据库/读环境”等函数返回值视为输入源（见 [sources.php](file:///d:/phpstudy_pro/WWW/rips/config/sources.php#L65-L115)）

另外：`source_functions` 是一个“动态集合”，默认来自 `Sources::$F_OTHER_INPUT` 等，并会在扫描过程中**把用户自定义函数推断为 source**（后文详述）。

```php
final class Sources
{	
	// userinput variables
	public static $V_USERINPUT = array(
		'$_GET',
		'$_POST',
		'$_COOKIE',
		'$_REQUEST',
		'$_FILES',
		'$_SERVER',
		'$HTTP_GET_VARS',
		'$HTTP_POST_VARS',
		'$HTTP_COOKIE_VARS',  
		'$HTTP_REQUEST_VARS', 
		'$HTTP_POST_FILES',
		'$HTTP_SERVER_VARS',
		'$HTTP_RAW_POST_DATA',
		'$argc',
		'$argv'
	);
	
	public static $V_SERVER_PARAMS = array(
		'HTTP_ACCEPT',
		'HTTP_ACCEPT_LANGUAGE',
		'HTTP_ACCEPT_ENCODING',
		'HTTP_ACCEPT_CHARSET',
		'HTTP_CONNECTION',
		'HTTP_HOST',
		'HTTP_KEEP_ALIVE',
		'HTTP_REFERER',
		'HTTP_USER_AGENT',
		'HTTP_X_FORWARDED_FOR',
		// all HTTP_ headers can be tainted
		'PHP_AUTH_DIGEST',
		'PHP_AUTH_USER',
		'PHP_AUTH_PW',
		'AUTH_TYPE',
		'QUERY_STRING',
		'REQUEST_METHOD',
		'REQUEST_URI', // partly urlencoded
		'PATH_INFO',
		'ORIG_PATH_INFO',
		'PATH_TRANSLATED',
		'REMOTE_HOSTNAME',
		'PHP_SELF'
	);
	
	// file content as input
	public static $F_FILE_INPUT = array(
		'bzread',
		'dio_read',
		'exif_imagetype',
		'exif_read_data',
		'exif_thumbnail',
		'fgets',
		'fgetss',
		'file', 
		'file_get_contents',
		'fread',
		'get_meta_tags',
		'glob',
		'gzread',
		'readdir',
		'read_exif_data',
		'scandir',
		'zip_read'
	);
	
	// database content as input
	public static $F_DATABASE_INPUT = array(
		'mysql_fetch_array',
		'mysql_fetch_assoc',
		'mysql_fetch_field',
		'mysql_fetch_object',
		'mysql_fetch_row',
		'pg_fetch_all',
		'pg_fetch_array',
		'pg_fetch_assoc',
		'pg_fetch_object',
		'pg_fetch_result',
		'pg_fetch_row',
		'sqlite_fetch_all',
		'sqlite_fetch_array',
		'sqlite_fetch_object',
		'sqlite_fetch_single',
		'sqlite_fetch_string'
	);
	
	// other functions as input
	public static $F_OTHER_INPUT = array(
		'get_headers',
		'getallheaders',
		'get_browser',
		'getenv',
		'gethostbyaddr',
		'runkit_superglobals',
		'import_request_variables'
	);
	
	//	'getenv' and 'apache_getenv' 
	// will be automatically added if 'putenv' or 'apache_setenv' with userinput is found
}
```

### 2.2 Sinks：哪些函数调用算“敏感点”
定义在 [config/sinks.php](file:///d:/phpstudy_pro/WWW/rips/config/sinks.php)：
- 每类漏洞对应一个 `$F_XXX` 映射：`函数名 => array(参数位置列表, 该 sink 的专属净化函数列表)`  
  例如 XSS：`echo/print/printf/...`（见 [sinks.php](file:///d:/phpstudy_pro/WWW/rips/config/sinks.php#L19-L35)）
- 参数位置列表里 `0` 表示“所有参数都追踪”（见 [sinks.php](file:///d:/phpstudy_pro/WWW/rips/config/sinks.php#L19-L24)）
- `main.php` 会按用户选择的漏洞类型，把多个 `$F_XXX` 合并成当次扫描的 `scan_functions`（见 [main.php](file:///d:/phpstudy_pro/WWW/rips/main.php#L79-L146)）

```php
// cross-site scripting affected functions
// parameter = 0 means, all parameters will be traced
$NAME_XSS = 'XSS';
$F_XSS = array(
	'echo'							=> array(array(0), $F_SECURING_XSS), 
	'print'							=> array(array(1), $F_SECURING_XSS),
	'print_r'						=> array(array(1), $F_SECURING_XSS),
	'exit'							=> array(array(1), $F_SECURING_XSS),
	'die'							=> array(array(1), $F_SECURING_XSS),
	'printf'						=> array(array(0), $F_SECURING_XSS),
	'vprintf'						=> array(array(0), $F_SECURING_XSS),
	'trigger_error'					=> array(array(1), $F_SECURING_XSS),
	'user_error'					=> array(array(1), $F_SECURING_XSS),
	'odbc_result_all'				=> array(array(2), $F_SECURING_XSS),
	'ovrimos_result_all'			=> array(array(2), $F_SECURING_XSS),
	'ifx_htmltbl_result'			=> array(array(2), $F_SECURING_XSS)
);

// HTTP header injections
$NAME_HTTP_HEADER = 'HTTP header注入';
$F_HTTP_HEADER = array(
	'header' 						=> array(array(1), array())
);

// session fixation
$NAME_SESSION_FIXATION = '会话固定';
$F_SESSION_FIXATION = array(
	'setcookie' 					=> array(array(2), array()),
	'setrawcookie' 					=> array(array(2), array()),
	'session_id' 					=> array(array(1), array())
);

// code evaluating functions  => (parameters to scan, securing functions)
// example parameter array(1,3) will trace only first and third parameter 
$NAME_CODE = 'PHP代码执行';
$F_CODE = array(
	'assert' 						=> array(array(1), array()),
	'create_function' 				=> array(array(1,2), array()),
	'eval' 							=> array(array(1), array()),
	'mb_ereg_replace'				=> array(array(1,2), $F_SECURING_PREG),
	'mb_eregi_replace'				=> array(array(1,2), $F_SECURING_PREG),
	'preg_filter'					=> array(array(1,2), $F_SECURING_PREG),
	'preg_replace'					=> array(array(1,2), $F_SECURING_PREG),
	'preg_replace_callback'			=> array(array(1), $F_SECURING_PREG),
);

// file inclusion functions => (parameters to scan, securing functions)
$NAME_FILE_INCLUDE = '文件包含';
$F_FILE_INCLUDE = array(
	'include' 						=> array(array(1), $F_SECURING_FILE),
	'include_once' 					=> array(array(1), $F_SECURING_FILE),
	'parsekit_compile_file'			=> array(array(1), $F_SECURING_FILE),
	'php_check_syntax' 				=> array(array(1), $F_SECURING_FILE),	
	'require' 						=> array(array(1), $F_SECURING_FILE),
	'require_once' 					=> array(array(1), $F_SECURING_FILE),
);
```

### 2.3 Sanitizers（securing / insecuring）：哪些操作算“净化/反净化”
定义在 [config/securing.php](file:///d:/phpstudy_pro/WWW/rips/config/securing.php)：
- `F_SECURING_STRING`：对所有漏洞通用的“看起来更安全”的函数（cast、hash、encode、strlen 等，见 [securing.php](file:///d:/phpstudy_pro/WWW/rips/config/securing.php#L48-L117)）
- `F_SECURING_XSS / SQL / FILE / SYSTEM / ...`：针对不同漏洞的净化函数集合（见 [securing.php](file:///d:/phpstudy_pro/WWW/rips/config/securing.php#L150-L212)）
- `F_INSECURING_STRING`：把之前的净化“再弄脏”的函数（decode、urldecode、htmlspecialchars_decode 等，见 [securing.php](file:///d:/phpstudy_pro/WWW/rips/config/securing.php#L119-L148)）
- `F_QUOTE_ANALYSIS`：一类特殊净化（主要是 SQL escape）需要结合“是否在引号内”判断是否有效（见 [securing.php](file:///d:/phpstudy_pro/WWW/rips/config/securing.php#L213-L215)）

```php
// securing functions for every vulnerability
$F_SECURING_STRING = array(
	'intval',
	'floatval',
	'doubleval',
	'filter_input',
	'urlencode',
	'rawurlencode',
	'round',
	'floor',
	'strlen',
	'strrpos',
	'strpos',
	'strftime',
	'strtotime',
	'md5',
	'md5_file',
	'sha1',
	'sha1_file',
	'crypt',
	'crc32',
	'hash',
	'mhash',
	'hash_hmac',
	'password_hash',
	'mcrypt_encrypt',
	'mcrypt_generic',
	'base64_encode',
	'ord',
	'sizeof',
	'count',
	'bin2hex',
	'levenshtein',
	'abs',
	'bindec',
	'decbin',
	'dechex',
	'decoct',
	'hexdec',
	'rand',
	'max',
	'min',
	'metaphone',
	'tempnam',
	'soundex',
	'money_format',
	'number_format',
	'date_format',
	'filetype',
	'nl_langinfo',
	'bzcompress',
	'convert_uuencode',
	'gzdeflate',
	'gzencode',
	'gzcompress',
	'http_build_query',
	'lzf_compress',
	'zlib_encode',
	'imap_binary',
	'iconv_mime_encode',
	'bson_encode',
	'sqlite_udf_encode_binary',
	'session_name',
	'readlink',
	'getservbyport',
	'getprotobynumber',
	'gethostname',
	'gethostbynamel',
	'gethostbyname',
);

// functions that insecures the string again 
$F_INSECURING_STRING = array(
	'base64_decode',
	'htmlspecialchars_decode',
	'html_entity_decode',
	'bzdecompress',
	'chr',
	'convert_uudecode',
	'gzdecode',
	'gzinflate',
	'gzuncompress',
	'lzf_decompress',
	'rawurldecode',
	'urldecode',
	'zlib_decode',
	'imap_base64',
	'imap_utf7_decode',
	'imap_mime_header_decode',
	'iconv_mime_decode',
	'iconv_mime_decode_headers',
	'hex2bin',
	'quoted_printable_decode',
	'imap_qprint',
	'mb_decode_mimeheader',
	'bson_decode',
	'sqlite_udf_decode_binary',
	'utf8_decode',
	'recode_string',
	'recode'
);

// securing functions for XSS
$F_SECURING_XSS = array(
	'htmlentities',
	'htmlspecialchars',
	'highlight_string',
);	

// securing functions for SQLi
$F_SECURING_SQL = array(
	'addslashes',
	'dbx_escape_string',
	'db2_escape_string',
	'ingres_escape_string',
	'maxdb_escape_string',
	'maxdb_real_escape_string',
	'mysql_escape_string',
	'mysql_real_escape_string',
	'mysqli_escape_string',
	'mysqli_real_escape_string',
	'pg_escape_string',	
	'pg_escape_bytea',
	'sqlite_escape_string',
	'sqlite_udf_encode_binary',
	'cubrid_real_escape_string',
);	

// securing functions for RCE with e-modifier in preg_**
$F_SECURING_PREG = array(
	'preg_quote'
);

// securing functions for file handling
$F_SECURING_FILE = array(
	'basename',
	'dirname',
	'pathinfo'
);

// securing functions for OS command execution
$F_SECURING_SYSTEM = array(
	'escapeshellarg',
	'escapeshellcmd'
);	

// securing XPath injection
$F_SECURING_XPATH = array(
	'addslashes'
);

// all specific securings
$F_SECURES_ALL = array_merge(
	$F_SECURING_XSS, 
	$F_SECURING_SQL,
	$F_SECURING_PREG,
	$F_SECURING_FILE,
	$F_SECURING_SYSTEM,
	$F_SECURING_XPATH
);	

// securing functions that work only when embedded in quotes
$F_QUOTE_ANALYSIS = $F_SECURING_SQL;
```

### 2.4 Tokens：RIPS 用哪些 token 分组来写解析逻辑
定义在 [config/tokens.php](file:///d:/phpstudy_pro/WWW/rips/config/tokens.php)：
- `Tokens::$T_FUNCTIONS`：把 `T_STRING/T_INCLUDE/T_REQUIRE/...` 等都视为“函数/调用类 token”（见 [tokens.php](file:///d:/phpstudy_pro/WWW/rips/config/tokens.php#L87-L95)）
- `Tokens::$T_INCLUDES`、`Tokens::$T_XSS`、赋值/运算符/控制流分组等（见 [tokens.php](file:///d:/phpstudy_pro/WWW/rips/config/tokens.php#L32-L162)）
- 自定义 `T_INCLUDE_END` 用来标记“内联 include 的结束点”（见 [tokens.php](file:///d:/phpstudy_pro/WWW/rips/config/tokens.php#L164-L166)）

```php
final class Tokens
{	
	// tokens to ignore while scanning
	public static $T_IGNORE = array(
		T_BAD_CHARACTER,
		T_DOC_COMMENT,
		T_COMMENT,
		//T_ML_COMMENT,
		T_INLINE_HTML,
		T_WHITESPACE,
		T_OPEN_TAG
		//T_CLOSE_TAG
	);
	
	// code blocks that should be ignored as requirement
	public static $T_LOOP_CONTROL = array(
		//T_DO, // removed, because DO..WHILE is rewritten to WHILE
		T_WHILE,
		T_FOR,
		T_FOREACH
	);
	
	// control structures
	public static $T_FLOW_CONTROL = array(
		T_IF, 
		T_SWITCH, 
		T_CASE, 
		T_ELSE, 
		T_ELSEIF
	);	
	
	// variable assignment tokens
	public static $T_ASSIGNMENT = array(
		T_AND_EQUAL,
		T_CONCAT_EQUAL,
		T_DIV_EQUAL,
		T_MINUS_EQUAL,
		T_MOD_EQUAL,
		T_MUL_EQUAL,
		T_OR_EQUAL,
		T_PLUS_EQUAL,
		T_SL_EQUAL,
		T_SR_EQUAL,
		T_XOR_EQUAL
	);
	
	// variable assignment tokens that prevent tainting
	public static $T_ASSIGNMENT_SECURE = array(
		T_DIV_EQUAL,
		T_MINUS_EQUAL,
		T_MOD_EQUAL,
		T_MUL_EQUAL,
		T_OR_EQUAL,
		T_PLUS_EQUAL,
		T_SL_EQUAL,
		T_SR_EQUAL,
		T_XOR_EQUAL
	);
	
	// condition operators
	public static $T_OPERATOR = array(
		T_IS_EQUAL,
		T_IS_GREATER_OR_EQUAL,
		T_IS_IDENTICAL,
		T_IS_NOT_EQUAL,
		T_IS_NOT_IDENTICAL,
		T_IS_SMALLER_OR_EQUAL
	);
	
	// all function call tokens
	public static $T_FUNCTIONS = array(
		T_STRING, // all functions
		T_EVAL,
		T_INCLUDE,
		T_INCLUDE_ONCE,
		T_REQUIRE,
		T_REQUIRE_ONCE
	);
	
	// including operation tokens
	public static $T_INCLUDES = array(
		T_INCLUDE,
		T_INCLUDE_ONCE,
		T_REQUIRE,
		T_REQUIRE_ONCE
	);
	
	// XSS affected operation tokens
	public static $T_XSS = array(
		T_PRINT,
		T_ECHO,
		T_OPEN_TAG_WITH_ECHO,
		T_EXIT
	);
	
	// securing operation tokens
	public static $T_CASTS = array(
		T_BOOL_CAST,
		T_DOUBLE_CAST,
		T_INT_CAST,
		T_UNSET_CAST,
		T_UNSET
	);
	
	// tokens that will have a space before and after in the output, besides $T_OPERATOR and $T_ASSIGNMENT
	public static $T_SPACE_WRAP = array(
		T_AS,
		T_BOOLEAN_AND,
		T_BOOLEAN_OR,
		T_LOGICAL_AND,
		T_LOGICAL_OR,
		T_LOGICAL_XOR,
		T_SL,
		T_SR,
		T_CASE,
		T_ELSE,
		T_GLOBAL,
		T_NEW
	);
	
	// arithmetical operators to detect automatic typecasts
	public static $T_ARITHMETIC = array(
		T_INC,
		T_DEC
	);
	
	// arithmetical operators to detect automatic typecasts
	public static $S_ARITHMETIC = array(
		'+',
		'-',
		'*',
		'/',
		'%'
	);
	
	// strings that will have a space before and after in the output besides $S_ARITHMETIC
	public static $S_SPACE_WRAP = array(
		'.',
		'=',
		'>',
		'<',
		':',
		'?'
	);
}	

// define own token for include ending
define('T_INCLUDE_END', 380);
```

---

## 3. Token 化与“把 PHP 变得更好分析”

### 3.1 Tokenizer：预处理 token 流（关键：降低 PHP 语法多样性）
在 [lib/tokenizer.php](file:///d:/phpstudy_pro/WWW/rips/lib/tokenizer.php)：

- 删除噪声 token：空白/注释/HTML 等（见 [tokenizer.php](file:///d:/phpstudy_pro/WWW/rips/lib/tokenizer.php#L49-L92)）
- 重写一些语法形态，保证后续 `Scanner` 更容易用“找 { }”来理解控制流：
  - `if (...) stmt;` / `else stmt;` 这类没有 `{}` 的语句块，会被包上一对 `{}`（见 [tokenizer.php](file:///d:/phpstudy_pro/WWW/rips/lib/tokenizer.php#L114-L176)）
  - `switch(): ... endswitch;`、`while(): endwhile;` 等 alternate syntax 也会被统一处理（同文件多处）
  - 反引号命令执行 `` `cmd` `` 被改写成 `backticks(cmd)` 形式，统一成“函数调用 sink”来扫（见 [tokenizer.php](file:///d:/phpstudy_pro/WWW/rips/lib/tokenizer.php#L94-L123)）
  - 函数名统一转小写，规避 PHP 函数大小写不敏感导致的漏检（见 [tokenizer.php](file:///d:/phpstudy_pro/WWW/rips/lib/tokenizer.php#L284-L299)）
  - `do { } while (...)` 被重排成 `while(...) { }`（RIPS 的分析不关心循环次数差异，只关心可达性/传播，见 [tokenizer.php](file:///d:/phpstudy_pro/WWW/rips/lib/tokenizer.php#L300-L372)）

### 3.2 数组访问重建：把 `$a[$b][1]` 的 key 挂到 token 上
`array_reconstruct_tokens()` 会把 `[]` 内的 key 收集到 `$token[3]`，常量 key 直接存值，动态 key 存一段 token 子数组，供后续反向追踪时解析（见 [tokenizer.php](file:///d:/phpstudy_pro/WWW/rips/lib/tokenizer.php#L375-L442)）。

**代码：Tokenizer 关键实现（tokenize + 预处理/修复/数组重建/三元运算处理）**

```php
class Tokenizer
{	
	public $filename;
	public $tokens;

	function __construct($filename)
	{
		$this->filename = $filename;
	}

	// main
	public function tokenize($code)
	{
		$this->tokens = token_get_all($code);			
		$this->prepare_tokens();
		$this->array_reconstruct_tokens();
		$this->fix_tokens();	
		$this->fix_ternary();
		return $this->tokens;
	}
	
	// adds braces around offsets
	function wrapbraces($start, $between, $end)
	{
		$this->tokens = array_merge(
			array_slice($this->tokens, 0, $start), array('{'), 
			array_slice($this->tokens, $start, $between), array('}'),
			array_slice($this->tokens, $end)
		);	
	}

	// delete all tokens to ignore while scanning, mostly whitespaces	
	function prepare_tokens()
	{	
		// delete whitespaces and other unimportant tokens, rewrite some special tokens
		for($i=0, $max=count($this->tokens); $i<$max; $i++)
		{
			if( is_array($this->tokens[$i]) ) 
			{
				if( in_array($this->tokens[$i][0], Tokens::$T_IGNORE) )
					unset($this->tokens[$i]);
				else if( $this->tokens[$i][0] === T_CLOSE_TAG )
					$this->tokens[$i] = ';';	
				else if( $this->tokens[$i][0] === T_OPEN_TAG_WITH_ECHO )
					$this->tokens[$i][1] = 'echo';
			} 
			// @ (depress errors) disturbs connected token handling
			else if($this->tokens[$i] === '@') 
			{
				unset($this->tokens[$i]);
			}	
			// rewrite $array{index} to $array[index]
			else if( $this->tokens[$i] === '{'
			&& isset($this->tokens[$i-1]) && ((is_array($this->tokens[$i-1]) && $this->tokens[$i-1][0] === T_VARIABLE)
			|| $this->tokens[$i-1] === ']') )
			{
				$this->tokens[$i] = '[';
				$f=1;
				while($this->tokens[$i+$f] !== '}')
				{
					$f++;
					if(!isset($this->tokens[$i+$f]))
					{
						addError('Could not find closing brace of '.$this->tokens[$i-1][1].'{}.', array_slice($this->tokens, $i-1, 2), $this->tokens[$i-1][2], $this->filename);
						break;	
					}
				}
				$this->tokens[$i+$f] = ']';
			}	
		}
		
		// rearranged key index of tokens
		$this->tokens = array_values($this->tokens);
	}	
		
	// some tokenchains need to be fixed to scan correctly later	
	function fix_tokens()
	{	
		for($i=0; $i<($max=count($this->tokens)); $i++)
		{
		// convert `backticks` to backticks()
			if( $this->tokens[$i] === '`' )
			{		
				$f=1;
				while( $this->tokens[$i+$f] !== '`' )
				{	
					// get line_nr of any near token
					if( is_array($this->tokens[$i+$f]) )
						$line_nr = $this->tokens[$i+$f][2];

					$f++;
					if(!isset($this->tokens[$i+$f]) || $this->tokens[$i+$f] === ';')
					{
						addError('Could not find closing backtick `.', array_slice($this->tokens, $i, 5), $this->tokens[$i+1][2], $this->filename);
						break;	
					}
				}
				if(!empty($line_nr))
				{ 
					$this->tokens[$i+$f] = ')';
					$this->tokens[$i] = array(T_STRING, 'backticks', $line_nr);
				
					// add element backticks() to array 			
					$this->tokens = array_merge(
						array_slice($this->tokens, 0, $i+1), array('('), 
						array_slice($this->tokens, $i+1)
					);	
				}

			}
		// real token
			else if( is_array($this->tokens[$i]) )
			{	
			// rebuild if-clauses, for(), foreach(), while() without { }
				if ( ($this->tokens[$i][0] === T_IF || $this->tokens[$i][0] === T_ELSEIF || $this->tokens[$i][0] === T_FOR 
				|| $this->tokens[$i][0] === T_FOREACH || $this->tokens[$i][0] === T_WHILE) && $this->tokens[$i+1] === '(' )
				{		
					// skip condition in ( )
					$f=2;
					$braceopen = 1;
					while($braceopen !== 0 ) 
					{
						if($this->tokens[$i+$f] === '(')
							$braceopen++;
						else if($this->tokens[$i+$f] === ')')
							$braceopen--;
						$f++;

						if(!isset($this->tokens[$i+$f]))
						{
							addError('Could not find closing parenthesis of '.$this->tokens[$i][1].'-statement.', array_slice($this->tokens, $i, 5), $this->tokens[$i][2], $this->filename);
							break;	
						}
					}	

					// alternate syntax while(): endwhile;
					if($this->tokens[$i+$f] === ':')
					{
						switch($this->tokens[$i][0])
						{
							case T_IF:
							case T_ELSEIF: $endtoken = T_ENDIF; break;
							case T_FOR: $endtoken = T_ENDFOR; break;
							case T_FOREACH: $endtoken = T_ENDFOREACH; break;
							case T_WHILE: $endtoken = T_ENDWHILE; break;
							default: $endtoken = ';';
						}
					
						$c=1;
						while( $this->tokens[$i+$f+$c][0] !== $endtoken)
						{
							$c++;
							if(!isset($this->tokens[$i+$f+$c]))
							{
								addError('Could not find end'.$this->tokens[$i][1].'; of alternate '.$this->tokens[$i][1].'-statement.', array_slice($this->tokens, $i, $f+1), $this->tokens[$i][2], $this->filename);
								break;	
							}
						}
						$this->wrapbraces($i+$f+1, $c+1, $i+$f+$c+2);
					}
					// if body not in { (and not a do ... while();) wrap next instruction in braces
					else if($this->tokens[$i+$f] !== '{' && $this->tokens[$i+$f] !== ';')
					{
						$c=1;
						while($this->tokens[$i+$f+$c] !== ';' && $c<$max)
						{
							$c++;
						}
						$this->wrapbraces($i+$f, $c+1, $i+$f+$c+1);
					}
				} 
			// rebuild else without { }	
				else if( $this->tokens[$i][0] === T_ELSE 
				&& $this->tokens[$i+1][0] !== T_IF
				&& $this->tokens[$i+1] !== '{')
				{	
					$f=2;
					while( $this->tokens[$i+$f] !== ';' && $f<$max)
					{		
						$f++;
					}
					$this->wrapbraces($i+1, $f, $i+$f+1);
				}
			// rebuild switch (): endswitch;		
				else if( $this->tokens[$i][0] === T_SWITCH && $this->tokens[$i+1] === '(')
				{
					$newbraceopen = 1;
					$c=2;
					while( $newbraceopen !== 0 )
					{
						// watch function calls in function call
						if( $this->tokens[$i + $c] === '(' )
						{
							$newbraceopen++;
						}
						else if( $this->tokens[$i + $c] === ')' )
						{
							$newbraceopen--;
						}					
						else if(!isset($this->tokens[$i+$c]) || $this->tokens[$i + $c] === ';')
						{
							addError('Could not find closing parenthesis of switch-statement.', array_slice($this->tokens, $i, 10), $this->tokens[$i][2], $this->filename);
							break;	
						}
						$c++;
					}
					// switch(): ... endswitch;
					if($this->tokens[$i + $c] === ':')
					{
						$f=1;
						while( $this->tokens[$i+$c+$f][0] !== T_ENDSWITCH)
						{
							$f++;
							if(!isset($this->tokens[$i+$c+$f]))
							{
								addError('Could not find endswitch; of alternate switch-statement.', array_slice($this->tokens, $i, $c+1), $this->tokens[$i][2], $this->filename);
								break;	
							}
						}
						$this->wrapbraces($i+$c+1, $f+1, $i+$c+$f+2);
					}
				}
			// rebuild switch case: without { }	
				else if( $this->tokens[$i][0] === T_CASE )
				{
					$e=1;
					while($this->tokens[$i+$e] !== ':' && $this->tokens[$i+$e] !== ';')
					{
						$e++;
						
						if(!isset($this->tokens[$i+$e]))
						{
							addError('Could not find : or ; after '.$this->tokens[$i][1].'-statement.', array_slice($this->tokens, $i, 5), $this->tokens[$i][2], $this->filename);
							break;	
						}
					}
					$f=$e+1;
					if(($this->tokens[$i+$e] === ':' || $this->tokens[$i+$e] === ';')
					&& $this->tokens[$i+$f] !== '{' 
					&& $this->tokens[$i+$f][0] !== T_CASE && $this->tokens[$i+$f][0] !== T_DEFAULT)
					{
						$newbraceopen = 0;
						while($newbraceopen || (isset($this->tokens[$i+$f]) && $this->tokens[$i+$f] !== '}' 
						&& !(is_array($this->tokens[$i+$f]) 
						&& ($this->tokens[$i+$f][0] === T_BREAK || $this->tokens[$i+$f][0] === T_CASE 
						|| $this->tokens[$i+$f][0] === T_DEFAULT || $this->tokens[$i+$f][0] === T_ENDSWITCH) ) ))
						{		
							if($this->tokens[$i+$f] === '{')
								$newbraceopen++;
							else if($this->tokens[$i+$f] === '}')	
								$newbraceopen--;
							$f++;
							
							if(!isset($this->tokens[$i+$f]))
							{
								addError('Could not find ending of '.$this->tokens[$i][1].'-statement.', array_slice($this->tokens, $i, $e+5), $this->tokens[$i][2], $this->filename);
								break;	
							}
						}
						if($this->tokens[$i+$f][0] === T_BREAK)
						{
							if($this->tokens[$i+$f+1] === ';')
								$this->wrapbraces($i+$e+1, $f-$e+1, $i+$f+2);
							// break 3;	
							else
								$this->wrapbraces($i+$e+1, $f-$e+2, $i+$f+3);
						}	
						else
						{
							$this->wrapbraces($i+$e+1, $f-$e-1, $i+$f);
						}	
						$i++;
					}
				}
			// rebuild switch default: without { }	
				else if( $this->tokens[$i][0] === T_DEFAULT
				&& $this->tokens[$i+2] !== '{' )
				{
					$f=2;
					$newbraceopen = 0;
					while( $this->tokens[$i+$f] !== ';' && $this->tokens[$i+$f] !== '}' || $newbraceopen )
					{		
						if($this->tokens[$i+$f] === '{')
							$newbraceopen++;
						else if($this->tokens[$i+$f] === '}')	
							$newbraceopen--;
						$f++;
						
						if(!isset($this->tokens[$i+$f]))
						{
							addError('Could not find ending of '.$this->tokens[$i][1].'-statement.', array_slice($this->tokens, $i, 5), $this->tokens[$i][2], $this->filename);
							break;	
						}
					}
					$this->wrapbraces($i+2, $f-1, $i+$f+1);
				}
			// lowercase all function names because PHP doesn't care	
				else if( $this->tokens[$i][0] === T_FUNCTION )
				{
					$this->tokens[$i+1][1] = strtolower($this->tokens[$i+1][1]);
				}	
				else if( $this->tokens[$i][0] === T_STRING && $this->tokens[$i+1] === '(')
				{
					$this->tokens[$i][1] = strtolower($this->tokens[$i][1]);
				}	
			// switch a do while with a while
				else if( $this->tokens[$i][0] === T_DO )
				{
					$f=2;
					$otherDOs = 0;
					while( $this->tokens[$i+$f][0] !== T_WHILE || $otherDOs )
					{		
						if($this->tokens[$i+$f][0] === T_DO)
							$otherDOs++;
						else if($this->tokens[$i+$f][0] === T_WHILE)
							$otherDOs--;
						$f++;
						
						if(!isset($this->tokens[$i+$f]))
						{
							addError('Could not find WHILE of DO-WHILE-statement.', array_slice($this->tokens, $i, 5), $this->tokens[$i][2], $this->filename);
							break;	
						}
					}
					
					if($this->tokens[$i+1] !== '{')
					{
						$this->wrapbraces($i+1, $f-1, $i+$f);
						$f+=2;
					}

					$d=1;
					while( $this->tokens[$i+$f+$d] !== ';' && $d<$max )
					{
						$d++;
					}
					
					$this->tokens = array_merge(
						array_slice($this->tokens, 0, $i),
						array_slice($this->tokens, $i+$f, $d),
						array_slice($this->tokens, $i+1, $f-1),
						array_slice($this->tokens, $i+$f+$d+1, count($this->tokens))
					);	
				}
			}	
		}
		$this->tokens = array_values($this->tokens);
	}
	
	// rewrite $arrays[] to	$variables and save keys in $tokens[$i][3]
	function array_reconstruct_tokens()
	{	
		for($i=0,$max=count($this->tokens); $i<$max; $i++)
		{
			// check for arrays
			if( is_array($this->tokens[$i]) && $this->tokens[$i][0] === T_VARIABLE && $this->tokens[$i+1] === '[' )
			{	
				$this->tokens[$i][3] = array();
				$has_more_keys = true;
				$index = -1;
				$c=2;
				
				// loop until no more index found: array[1][2][3]
				while($has_more_keys && $index < MAX_ARRAY_KEYS)
				{
					$index++;
					// save constant index as constant
					if(($this->tokens[$i+$c][0] === T_CONSTANT_ENCAPSED_STRING || $this->tokens[$i+$c][0] === T_LNUMBER || $this->tokens[$i+$c][0] === T_NUM_STRING || $this->tokens[$i+$c][0] === T_STRING) && $this->tokens[$i+$c+1] === ']')
					{ 		
						unset($this->tokens[$i+$c-1]);
						$this->tokens[$i][3][$index] = str_replace(array('"', "'"), '', $this->tokens[$i+$c][1]);
						unset($this->tokens[$i+$c]);
						unset($this->tokens[$i+$c+1]);
						$c+=2;
					// save tokens of non-constant index as token-array for backtrace later	
					} else
					{
						$this->tokens[$i][3][$index] = array();
						$newbraceopen = 1;
						unset($this->tokens[$i+$c-1]);
						while($newbraceopen !== 0)
						{	
							if( $this->tokens[$i+$c] === '[' )
							{
								$newbraceopen++;
							}
							else if( $this->tokens[$i+$c] === ']' )
							{
								$newbraceopen--;
							}
							else
							{
								$this->tokens[$i][3][$index][] = $this->tokens[$i+$c];
							}	
							unset($this->tokens[$i+$c]);
							$c++;
							
							if(!isset($this->tokens[$i+$c]))
							{
								addError('Could not find closing bracket of '.$this->tokens[$i][1].'[].', array_slice($this->tokens, $i, 5), $this->tokens[$i][2], $this->filename);
								break;	
							}
						}
						unset($this->tokens[$i+$c-1]);
					}
					if($this->tokens[$i+$c] !== '[')
						$has_more_keys = false;
					$c++;	
				}	
				
				$i+=$c-1;
			}
		}
	
		// return tokens with rearranged key index
		$this->tokens = array_values($this->tokens);		
	}
	
	// handle ternary operator (remove condition, only values should be handled during trace)
	function fix_ternary()
	{
		for($i=0,$max=count($this->tokens); $i<$max; $i++)
		{
			if( $this->tokens[$i] === '?' )
			{
				unset($this->tokens[$i]);
				// condition in brackets: fine, delete condition
				if($this->tokens[$i-1] === ')')
				{
					unset($this->tokens[$i-1]);
					// delete tokens till ( 
					$newbraceopen = 1;
					$f = 2;
					while( $newbraceopen !== 0 && $this->tokens[$i - $f] !== ';')
					{
						if( $this->tokens[$i - $f] === '(' )
						{
							$newbraceopen--;
						}
						else if( $this->tokens[$i - $f] === ')' )
						{
							$newbraceopen++;
						}
						unset($this->tokens[$i - $f]);	
						$f++;
						
						if(($i-$f)<0)
						{
							addError('Could not find opening parenthesis in ternary operator (1).', array_slice($this->tokens, $i-5, 10), $this->tokens[$i+1][2], $this->filename);
							break;	
						}
					}

					//delete token before, if T_STRING
					if($this->tokens[$i-$f] === '!' || (is_array($this->tokens[$i-$f]) 
					&& ($this->tokens[$i-$f][0] === T_STRING || $this->tokens[$i-$f][0] === T_EMPTY || $this->tokens[$i-$f][0] === T_ISSET)))
					{
						unset($this->tokens[$i-$f]);
					}
					
				}
				// condition is a check or assignment
				else if(in_array($this->tokens[$i-2][0], Tokens::$T_ASSIGNMENT) || in_array($this->tokens[$i-2][0], Tokens::$T_OPERATOR) )
				{
					// remove both operands
					unset($this->tokens[$i-1]);
					unset($this->tokens[$i-2]);
					// if operand is in braces
					if($this->tokens[$i-3] === ')')
					{
						// delete tokens till ( 
						$newbraceopen = 1;
						$f = 4;
						while( $newbraceopen !== 0 )
						{
							if( $this->tokens[$i - $f] === '(' )
							{
								$newbraceopen--;
							}
							else if( $this->tokens[$i - $f] === ')' )
							{
								$newbraceopen++;
							}
							unset($this->tokens[$i - $f]);	
							$f++;
							
							if(($i-$f)<0 || $this->tokens[$i - $f] === ';')
							{
								addError('Could not find opening parenthesis in ternary operator (2).', array_slice($this->tokens, $i-8, 6), $this->tokens[$i+1][2], $this->filename);
								break;	
							}
						}

						//delete token before, if T_STRING
						if(is_array($this->tokens[$i-$f]) 
						&& ($this->tokens[$i-$f][0] === T_STRING || $this->tokens[$i-$f][0] === T_EMPTY || $this->tokens[$i-$f][0] === T_ISSET))
						{
							unset($this->tokens[$i-$f]);
						}
					}

					unset($this->tokens[$i-3]);
					
				}
				// condition is a single variable, delete
				else if(is_array($this->tokens[$i-1]) && $this->tokens[$i-1][0] === T_VARIABLE)
				{
					unset($this->tokens[$i-1]);
				}
			}	
		}
		// return tokens with rearranged key index
		$this->tokens = array_values($this->tokens);	
	}
}	
```

---

## 4. Scanner：程序模型 + 跨文件内联 + 污点追踪

### 4.1 数据结构：追踪树是怎么存的
在 [lib/constructer.php](file:///d:/phpstudy_pro/WWW/rips/lib/constructer.php)：
- `VarDeclare`：一次变量声明（或“赋值语句片段”）的抽象，带 token 范围、依赖条件（if/switch）、数组 key 等（见 [constructer.php](file:///d:/phpstudy_pro/WWW/rips/lib/constructer.php#L18-L47)）
- `VulnTreeNode`：一个漏洞点的追踪树节点（children 递归形成树）（见 [constructer.php](file:///d:/phpstudy_pro/WWW/rips/lib/constructer.php#L72-L108)）
- `VulnBlock`：把同一个 sink 触发的若干追踪树聚合到一起，并打上漏洞类别（见 [constructer.php](file:///d:/phpstudy_pro/WWW/rips/lib/constructer.php#L49-L70)）

```php
// variable declarations = childs
class VarDeclare
{
	public $id;
	public $tokens;	
	public $tokenscanstart;
	public $tokenscanstop;
	public $value;
	public $comment;
	public $line;	
	public $marker;
	public $dependencies;
	public $stopvar;
	public $array_keys;
	
	function __construct($tokens = array(), $comment = '') 
	{
		$this->id = 0;
		$this->tokens = $tokens;
		$this->tokenscanstart = 0;
		$this->tokenscanstop = count($tokens);
		$this->value = '';
		$this->comment = $comment;
		$this->line = '';
		$this->marker = 0;
		$this->dependencies = array();
		$this->stopvar = false;
		$this->array_keys = array();
	}
}

// group vulnerable parts to one vulnerability trace
class VulnBlock
{
	public $uid;
	public $vuln;
	public $category;
	public $treenodes;
	public $sink;
	public $dataleakvar;
	public $alternates;
	
	function __construct($uid = '', $category = 'match', $sink = '') 
	{
		$this->uid = $uid;
		$this->vuln = false;
		$this->category = $category;
		$this->treenodes = array();
		$this->sink = $sink;
		$this->dataleakvar = array();
		$this->alternates = array();
	}
}

// used to store new finds
class VulnTreeNode
{
	public $id;
	public $value;
	public $dependencies;
	public $title;
	public $name;
	public $marker;
	public $lines;
	public $filename;
	public $children;
	public $funcdepend;
	public $funcparamdepend;
	public $foundcallee;
	public $get;
	public $post;
	public $cookie;
	public $files;
	public $server;

	function __construct($value = null) 
	{
		$this->id = 0;
		$this->value = $value;
		$this->title = '';
		$this->dependencies = array();
		$this->name = '';
		$this->marker = 0;
		$this->lines = array();
		$this->filename = '';
		$this->children = array();
		$this->funcdepend = '';
		$this->funcparamdepend = null;
		$this->foundcallee = false;
	}
}
```

### 4.2 include/require：RIPS 如何做到“跨文件追踪”
这是开源版 RIPS 最有特色的一点：它不是单独建 AST/CFG，而是用一种更“工程化”的办法——**把被 include 的文件 token 直接插入当前 token 流**。

位置在 [scanner.php](file:///d:/phpstudy_pro/WWW/rips/lib/scanner.php#L1332-L1572)：
- 发现 `include/require`（仅在非函数内：`&& !$this->in_function`）
- 尝试解析 include 的目标路径：
  - 静态字符串 `include 'a.php'` 直接取值
  - 动态 include：调用 [Analyzer::get_tokens_value](file:///d:/phpstudy_pro/WWW/rips/lib/analyzer.php#L18-L115) 尽量把表达式“还原成字符串”（能还原到多大取决于变量是否可解析）
  - 结合 `include_path`、相对路径、多级 `../` 猜测等做落地查找（同段代码）
- 找到文件后：
  - `Tokenizer` 解析该文件得到 `$inc_tokens`
  - 把 `$inc_tokens` **插入**到当前 `$this->tokens` 中，并额外插入一个 `T_INCLUDE_END` 作为边界标记（见 [scanner.php](file:///d:/phpstudy_pro/WWW/rips/lib/scanner.php#L1495-L1513)）
  - 同时维护 `lines_stack/file_pointer/inc_file_stack/tif_stack`，让后续的报表能正确显示“追踪到的是哪个文件的哪一行”（见 [scanner.php](file:///d:/phpstudy_pro/WWW/rips/lib/scanner.php#L1517-L1541)）
- 当扫描到 `T_INCLUDE_END` 时弹栈恢复（见 [scanner.php](file:///d:/phpstudy_pro/WWW/rips/lib/scanner.php#L2228-L2237)）

**代码：include/require 内联（Scanner::parse 的 FILE INCLUSION 分支）**

```php
// include tokens from included files
else if( in_array($token_name, Tokens::$T_INCLUDES) && !$this->in_function)
{						
	$GLOBALS['count_inc']++;
	// include('xxx')
	if ( (($this->tokens[$i+1] === '(' 
		&& $this->tokens[$i+2][0] === T_CONSTANT_ENCAPSED_STRING
		&& $this->tokens[$i+3] === ')')
	// include 'xxx'
	|| (is_array($this->tokens[$i+1])
		&& $this->tokens[$i+1][0] === T_CONSTANT_ENCAPSED_STRING
		&& $this->tokens[$i+2] === ';' )) )
	{					
		// include('file')
		if($this->tokens[$i+1] === '(')
		{
			$inc_file = substr($this->tokens[$i+2][1], 1, -1);
			$skip = 5;
		}
		// include 'file'
		else
		{
			$inc_file = substr($this->tokens[$i+1][1], 1, -1);
			$skip = 3;
		}	
	}
	// dynamic include
	else
	{
		$inc_file = Analyzer::get_tokens_value(
			$this->file_pointer,
			array_slice($this->tokens, $i+1, $c=Analyzer::getBraceEnd($this->tokens, $i+1)+1), 
			$this->in_function ? $this->var_declares_local : $this->var_declares_global, 
			$this->var_declares_global, 
			$i
		);

		// in case the get_var_value added several php files, take the first
		$several = explode('.php', $inc_file);
		if(count($several) > 1)
			$try_file = $several[0] . '.php';

		$skip = $c+1; // important to save $c+1 here
	}

	$try_file = $inc_file;

	// try absolute include path
	foreach($this->include_paths as $include_path)
	{
		if(is_file("$include_path/$try_file"))
		{
			$try_file = "$include_path/$try_file";	
			break;
		}
	}

	// if dirname(__FILE__) appeared it was an absolute path
	if(!is_file($try_file))
	{
		// check relativ path
		$try_file = dirname($this->file_name). '/' . $inc_file;
		
		if(!is_file($try_file))
		{
			$other_try_file = dirname($this->file_pointer). '/' . $inc_file;
			
			// if file can not be found check include_path if set
			if(!is_file($other_try_file)) 
			{
				if(isset($this->include_paths[0]))
				{
					foreach($this->include_paths as $include_path)
					{
						if(is_file(dirname($this->file_name).'/'.$include_path.'/'.$inc_file))
						{
							$try_file = dirname($this->file_name).'/'.$include_path.'/'.$inc_file;
							break;
						}
						else if(is_file(dirname($this->file_pointer).'/'.$include_path.'/'.$inc_file))
						{
							$try_file = dirname($this->file_pointer).'/'.$include_path.'/'.$inc_file;
							break;
						}
					}
				}
				
				// if still not a valid file, look a directory above
				if(!is_file($try_file))
				{
					$try_file = str_replace('\\', '/', $try_file);
					$pos = strlen($try_file);
					for($c=1; $c<substr_count($try_file, '/'); $c++)
					{
						$pos = strripos(substr($try_file,1,$pos), '/');
						if(is_file(substr_replace($try_file, '/../', $pos+1, 1)))
						{
							$try_file = substr_replace($try_file, '/../', $pos+1, 1);
							break;
						}
					}
				
					if(!is_file($try_file))
					{
						$try_file = str_replace('\\', '/', $other_try_file);
						$pos = strlen($try_file);
						for($c=1; $c<substr_count($try_file, '/'); $c++)
						{
							$pos = strripos(substr($try_file,1,$pos), '/');
							if(is_file(substr_replace($try_file, '/../', $pos+1, 1)))
							{
								$try_file = substr_replace($try_file, '/../', $pos+1, 1);
								break;
							}
						}
				
						// if still not a valid file, guess it
						if(!is_file($try_file))
						{
							$searchfile = basename($try_file);
							if(!strstr($searchfile, '$_USERINPUT'))
							{
								foreach($GLOBALS['files'] as $cfile)
								{
									if(basename($cfile) == $searchfile)
									{
										$try_file = $cfile;
										break;
									}
								}
							}
						}
					
					}
				}
			} 
			else
			{
				$try_file = $other_try_file;
			}
		} 
	}
	
	$try_file_unreal = $try_file;
	$try_file = realpath($try_file);

	// file is valid
	if(!empty($try_file_unreal) && !empty($try_file) && $inc_lines = @file( $try_file_unreal ))
	{
		// file name has not been included
		if(!in_array($try_file, $this->inc_map))
		{	
			// Tokens
			$tokenizer = new Tokenizer($try_file);
			$inc_tokens = $tokenizer->tokenize(implode('',$inc_lines));
			unset($tokenizer);

			// if(include('file')) { - include tokens after { and not into the condition :S
			if($this->in_condition)
			{
				$this->tokens = array_merge(
					array_slice($this->tokens, 0, $this->in_condition+1), 	// before include in condition
					$inc_tokens, 											// included tokens
					array(array(T_INCLUDE_END, 0, 1)), 						// extra END-identifier
					array_slice($this->tokens, $this->in_condition+1) 		// after condition
				);
			} else
			{
				// insert included tokens in current tokenlist and mark end
				$this->tokens = array_merge(
					array_slice($this->tokens, 0, $i+$skip), 			// before include
					$inc_tokens, 										// included tokens
					array(array(T_INCLUDE_END, 0, 1)), 					// extra END-identifier
					array_slice($this->tokens, $i+$skip) 				// after include
				);
			}
			
			$tokencount = count($this->tokens);
			
			$this->lines_stack[] = $inc_lines;
			$this->lines_pointer = end($this->lines_stack);
			
			$this->tif_stack[] = $this->tif;
			$this->tif = -$skip;
			
			$this->file_pointer = $try_file;
			if(!isset($GLOBALS['file_sinks_count'][$this->file_pointer]))
				$GLOBALS['file_sinks_count'][$this->file_pointer] = 0;

			echo $GLOBALS['fit'] . '|' . $GLOBALS['file_amount'] . '|' . $this->file_pointer . '|' . $GLOBALS['timeleft'] . '|' ."\n";
			@ob_flush();
			flush();
													
			$this->comment = basename($inc_file);
			
			$this->inc_file_stack[] = $try_file;	

			$this->inc_map[] = $try_file; // all basic includes
		} 
	}
	else
	{
		$GLOBALS['count_inc_fail']++;
	}
}	
```

**代码：include 结束标记（T_INCLUDE_END）恢复文件/行号指针**

```php
else if( $token_name === T_INCLUDE_END)
{
	array_pop($this->lines_stack);
	$this->lines_pointer = end($this->lines_stack);	
	array_pop($this->inc_file_stack);
	$this->file_pointer = end($this->inc_file_stack);
	$this->comment = basename($this->file_pointer) == basename($this->file_name) ? '' : basename($this->file_pointer);
	$this->tif = array_pop($this->tif_stack);
}					
```

这套机制的效果：一次 `Scanner($entryFile)->parse()` 的 token 流里，可能包含了多个文件的 token，因此**变量赋值、函数调用、sink 出现的位置可以跨文件连起来**（对典型的 include 架构很有效）。

### 4.3 变量建模：如何记录“$a 的值从哪里来”
在 `parse()` 的 token 遍历中，RIPS 会识别赋值/数组/foreach/list/preg_match 等模式，把“左值变量”写入 `var_declares_global`（全局）或 `var_declares_local`（函数内）：

- `$var = ...;`：记录声明点 token 片段，用于后续反向追踪（见 [scanner.php](file:///d:/phpstudy_pro/WWW/rips/lib/scanner.php#L943-L1028)）
- `array(...)`：按元素/键值拆分成多个“伪声明”，让 `$a['k']` 也能被回溯（见 [scanner.php](file:///d:/phpstudy_pro/WWW/rips/lib/scanner.php#L948-L1009)）
- `foreach ($x as $k => $v)`：把 `$k/$v` 视为由 `$x` 导出的声明（见 [scanner.php](file:///d:/phpstudy_pro/WWW/rips/lib/scanner.php#L870-L895)）
- `list($a,$b)=...`：把 list 也转换为声明（见 [scanner.php](file:///d:/phpstudy_pro/WWW/rips/lib/scanner.php#L2193-L2227)）

额外处理：
- `$GLOBALS[...]`、`$_SESSION`、`register_globals` 兼容逻辑在反向追踪里有专门分支（见 [scan_parameter](file:///d:/phpstudy_pro/WWW/rips/lib/scanner.php#L183-L216) 一带）。

### 4.4 污点追踪核心：scan_parameter() 反向递归
核心函数是 [Scanner::scan_parameter](file:///d:/phpstudy_pro/WWW/rips/lib/scanner.php#L149-L556)：

它做的事可以理解为：

> 给定一个“当前变量 token”（可能带数组 key），在已记录的声明表里找到“最近一次、且在当前位置之前”的赋值，然后把赋值右侧表达式里出现的变量继续递归追踪；一旦遇到 source 或 tainting function，就标记为 tainted；若遇到 sanitizer 包裹或类型转换，则视为被净化（在一定 verbosity 下会剪枝）。

几个关键点：
- **声明匹配**：用 `VarDeclare->id < last_token_id` 保证只用“之前发生的赋值”，并用数组 key 差异来判断 `$a['x']` vs `$a['y']`（见 [scanner.php](file:///d:/phpstudy_pro/WWW/rips/lib/scanner.php#L221-L236)）
- **依赖条件（控制流）**：每条赋值可以带 `dependencies`（如 if/else/switch 的条件 token），用于报表里展示“需要满足什么条件才能走到这里”（见 parse 里对 `Tokens::$T_FLOW_CONTROL` 的处理，以及 `{`/`}` 入栈出栈，见 [scanner.php](file:///d:/phpstudy_pro/WWW/rips/lib/scanner.php#L1986-L2001) 和 [scanner.php](file:///d:/phpstudy_pro/WWW/rips/lib/scanner.php#L2244-L2303)）
- **source 识别**：
  - 直接变量：`Sources::$V_USERINPUT`（并对 `$_SERVER` 只认特定 key/HTTP_ 头，见 [scanner.php](file:///d:/phpstudy_pro/WWW/rips/lib/scanner.php#L507-L555)）
  - 函数返回：若 RHS 出现 `source_functions` 中的函数名，认为 tainted（见 [scanner.php](file:///d:/phpstudy_pro/WWW/rips/lib/scanner.php#L362-L381)）
- **sanitizer 识别**：
  - 显式净化函数：`$F_SECURING_*` / `$F_SECURING_STRING` / cast（见 [scanner.php](file:///d:/phpstudy_pro/WWW/rips/lib/scanner.php#L382-L390)）
  - 反净化函数：`$F_INSECURING_STRING` 会让后续追踪“忽略净化”（见 [scanner.php](file:///d:/phpstudy_pro/WWW/rips/lib/scanner.php#L391-L396)）
- **剪枝与误报控制**：
  - `MAXTRACE` 限制追踪深度（见 [scanner.php](file:///d:/phpstudy_pro/WWW/rips/lib/scanner.php#L239-L279)）
  - 遇到另一个 sink/interesting 点会“trace stopped”（避免爆炸并减少噪声，见 [scanner.php](file:///d:/phpstudy_pro/WWW/rips/lib/scanner.php#L397-L409)）

**代码：scan_parameter()（完整函数体）**

```php
// traces recursivly parameters and adds them as child to parent
// returns true if a parameter is tainted by userinput (1=directly tainted, 2=function param)
function scan_parameter($mainparent, $parent, $var_token, $var_keys=array(), $last_token_id, $var_declares, $var_declares_global=array(), $userinput, $F_SECURES=array(), $return_scan=false, $ignore_securing=false, $secured=false)
{	
	$vardependent = false;
	
	$var_name = $var_token[1]; 
	// constants
	if($var_name[0] !== '$')
	{
		$var_name = strtoupper($var_name);
	} 
	// variables
	else
	{
		// reconstruct array key values $a[$b]
		if(isset($var_token[3]))
		{
			for($k=0;$k<count($var_token[3]); $k++)
			{
				if(is_array($var_token[3][$k]))
				{
					$var_token[3][$k] = Analyzer::get_tokens_value(
						$this->file_pointer,
						$var_token[3][$k], 
						$var_declares, 
						$var_declares_global, 
						$last_token_id
					);
				}	
			}
		}	
		
		// handle $GLOBALS and $_SESSIONS
		if(isset($var_token[3]))
		{
			if($var_name == '$GLOBALS' && !isset($var_declares[$var_name]) && !empty($var_token[3][0]) ) 
			{
				$var_name = '$'. str_replace(array("'",'"'), '', $var_token[3][0]);
				// php $GLOBALS: ignore previous local vars and take only global vars
				$var_declares = $var_declares_global;
			}
			else if($var_name === '$_SESSION' && !isset($var_declares[$var_name]) && !empty($var_declares_global))
			{
				// $_SESSION data is handled as global variables
				$var_declares = array_merge($var_declares_global, $var_declares);
			}
		}
	
		// if a register_globals implementation is present shift it to the beginning of the var_declare array
		if(isset($var_declares['register_globals']) && !in_array($var_name, Sources::$V_USERINPUT)
		&& (!$this->in_function || in_array($var_name, $this->put_in_global_scope)))
		{		
			if(!isset($var_declares[$var_name]))
			{
				$var_declares[$var_name] = $var_declares['register_globals'];
			}	
			else	
			{
				foreach($var_declares['register_globals'] as $glob_obj)
				{
					if($glob_obj->id < $last_token_id)
						$var_declares[$var_name][] = $glob_obj;
				}
			}	
		}	
	}

	// check if var declaration could be found for this var
	if( isset($var_declares[$var_name]) && (end($var_declares[$var_name])->id < $last_token_id || $userinput) )
	{		
		foreach($var_declares[$var_name] as $var_declare)
		{	
			// check if array keys are the same (if it is an array)
			$array_key_diff = array();
			if( !empty($var_token[3]) && !empty($var_declare->array_keys) )	
				$array_key_diff = array_diff_assoc($var_token[3], $var_declare->array_keys); 

			if( $var_declare->id < $last_token_id && (empty($array_key_diff) || in_array('*', $array_key_diff) || in_array('*', $var_declare->array_keys)) )
			{	
				$comment = '';
				// add line to output
				if(count($mainparent->lines) < MAXTRACE)				
				{
					$clean_vars_before_ifelse = false;
					// add same var_name with different dependencies
					if(!empty($var_declare->dependencies) && $mainparent->dependencies != $var_declare->dependencies )
					{							
						foreach($var_declare->dependencies as $deplinenr=>$dependency)
						{
							if( !isset($mainparent->dependencies[$deplinenr]) && $deplinenr != $var_declare->line )
							{	
								$vardependent = true;
								$comment.= tokenstostring($dependency).', ';
								// if dependencie has an ELSE clause, same vars before are definetely overwritten
								if($dependency[count($dependency)-1][0] === T_ELSE)
									$clean_vars_before_ifelse = true;
							}
						}
					}

					// stop at var declarations before if else statement. they are overwritten
					if($clean_vars_before_ifelse)
					{
						for($c=0;$c<count($var_declares[$var_name]);$c++)
						{	
							if(count($var_declares[$var_name][$c]->dependencies) < count($var_declare->dependencies))
							{
								$var_declares[$var_name][$c-1]->stopvar=true;
								break;
							}	
						}
					}
					
					$mainparent->lines[] = $var_declare->line;	
					$var_trace = new VarDeclare('');
					$parent->children[] = $var_trace;
				} else
				{	
					$stop = new VarDeclare('... Trace stopped.');
					$parent->children[] = $stop; 
					return $userinput;
				}
				
				// find other variables in this line
				$tokens = $var_declare->tokens;
				$last_userinput = false;
				$in_arithmetic = false;
				$in_securing = false;
				$parentheses_open = 0;
				$parentheses_save = -1;
				
				$tainted_vars = array();
				$var_count = 1;

				for($i=$var_declare->tokenscanstart; $i<$var_declare->tokenscanstop; $i++)
				{
					$this_one_is_secure = false;
					if( is_array($tokens[$i]) )
					{
						// if token is variable or constant
						if( ($tokens[$i][0] === T_VARIABLE && $tokens[$i+1][0] !== T_OBJECT_OPERATOR)
						|| ($tokens[$i][0] === T_STRING && $tokens[$i+1] !== '(') )
						{	
							$var_count++;

							// check if typecasted
							if((is_array($tokens[$i-1]) 
							&& in_array($tokens[$i-1][0], Tokens::$T_CASTS))
							|| (is_array($tokens[$i+1]) 
							&& in_array($tokens[$i+1][0], Tokens::$T_ARITHMETIC)) )
							{
								$GLOBALS['userfunction_secures'] = true;
								$this_one_is_secure = true;

								$var_trace->marker = 2;
							} 
							
							// check for automatic typecasts by arithmetic
							if(in_array($tokens[$i-1], Tokens::$S_ARITHMETIC)
							|| in_array($tokens[$i+1], Tokens::$S_ARITHMETIC) )
							{
								$GLOBALS['userfunction_secures'] = true;
								$in_arithmetic = true;
								$var_trace->marker = 2;
							}
							
							$userinput = $this->scan_parameter(
								$mainparent, 
								$var_trace, 
								$tokens[$i], 
								$var_keys,
								$var_declare->id, 
								((is_array($tokens[$i-1]) && $tokens[$i-1][0] === T_GLOBAL) || $tokens[$i][1][0] !== '$') ? $var_declares_global : $var_declares,
								$var_declares_global, 
								$userinput,
								$F_SECURES, 
								$return_scan, 
								$ignore_securing, 
								($this_one_is_secure || $in_securing || $in_arithmetic)
							);

							if($secured && $GLOBALS['verbosity'] < 3 && !$last_userinput) 
							{
								$userinput = false;
							}	
							
							if($userinput && !$last_userinput)
							{
								$tainted_vars[] = $var_count;
							}
						}
						// if in foreach($bla as $key=>$value) dont trace $key, $value back
						else if( $tokens[$i][0] === T_AS )
						{
							break;
						}
						// also check for userinput from functions returning userinput
						else if( in_array($tokens[$i][1], $this->source_functions) )
						{
							$userinput = true;
							$var_trace->marker = 4;
							$mainparent->title = 'Userinput returned by function <i>'.$tokens[$i][1].'()</i> reaches sensitive sink.';
							
							if($return_scan)
							{
								$GLOBALS['userfunction_taints'] = true;
							}	
							else if($this->in_function)
							{
								$this->addtriggerfunction($mainparent);
							}	
						}
						// detect securing functions
						else if(!$ignore_securing && ( (is_array($F_SECURES) && in_array($tokens[$i][1], $F_SECURES))
						|| (isset($tokens[$i][1]) && in_array($tokens[$i][1], $GLOBALS['F_SECURING_STRING'])) 
						|| (in_array($tokens[$i][0], Tokens::$T_CASTS) && $tokens[$i+1] === '(') )  )
						{
							$parentheses_save = $parentheses_open;
							$in_securing = true;
							$this->securedby[] = $tokens[$i][1];
						}
						//detect insecuring functions
						else if( isset($tokens[$i][1]) && in_array($tokens[$i][1], $GLOBALS['F_INSECURING_STRING']))
						{
							$parentheses_save = $parentheses_open;
							$ignore_securing = true;
						}
						else if( ((in_array($tokens[$i][0], Tokens::$T_FUNCTIONS) 
						&& isset($GLOBALS['scan_functions'][$tokens[$i][1]]))
						|| isset(Info::$F_INTEREST[$tokens[$i][1]]))
						&& !isset($GLOBALS['F_CODE'][$tokens[$i][1]]) 
						&& !isset($GLOBALS['F_REFLECTION'][$tokens[$i][1]]) 
						&& !isset($GLOBALS['F_OTHER'][$tokens[$i][1]]))
						{
							$var_trace->value = highlightline($tokens, $comment.$var_declare->comment.', trace stopped', $var_declare->line);
							$var_trace->line = $var_declare->line;
							return $userinput;
						}
						else if(in_array($tokens[$i][0], Tokens::$T_ASSIGNMENT_SECURE))
						{
							$GLOBALS['userfunction_secures'] = true;
							$secured = 'arithmetic assignment';

							$userinput = false;
							$var_trace->marker = 2;
						}
						else if($tokens[$i][1] === 'func_get_args' && $this->in_function && $tokens[$i][0] === T_STRING)
						{
							$this->addfunctiondependend($mainparent, $parent, $return_scan, -1);
							$userinput = 2;
						}
						else if($tokens[$i][1] === 'func_get_arg' && $this->in_function && $tokens[$i][0] === T_STRING)
						{
							$this->addfunctiondependend($mainparent, $parent, $return_scan, $tokens[$i+2][1]);
							$userinput = 2;
						}
					}
					else if($tokens[$i] === '.')
					{
						$in_arithmetic = false;
					}
					else if($tokens[$i] === '(')
					{
						$parentheses_open++;
					}
					else if($tokens[$i] === ')')
					{
						$parentheses_open--;
						if($parentheses_open === $parentheses_save)
						{
							$parentheses_save = -1;
							$in_securing = false;
							$ignore_securing = false;
						}
					}
										
					$last_userinput = $userinput;
				}

				$var_trace->value = highlightline($tokens, $var_declare->comment.$comment, $var_declare->line, false, false, $tainted_vars);
				$var_trace->line = $var_declare->line;
	
				if( ($userinput || !$vardependent || $var_declare->stopvar) && !in_array('*', $array_key_diff)) 
					break;
			}
		}
	}
	else if($this->in_function && in_array($var_name, $this->function_obj->parameters) && ($GLOBALS['verbosity'] >= 3 || empty($secured)) )
	{
		$key = array_search($var_name, $this->function_obj->parameters);
		$this->addfunctiondependend($mainparent, $parent, $return_scan, $key);
		$userinput = 2;
	} 
	else if(SCAN_REGISTER_GLOBALS && $var_token[0] === T_VARIABLE && !in_array($var_name, Sources::$V_USERINPUT) && (!$this->in_function || (in_array($var_name, $this->put_in_global_scope) && !in_array($var_name, $this->function_obj->parameters))) && empty($secured))
	{
		$var_trace = new VarDeclare('');
		$parent->children[] = $var_trace;
		$var_trace->value = highlightline(array(array(T_VARIABLE,$var_name,0),array(T_CONSTANT_ENCAPSED_STRING,' is not initialized and '.PHPDOC.'register_globals is enabled',0)), $var_declare->comment.$comment, 0, false, false, $tainted_vars);
		$var_trace->line = 0;
		$var_trace->marker = 1;
		$userinput = true;
		$this->addexploitparameter($mainparent, '$_GET', str_replace('$','',$var_name));
	}
	
	// if var is userinput, return true directly	
	if( in_array($var_name, Sources::$V_USERINPUT) && empty($secured) )
	{
		$overwritten = false;
		if(isset($var_declares[$var_name]))
		{
			foreach($var_declares[$var_name] as $var)
			{
				$array_key_diff = false;
				if( isset($var_token[3]) && !empty($var_declare->array_keys) )		
					$array_key_diff = array_diff_assoc($var_token[3], $var_declare->array_keys);
			
				if($last_token_id != $var->id && !$array_key_diff)
					$overwritten = true;
			}
		}	

		if(!$overwritten)
		{
			if(isset($var_token[3]))
				$parameter_name = str_replace(array("'",'"'), '', $var_token[3][0]);
			else
				$parameter_name = 'x';
			
			if($var_name !== '$_SERVER'
			|| in_array($parameter_name, Sources::$V_SERVER_PARAMS) 
			|| substr($parameter_name,0,5) === 'HTTP_')
			{
				$userinput = true;
				$parent->marker = 1;			

				$this->addexploitparameter($mainparent, $var_name, $parameter_name);
				
				if(!empty($mainparent->dependencies))
				{
					foreach($mainparent->dependencies as $dtokens)
					{
						for($t=0;$t<count($dtokens);$t++)
						{						
							if($dtokens[$t][0] === T_VARIABLE && in_array($dtokens[$t][1], Sources::$V_USERINPUT) && ($dtokens[$t][1] !== '$_SERVER' || in_array($dtokens[$t][3][0], Sources::$V_SERVER_PARAMS)
							|| substr($dtokens[$t][3][0],0,5) === 'HTTP_'))
							{
								$this->addexploitparameter($mainparent, $dtokens[$t][1], str_replace(array('"',"'"), '', $dtokens[$t][3][0]));		
							}
						}
					}
				}
			}
						
			if($this->in_function && !$return_scan)
			{
				$this->addtriggerfunction($mainparent);
			}
		}
	} 
	
	return $userinput;
}
```

---

## 5. sink 命中：RIPS 如何判定“这里可能有漏洞”

在 `parse()` 中扫描到一个“调用 token”（`Tokens::$T_FUNCTIONS` 或 XSS 特殊 token）时，会进入 taint analysis 分支：
- 判断该调用名是否在当次 `scan_functions` 中（由 [main.php](file:///d:/phpstudy_pro/WWW/rips/main.php#L79-L146) 选择出来）
- 只追踪“规则指定的参数位置”（见 [scanner.php](file:///d:/phpstudy_pro/WWW/rips/lib/scanner.php#L1613-L1687)）
- 对每个危险参数调用 `scan_parameter()`：
  - 结果 `userinput == 1`：直接 tainted
  - `userinput == 2`：依赖函数参数（需要触发点/调用点），RIPS 会记录 function-dependent 信息（相关逻辑在 scan_parameter 内部多处）

### 5.1 引号分析（典型：SQL escape 的误用）
RIPS 识别出“净化函数包裹了参数”后，并不总是认为安全：
- 对 `mysql_real_escape_string` 这类（`F_QUOTE_ANALYSIS`），如果净化后的变量没有处于引号中，净化可能无效，仍可判定为危险（见 `quote_analysis_needed()` 和后续检查逻辑，入口在 [scanner.php](file:///d:/phpstudy_pro/WWW/rips/lib/scanner.php#L819-L828)，使用点在 sink 扫描大循环中）。

```php
// check if securing function is listed as securing that depends on quotes	
function quote_analysis_needed()
{
	foreach($this->securedby as $var=>$func)
	{
		if(in_array($func, $GLOBALS['F_QUOTE_ANALYSIS']))
			return true;
	}
	return false;
}
```

---

## 6. 用户自定义函数：RIPS 如何实现“跨函数追踪/推断净化与污染”

RIPS 会记录用户定义函数的声明、参数、调用关系用于图展示与更好的追踪（见 [scanner.php](file:///d:/phpstudy_pro/WWW/rips/lib/scanner.php#L2006-L2083) 和 [printer.php](file:///d:/phpstudy_pro/WWW/rips/lib/printer.php#L500-L620)）。

更重要的是：它会**推断某个用户函数是否是 sanitizer 或 source**：
- 在函数体内遇到 `return`，对返回表达式做 `scan_parameter(..., $return_scan=TRUE)`（见 [scanner.php](file:///d:/phpstudy_pro/WWW/rips/lib/scanner.php#L2113-L2164)）
- 若返回值不含用户输入，或出现类型转换/净化痕迹，则把该函数加入全局 `F_SECURING_STRING`（未来用作 sanitizer）
- 若返回值含用户输入（或函数内部取了用户输入并返回），则把该函数加入 `source_functions`（未来用作 tainting function）

这就是 RIPS 能做到“函数 A 返回经过净化的数据/返回用户输入”这种跨函数传播的原因之一（尽管开源版对复杂 OOP/多态支持有限）。

---

## 7. 结果输出：追踪树如何变成你看到的页面

### 7.1 输出数据的组织
当一个 sink 被判定“有 tainted 参数”时：
- 构造 `VulnTreeNode`（单次命中点）
- 归并进 `VulnBlock`（同类漏洞块），并写入全局 `$output[$entryFile][]`（见 [scanner.php](file:///d:/phpstudy_pro/WWW/rips/lib/scanner.php#L760-L772)）

### 7.2 HTML 渲染与交互
- [printer.php](file:///d:/phpstudy_pro/WWW/rips/lib/printer.php) 的 `printoutput()` 负责按文件、按类别输出，并把每棵树按 bottom-up/top-down 渲染（见 [printer.php](file:///d:/phpstudy_pro/WWW/rips/lib/printer.php#L354-L499)）
- `highlightline()` 会把 token 转成带 CSS class 的 HTML，并额外支持：
  - 点击变量高亮/追踪
  - 点击函数名跳转定义/调用
  - 打开代码查看器（见 [printer.php](file:///d:/phpstudy_pro/WWW/rips/lib/printer.php#L61-L191)）
- 代码查看器是 [windows/code.php](file:///d:/phpstudy_pro/WWW/rips/windows/code.php)，它对单行用 `token_get_all('<? '.$line.' ?>')` 做语法着色，并标记行号（见 [code.php](file:///d:/phpstudy_pro/WWW/rips/windows/code.php#L21-L126)）
- “数据泄漏扫描”入口是 [windows/leakscan.php](file:///d:/phpstudy_pro/WWW/rips/windows/leakscan.php)：
  - 本质上是再跑一遍 scanner（主要看输出点/HTML 输出路径），然后检查指定变量名是否出现在输出追踪树里（见 [leakscan.php](file:///d:/phpstudy_pro/WWW/rips/windows/leakscan.php#L112-L189)）

**代码：输出渲染（highlightline + printoutput）**

```php
// prepare output to style with CSS
function highlightline($tokens=array(), $comment='', $line_nr, $title=false, $udftitle=false, $tainted_vars=array())
{
	$reference = true;
	$output = "<span class=\"linenr\">$line_nr:</span>&nbsp;";
	if($title)
	{
		$output.='<a class="link" href="'.PHPDOC.$title.'" title="open php documentation" target=_blank>';
		$output.="$title</a>&nbsp;";
	} 
	else if($udftitle)
	{
		$output.='<a class="link" style="text-decoration:none;" href="#'.$udftitle.'_declare" title="jump to declaration">&uArr;</a>&nbsp;';
	}
	
	$var_count = 0;
	
	for($i=0;$i<count($tokens);$i++)
	{
		$token = $tokens[$i];
		if (is_string($token))
		{		
			if($token === ',' || $token === ';')
				$output .= "<span class=\"phps-code\">$token&nbsp;</span>";
			else if(in_array($token, Tokens::$S_SPACE_WRAP) || in_array($token, Tokens::$S_ARITHMETIC))
				$output .= '<span class="phps-code">&nbsp;'.$token.'&nbsp;</span>';
			else
				$output .= '<span class="phps-code">'.htmlentities($token, ENT_QUOTES, 'utf-8').'</span>';
				
		} 
		else if (is_array($token) 
		&& $token[0] !== T_OPEN_TAG
		&& $token[0] !== T_CLOSE_TAG) 
		{
			
			if(in_array($token[0], Tokens::$T_SPACE_WRAP) || in_array($token[0], Tokens::$T_OPERATOR) || in_array($token[0], Tokens::$T_ASSIGNMENT))
			{
				$output.= '&nbsp;<span class="phps-'.str_replace('_', '-', strtolower(token_name($token[0])))."\">{$token[1]}</span>&nbsp;";
			}	
			else
			{
				if($token[0] === T_FUNCTION)
				{
					$reference = false;
					$funcname = $tokens[$i+1][0] === T_STRING ? $tokens[$i+1][1] : $tokens[$i+2][1];
					$output .= '<A NAME="'.$funcname.'_declare" class="jumplink"></A>';
					$output .= '<a class="link" style="text-decoration:none;" href="#'.$funcname.'_call" title="jump to call">&dArr;</a>&nbsp;';
				}	
				
				$text = htmlentities($token[1], ENT_QUOTES, 'utf-8');
				$text = str_replace(array(' ', "\n"), '&nbsp;', $text);

				if($token[0] === T_FUNCTION)
					$text.='&nbsp;';
					
				if($token[0] === T_STRING && $reference 
				&& isset($GLOBALS['user_functions_offset'][strtolower($text)]))
				{				
					$text = @'<span onmouseover="getFuncCode(this,\''.addslashes($GLOBALS['user_functions_offset'][strtolower($text)][0]).'\',\''.$GLOBALS['user_functions_offset'][strtolower($text)][1].'\',\''.$GLOBALS['user_functions_offset'][strtolower($text)][2].'\')" style="text-decoration:underline" class="phps-'.str_replace('_', '-', strtolower(token_name($token[0])))."\">$text</span>\n";
				}	
				else 
				{
					$span = '<span ';
				
					if($token[0] === T_VARIABLE)
					{
						$var_count++;
						$cssname = str_replace('$', '', $token[1]);
						$span.= 'style="cursor:pointer;" name="phps-var-'.$cssname.'" onClick="markVariable(\''.$cssname.'\')" ';
						$span.= 'onmouseover="markVariable(\''.$cssname.'\')" onmouseout="markVariable(\''.$cssname.'\')" ';
					}	
					
					if($token[0] === T_VARIABLE && @in_array($var_count, $tainted_vars))
						$span.= "class=\"phps-tainted-var\">$text</span>";	
					else
						$span.= 'class="phps-'.str_replace('_', '-', strtolower(token_name($token[0])))."\">$text</span>";
						
					$text = $span;	
					
					// rebuild array keys
					if(isset($token[3]))
					{
						foreach($token[3] as $key)
						{
							if($key != '*')
							{
								$text .= '<span class="phps-code">[</span>';
								if(!is_array($key))
								{
									if(is_numeric($key))
										$text .= '<span class="phps-t-lnumber">' . $key . '</span>';
									else
										$text .= '<span class="phps-t-constant-encapsed-string">\'' . htmlentities($key, ENT_QUOTES, 'utf-8') . '\'</span>';
								} else
								{
									foreach($key as $token)
									{
										if(is_array($token))
										{
											$text .= '<span ';
											
											if($token[0] === T_VARIABLE)
											{
												$cssname = str_replace('$', '', $token[1]);
												$text.= 'style="cursor:pointer;" name="phps-var-'.$cssname.'" onClick="markVariable(\''.$cssname.'\')" ';
												$text.= 'onmouseover="markVariable(\''.$cssname.'\')" onmouseout="markVariable(\''.$cssname.'\')" ';
											}	
											
											$text .= 'class="phps-'.str_replace('_', '-', strtolower(token_name($token[0]))).'">'.htmlentities($token[1], ENT_QUOTES, 'utf-8').'</span>';
										}	
										else
											$text .= "<span class=\"phps-code\">{$token}</span>";
									}
								}
								$text .= '<span class="phps-code">]</span>';
							}
						}
					}
				}
				$output .= $text;
				if(is_array($token) && (in_array($token[0], Tokens::$T_INCLUDES) || in_array($token[0], Tokens::$T_XSS) || $token[0] === 'T_EVAL'))
					$output .= '&nbsp;';
			}		
		}
	}
	
	if(!empty($comment))
		$output .= '&nbsp;<span class="phps-t-comment">// '.htmlentities($comment, ENT_QUOTES, 'utf-8').'</span>';

	return $output;
}

// print the scanresult
function printoutput($output, $treestyle=1)
{
	if(!empty($output))
	{
		$nr=0;
		reset($output);
		do
		{				
			if(key($output) != "" && !empty($output[key($output)]) && fileHasVulns($output[key($output)]))
			{		
				echo '<div class="filebox">',
				'<span class="filename">File: ',key($output),'</span><br>',
				'<div id="',key($output),'"><br>';

				foreach($output[key($output)] as $vulnBlock)
				{	
					if($vulnBlock->vuln)	
					{
						$nr++;
						echo '<div class="vulnblock">',
						'<div id="pic',$vulnBlock->category,$nr,'" class="minusico" name="pic',$vulnBlock->category,'" style="margin-top:5px" title="minimize"',
						' onClick="hide(\'',$vulnBlock->category,$nr,'\')"></div><div class="vulnblocktitle">',$vulnBlock->category,'</div>',
						'</div><div name="allcats"><div class="vulnblock" style="border-top:0px" name="',$vulnBlock->category,'" id="',$vulnBlock->category,$nr,'">';
						
						if($treestyle == 2)
							krsort($vulnBlock->treenodes);
						
						foreach($vulnBlock->treenodes as $tree)
						{
							{	
								echo '<div class="codebox"><table border=0>',"\n",
								'<tr><td valign="top" nowrap>',"\n",
								'<div class="fileico" title="review code" ',
								'onClick="openCodeViewer(this,\'',
								addslashes($tree->filename), '\',\'',
								implode(',', $tree->lines), '\');"></div>'."\n",
								'<div id="pic',key($output),$tree->lines[0],'" class="minusico" title="minimize"',
								' onClick="hide(\'',addslashes(key($output)),$tree->lines[0],'\')"></div><br />',"\n";

								if(isset($GLOBALS['scan_functions'][$tree->name]))
								{
									echo '<div class="help" title="get help" onClick="openHelp(this,\'',
									$vulnBlock->category,'\',\'',$tree->name,'\',\'',
									(int)!empty($tree->get),'\',\'',
									(int)!empty($tree->post),'\',\'',
									(int)!empty($tree->cookie),'\',\'',
									(int)!empty($tree->files),'\',\'',
									(int)!empty($tree->cookie),'\')"></div>',"\n";
									
									if(isset($GLOBALS['F_DATABASE'][$tree->name])
									|| isset($GLOBALS['F_FILE_AFFECT'][$tree->name]) 
									|| isset($GLOBALS['F_FILE_READ'][$tree->name]) 
									|| isset($GLOBALS['F_LDAP'][$tree->name])
									|| isset($GLOBALS['F_XPATH'][$tree->name])
									|| isset($GLOBALS['F_POP'][$tree->name]) )
									{
										if(!empty($vulnBlock->dataleakvar))
										{
											echo '<div class="dataleak" title="check data leak" onClick="leakScan(this,\'',
											$vulnBlock->dataleakvar[1],'\',\'',
											$vulnBlock->dataleakvar[0],'\', false)"></div>',"\n";
										} else
										{
											$tree->title .= ' (Blind exploitation)';
										}
									}	
								}
								
								if(!empty($tree->get) || !empty($tree->post) 
								|| !empty($tree->cookie) || !empty($tree->files)
								|| !empty($tree->server) )
								{
									echo '<div class="exploit" title="generate exploit" ',
									'onClick="openExploitCreator(this, \'',
									addslashes($tree->filename),
									'\',\'',implode(',',array_unique($tree->get)),
									'\',\'',implode(',',array_unique($tree->post)),
									'\',\'',implode(',',array_unique($tree->cookie)),
									'\',\'',implode(',',array_unique($tree->files)),
									'\',\'',implode(',',array_unique($tree->server)),'\');"></div>';
								}
								echo '</td><td><span class="vulntitle">',$tree->title,'</span>',
								'<div class="code" id="',key($output),$tree->lines[0],'">',"\n";

								if($treestyle == 1)
									traverseBottomUp($tree);
								else if($treestyle == 2)
									traverseTopDown($tree);

									echo '<ul><li>',"\n";
								dependenciesTraverse($tree);
								echo '</li></ul>',"\n",	'</div>',"\n", '</td></tr></table></div>',"\n";
							}
						}	
						
						if(!empty($vulnBlock->alternatives))
						{
							echo '<div class="codebox"><table><tr><td><ul><li><span class="vulntitle">Vulnerability is also triggered in:</span>';
							foreach($vulnBlock->alternatives as $alternative)
							{
								echo '<ul><li>'.$alternative.'</li></ul>';
							}
							echo '</li></ul></td></table></div>';
						}
						
						echo '</div></div><div style="height:20px"></div>',"\n";
					}	
				}

				echo '</div><div class="buttonbox">',"\n",
				'<input type="submit" class="Button" value="hide all" ',
				'onClick="hide(\'',addslashes(key($output)),'\')">',"\n",
				'</div></div><hr>',"\n";
			}	
			else if(count($output) == 1)
			{
				echo '<div style="margin-left:30px;color:#000000">Nothing vulnerable found. Change the verbosity level or vulnerability type  and try again.</div>';
			}
		}
		while(next($output));
	}
	else if(count($GLOBALS['scanned_files']) > 0)
	{
		echo '<div style="margin-left:30px;color:#000000">Nothing vulnerable found. Change the verbosity level or vulnerability type and try again.</div>';
	}
	else
	{
		echo '<div style="margin-left:30px;color:#000000">Nothing to scan. Please check your path/file name.</div>';
	}
}
```

---

## 8. 你真正关心的：RIPS 审计的“工作机制”抽象成一句话

RIPS 把 PHP 源码转换成 token 流，并用以下三个表驱动审计：

- **source 表**：哪些变量/函数返回值可控（[sources.php](file:///d:/phpstudy_pro/WWW/rips/config/sources.php)）
- **sink 表**：哪些调用危险、危险在哪些参数（[sinks.php](file:///d:/phpstudy_pro/WWW/rips/config/sinks.php)）
- **sanitizer 表**：哪些函数/类型转换能降低风险，哪些操作会破坏净化（[securing.php](file:///d:/phpstudy_pro/WWW/rips/config/securing.php)）

扫描时一旦遇到 sink，就对危险参数做“反向递归追踪”（[scan_parameter](file:///d:/phpstudy_pro/WWW/rips/lib/scanner.php#L149-L556)），追到 source 则报；追到 sanitizer 则（在一定条件下）不报；追不出就按 verbosity 策略输出可疑点。

---

## 9. 局限与误差来源（理解这些才能正确使用 RIPS）
- 静态分析不可避免的限制：动态 include、动态函数名/变量名、复杂字符串拼接、复杂控制流都可能导致：
  - include 解析失败（RIPS 会统计 include 成功率，见 [main.php](file:///d:/phpstudy_pro/WWW/rips/main.php#L356-L392)）
  - 漏报/误报
- 开源版对面向对象支持有限：遇到 `class` 会提示“不支持，可能不准确”（见 [scanner.php](file:///d:/phpstudy_pro/WWW/rips/lib/scanner.php#L2169-L2177)）

---

## 10. 如何基于源码扩展“审计能力”（改规则即可）
- 想新增一种 sink：在 [config/sinks.php](file:///d:/phpstudy_pro/WWW/rips/config/sinks.php) 增加函数名与危险参数位置，并给出对应净化函数列表。
- 想新增 source：在 [config/sources.php](file:///d:/phpstudy_pro/WWW/rips/config/sources.php) 增加超全局变量或 tainting function。
- 想新增 sanitizer：在 [config/securing.php](file:///d:/phpstudy_pro/WWW/rips/config/securing.php) 加入对应集合，并按需要放进 `F_QUOTE_ANALYSIS`（如果必须结合引号判断有效性）。

---
