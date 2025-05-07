import unittest
from unittest.mock import patch, MagicMock
import os
import tempfile
from io import StringIO
import sys
import json
from typing import List, Dict, Any, Set, Optional, Tuple, Union
import subprocess
import logging
import argparse
import importlib.util
import importlib.metadata
import ast
import re
import difflib
import time
from packaging.version import parse as parse_version, InvalidVersion
import requests
from requests.exceptions import RequestException, Timeout, ConnectionError
import hashlib # check_security_vulnerabilities のシミュレーションで使用
from functools import lru_cache

# --- Environment Configuration ---
class Config:
    """アプリケーション設定を環境変数から管理する構成クラス。"""

    # リクエスト設定
    REQUEST_TIMEOUT = int(os.environ.get('DEPENDENCY_CHECK_TIMEOUT', '10')) # 少し長めに
    REQUEST_RETRIES = int(os.environ.get('DEPENDENCY_CHECK_RETRIES', '3'))
    REQUEST_BACKOFF = float(os.environ.get('DEPENDENCY_CHECK_BACKOFF', '1.5'))

    # APIエンドポイント
    PYPI_API_URL = os.environ.get('PYPI_API_URL', 'https://pypi.org/pypi/{package}/json')
    NPM_API_URL = os.environ.get('NPM_API_URL', 'https://registry.npmjs.org/{package}')

    # セキュリティ設定 (より現実的な利用を想定)
    # 例: OSV形式の脆弱性情報を格納したローカルディレクトリや、特定のAPIエンドポイント
    # これらのURLは実際のデータベース構造やAPI仕様に依存します。
    # Pypa Advisory Database (OSV format) の GitHub リポジトリの例
    PYPA_ADVISORY_DB_URL_BASE = os.environ.get('PYPA_ADVISORY_DB_URL_BASE',
                                             'https://raw.githubusercontent.com/pypa/advisory-database/main/vulns/')
    # Node.js Security WG (OSV format) の GitHub リポジトリの例
    NODEJS_ADVISORY_DB_URL_BASE = os.environ.get('NODEJS_ADVISORY_DB_URL_BASE',
                                               'https://raw.githubusercontent.com/nodejs/security-wg/main/vuln/npm/')
    ADVISORY_REQUEST_TIMEOUT = int(os.environ.get('ADVISORY_REQUEST_TIMEOUT', '10'))


    # キャッシュ設定
    CACHE_EXPIRY = int(os.environ.get('DEPENDENCY_CACHE_EXPIRY', '3600'))  # 1時間デフォルト

    # ロギング
    LOG_LEVEL = os.environ.get('DEPENDENCY_LOG_LEVEL', 'INFO')

# --- Logging ---
def setup_logging():
    """適切なレベルと形式でロギングを設定します。"""
    log_level = getattr(logging, Config.LOG_LEVEL.upper(), logging.INFO)
    # Rich を使ってより見やすいログ出力も検討可能
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        stream=sys.stdout
    )
    return logging.getLogger(__name__)

logger = setup_logging()

# --- Constants ---
SUPPORTED_LANGUAGES = ['python', 'javascript']
DEFAULT_LANGUAGE = 'python'

# 注意: これらのリストは完全ではなく、言語バージョンの更新に伴いメンテナンスが必要です。
NODE_BUILTIN_MODULES = set([
    'assert', 'async_hooks', 'buffer', 'child_process', 'cluster', 'console',
    'constants', 'crypto', 'dgram', 'diagnostics_channel', 'dns', 'domain',
    'events', 'fs', 'http', 'http2', 'https', 'inspector', 'module', 'net',
    'os', 'path', 'perf_hooks', 'process', 'punycode', 'querystring',
    'readline', 'repl', 'stream', 'string_decoder', 'sys', 'timers', 'tls',
    'trace_events', 'tty', 'url', 'util', 'v8', 'vm', 'wasi', 'worker_threads',
    'zlib'
])
# Python標準ライブラリモジュールのリスト (主要なもの、網羅的ではない可能性あり)
# `sys.stdlib_module_names` (Python 3.10+) や `is_stdlib` (サードパーティライブラリ) の利用も検討可
PYTHON_STDLIB_MODULES = set(sys.stdlib_module_names if sys.version_info >= (3, 10) else [
    'abc', 'argparse', 'ast', 'asyncio', 'base64', 'collections', 'concurrent',
    'contextlib', 'copy', 'csv', 'datetime', 'decimal', 'difflib', 'email', 'enum',
    'functools', 'glob', 'gzip', 'hashlib', 'heapq', 'http', 'importlib', 'io',
    'itertools', 'json', 'logging', 'math', 'multiprocessing', 'operator', 'os',
    'pathlib', 'pickle', 'platform', 'pprint', 'queue', 'random', 're',
    'sched', 'secrets', 'select', 'shlex', 'shutil', 'signal', 'socket',
    'socketserver', 'sqlite3', 'ssl', 'statistics', 'string', 'struct',
    'subprocess', 'sys', 'tarfile', 'tempfile', 'textwrap', 'threading',
    'time', 'timeit', 'tkinter', 'traceback', 'types', 'typing', 'unittest',
    'urllib', 'uuid', 'warnings', 'weakref', 'webbrowser', 'xml', 'zipfile',
    'zlib'
])


POPULAR_PACKAGES = {
    'python': ['requests', 'numpy', 'pandas', 'flask', 'django', 'pytest', 'matplotlib',
               'tensorflow', 'torch', 'scikit-learn', 'pillow', 'scipy', 'beautifulsoup4',
               'sqlalchemy', 'fastapi', 'seaborn', 'boto3', 'opencv-python', 'cryptography',
               'PyYAML', 'python-dotenv', 'psycopg2-binary', 'redis'],
    'javascript': ['react', 'vue', 'angular', 'express', 'lodash', 'axios', 'moment',
                  'jquery', 'redux', 'webpack', 'typescript', 'next', 'jest', 'babel',
                  'eslint', 'node-fetch', 'styled-components', 'tailwindcss', 'async',
                  'debug', 'commander', 'chalk', 'uuid', 'ws', 'socket.io']
}

# 既知の悪意のあるパッケージやタイポスクワッティングの懸念があるパッケージの例
# これはごく一部の例であり、実際の脅威インテリジェンスソースから定期的に更新する必要があります。
SUSPICIOUS_PACKAGES = {
    'python': {
        'reqeusts': 'requests',
        'djanga': 'django',
        'python-dateutil1': 'python-dateutil',
        'beatifulsoup': 'beautifulsoup4',
        'colourama': 'colorama', # 実際の例
        'install-package': None, # 架空の悪意のある例
        'python-mongo': 'pymongo',
        'scikit-learn-real': 'scikit-learn', # typosquatting
        'tensorflou': 'tensorflow',
    },
    'javascript': {
        'loadash': 'lodash',
        'jquery.js': 'jquery', # 誤解を招く名前
        'crossenv': 'cross-env',
        'expressjs': 'express',
        'node-static-web': 'node-static', # typosquatting
        'webpack-cli-v4': 'webpack-cli',
        'event-stream-latest': 'event-stream', # 過去のインシデント
    }
}

# --- Utility Functions ---
def safe_run(command: List[str], cwd: Optional[str] = None) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    コマンドを安全に実行し、そのJSON出力またはエラーメッセージを返します。
    """
    try:
        logger.debug(f"Running command: {' '.join(command)} in {cwd or '.'}")
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            cwd=cwd,
            check=False,
            timeout=30  # サブプロセスのタイムアウト
        )
        if result.returncode == 0:
            if not result.stdout.strip(): # 空の標準出力はJSONデコードエラーになるため
                return {}, None
            try:
                return json.loads(result.stdout), None
            except json.JSONDecodeError as e:
                # npm list --json などで末尾に余計な情報が含まれる場合があるため、主要なJSON部分を抽出試行
                try:
                    # 最初の '{' から最後の '}' までを抽出
                    json_like_part = result.stdout[result.stdout.find('{'):result.stdout.rfind('}')+1]
                    if json_like_part:
                        return json.loads(json_like_part), None
                except json.JSONDecodeError:
                    pass # 抽出してもダメなら諦める
                return None, f"JSONデコードエラー: {e}, stdout (最初の100文字): {result.stdout[:100]}..."
        return None, f"コマンドエラー (code {result.returncode}): {result.stderr.strip()}"
    except FileNotFoundError:
        return None, f"コマンドが見つかりません: {command[0]}"
    except subprocess.TimeoutExpired:
        return None, f"コマンドがタイムアウトしました: {' '.join(command)}"
    except Exception as e:
        return None, f"コマンド実行中に予期しないエラーが発生しました ('{' '.join(command)}'): {e}"

@lru_cache(maxsize=256) # キャッシュサイズを増加
def get_installed_python_version(module_name: str) -> Optional[str]:
    """
    インストールされているPythonモジュールのバージョンを取得します。
    """
    try:
        return importlib.metadata.version(module_name)
    except importlib.metadata.PackageNotFoundError:
        return None
    except Exception as e: # より広範なエラーをキャッチ
        logger.debug(f"{module_name} のバージョン取得中にエラー: {e}")
        return None

@lru_cache(maxsize=256) # キャッシュサイズを増加
def get_public_versions(package_name: str, language: str) -> List[str]:
    """
    公開リポジトリからパッケージの利用可能なバージョンリストを取得します。
    """
    versions: List[str] = []
    retries = Config.REQUEST_RETRIES
    backoff_factor = Config.REQUEST_BACKOFF

    url = ""
    key_to_extract = ""

    if language == 'python':
        url = Config.PYPI_API_URL.format(package=package_name)
        key_to_extract = 'releases'
    elif language == 'javascript':
        url = Config.NPM_API_URL.format(package=package_name)
        key_to_extract = 'versions'
    else:
        logger.error(f"サポートされていない言語です: {language}")
        return []

    for attempt in range(retries):
        try:
            logger.debug(f"パッケージ情報をリクエスト中 ({attempt + 1}/{retries}): {url}")
            response = requests.get(url, timeout=Config.REQUEST_TIMEOUT)
            response.raise_for_status()  # 4xx/5xxエラーで例外を発生
            data = response.json()
            if key_to_extract in data and isinstance(data[key_to_extract], dict):
                return list(data[key_to_extract].keys())
            logger.warning(f"{package_name} のバージョン情報が期待する形式ではありませんでした。Key: '{key_to_extract}'")
            return [] # データ形式が不正なら空リストを返す

        except Timeout:
            logger.warning(f"{package_name} のバージョンリクエストがタイムアウトしました。")
        except ConnectionError:
            logger.warning(f"{package_name} で接続エラーが発生しました。ネットワーク接続を確認してください。")
        except RequestException as e:
            if e.response is not None and e.response.status_code == 404:
                logger.info(f"パッケージ {package_name} ({language}) がレジストリに見つかりません。")
                return [] # 404の場合はリトライ不要
            logger.warning(f"{package_name} でリクエストエラー: {e}")
        except json.JSONDecodeError:
            logger.warning(f"{package_name} のAPIレスポンスがJSONとしてデコードできませんでした。")
        except Exception as e: # その他の予期しないエラー
            logger.error(f"{package_name} のバージョンフェッチ中に予期しないエラー: {e}")
            return [] # 予期しないエラーの場合はリトライしない

        if attempt < retries - 1:
            sleep_time = backoff_factor ** attempt
            logger.info(f"{sleep_time:.1f}秒待機してリトライします...")
            time.sleep(sleep_time)
        else:
            logger.error(f"{package_name} のバージョン取得に失敗しました（リトライ上限到達）。")

    return versions # すべてのリトライが失敗した場合

def is_version_unusual(installed_version_str: str, public_versions_str: List[str]) -> bool:
    """
    インストールされているバージョンが、公開されているバージョンと比較して異常に高いかどうかをチェックします。
    """
    if not installed_version_str or not public_versions_str:
        return False

    try:
        installed_v = parse_version(installed_version_str)
        public_versions = [parse_version(v_str) for v_str in public_versions_str if isinstance(v_str, str)] # 文字列のみをパース

        if not public_versions: # 有効な公開バージョンがない場合
             return False

        # pre-releaseではない最新の公開バージョンを見つける
        stable_public_versions = [v for v in public_versions if not v.is_prerelease]

        if stable_public_versions:
            max_public_v = max(stable_public_versions)
        elif public_versions: # pre-releaseしかない場合
            max_public_v = max(public_versions)
        else: # 有効なバージョンが一つもなければ比較不可
            return False

        return installed_v > max_public_v
    except InvalidVersion as e:
        logger.debug(f"不正なバージョン文字列のため比較できませんでした: {e}")
        return False
    except Exception as e:
        logger.debug(f"バージョン比較中にエラーが発生しました: {e}")
        return False


def find_similar_name(name: str, language: str) -> Optional[Tuple[str, float]]:
    """
    タイポを検出するために、類似したパッケージ名を検索します。
    """
    # 既知のタイポスクワッティングパッケージをチェック
    lang_suspicious = SUSPICIOUS_PACKAGES.get(language, {})
    if name.lower() in lang_suspicious: # case-insensitive check
        correct_name = lang_suspicious[name.lower()]
        if correct_name is None: # 悪意のあるパッケージとしてマークされている場合
            return (f"{name} (既知の疑わしいパッケージ)", 1.0)
        return (correct_name, 1.0)

    # 一般的なパッケージとの類似性をチェック
    best_match: Optional[str] = None
    # 類似度の閾値を少し下げることで、より多くの候補を拾えるようにするが、誤検知も増える可能性
    best_score = 0.75 # 以前は0.8

    # 検索対象のリストを正規化 (小文字化)
    candidates = [candidate.lower() for candidate in POPULAR_PACKAGES.get(language, [])]
    name_lower = name.lower()

    for candidate in candidates:
        score = difflib.SequenceMatcher(None, name_lower, candidate).ratio()
        if score > best_score:
            # 元のケースのパッケージ名を返すために、POPULAR_PACKAGESから再検索
            original_candidate = next((c for c in POPULAR_PACKAGES.get(language, []) if c.lower() == candidate), candidate)
            best_match, best_score = original_candidate, score

    return (best_match, best_score) if best_match else None

@lru_cache(maxsize=128)
def check_security_vulnerabilities(package_name: str, version_str: str, language: str) -> List[Dict[str, Any]]:
    """
    パッケージの既知のセキュリティ脆弱性をチェックします。(シミュレーションと今後の拡張のためのコメント)

    現実的な脆弱性チェックの実装は複雑であり、主に以下のいずれかのアプローチが必要です:
    1. 外部の脆弱性データベースAPIへのリアルタイムクエリ:
       - `requests` などを使用して、OSV (Open Source Vulnerability format) などの標準形式で
         情報を提供するAPI (例: OSV.dev API, GitHub Advisory Database API, npm audit API) に問い合わせる。
       - APIキーの管理、レート制限への対応、ネットワーク遅延の考慮が必要。
    2. ローカル脆弱性データベーススナップショットの利用:
       - PyPA Advisory Database (https://github.com/pypa/advisory-database) や
         Node.js Security WG (https://github.com/nodejs/security-wg/tree/main/vuln/npm) などの
         リポジトリから脆弱性情報 (通常OSV形式のJSONファイル群) を定期的にダウンロードし、ローカルに保持。
       - このスクリプトは、ローカルのファイルシステムから該当パッケージの脆弱性情報を読み込み、
         指定されたバージョンが影響を受けるかどうかを判定する。
       - データベースの鮮度を保つための更新メカニズムが必要。
    3. 既存のセキュリティスキャンツールの利用:
       - `pip-audit`, `safety` (Python), `npm audit`, `yarn audit` (JavaScript) などの
         専用ツールをサブプロセスとして呼び出し、その結果を解析する。
       - これらのツールは上記1または2のアプローチを内部で採用していることが多い。
       - ツールがインストールされている必要がある。

    この関数は現在、**ごく基本的なシミュレーションのみ**を行っています。
    Configクラスの `PYPA_ADVISORY_DB_URL_BASE` や `NODEJS_ADVISORY_DB_URL_BASE` は、
    アプローチ2のようなローカルスナップショットや、特定の構造を持つAPIエンドポイントを想定したものです。
    実際のファイル名やパスの構造は、使用するデータベースに依存します。

    例 (OSV形式のファイルをローカルで検索する場合の擬似コード):
    if language == 'python':
        db_path = os.path.join(Config.PYPA_ADVISORY_DB_LOCAL_PATH, package_name, f"{package_name}.json")
        # または OSV ID がファイル名になっている場合など、データベースの構造に合わせる
    elif language == 'javascript':
        db_path = os.path.join(Config.NODEJS_ADVISORY_DB_LOCAL_PATH, package_name + ".json") # or other format

    try:
        with open(db_path, 'r') as f:
            osv_data = json.load(f)
        # osv_data を解析し、'affected' フィールド内のバージョン範囲と version_str を比較
        # 詳細は OSV 仕様 (https://ossf.github.io/osv-schema/) を参照
    except FileNotFoundError:
        # 脆弱性情報なし
        pass
    except Exception as e:
        logger.error(f"脆弱性情報 ({package_name}) の解析エラー: {e}")
    """
    if not version_str or version_str == 'N/A':
        return []

    vulnerabilities: List[Dict[str, Any]] = []

    try:
        installed_v = parse_version(version_str)

        # --- 以下はシミュレーションの脆弱性チェックロジックです ---
        # 実際のシステムでは、上記コメントにあるようなデータベース連携が必要です。

        # シミュレーション: 一般的な問題のあるバージョンのパターン (例のみ)
        if installed_v < parse_version("1.0.0"):
            vulnerabilities.append({
                'id': 'SIMULATED-OLD-VERSION',
                'severity': 'LOW', # 深刻度を追加 (例: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN)
                'description': f'バージョン {version_str} は非常に古いです。安定性の問題や未発見の脆弱性がある可能性があります。1.0.0以上へのアップグレードを検討してください。',
                'affected_versions': ['<1.0.0'],
                'fixed_versions': ['>=1.0.0']
            })

        # シミュレーション: 特定のパッケージとバージョンの脆弱性 (例)
        if language == 'python':
            if package_name == 'requests' and installed_v < parse_version('2.25.0'): # 脆弱性バージョン例を少し更新
                vulnerabilities.append({
                    'id': 'CVE-2023-XXXX', # ダミーのCVE ID
                    'severity': 'HIGH',
                    'description': 'requests < 2.25.0 には、特定の状況下でのリダイレクト処理に関する脆弱性 (シミュレーション) が存在する可能性があります。2.25.0以上にアップグレードしてください。',
                    'affected_versions': ['<2.25.0'],
                    'fixed_versions': ['>=2.25.0']
                })
            elif package_name == 'django' and installed_v < parse_version('3.2.10'): # 脆弱性バージョン例を少し更新
                vulnerabilities.append({
                    'id': 'CVE-2023-YYYY', # ダミーのCVE ID
                    'severity': 'CRITICAL',
                    'description': '古いDjangoバージョン (例: < 3.2.10) には複数の既知のセキュリティ脆弱性が存在する可能性があります (シミュレーション)。最新のパッチバージョンにアップグレードしてください。',
                    'affected_versions': ['<3.2.10'],
                    'fixed_versions': ['>=3.2.10']
                })
        elif language == 'javascript':
            if package_name == 'lodash' and installed_v < parse_version('4.17.21'):
                vulnerabilities.append({
                    'id': 'CVE-2021-ZZZZ', # ダミーのCVE ID
                    'severity': 'HIGH',
                    'description': 'lodash < 4.17.21 にはプロトタイプ汚染の脆弱性が存在する可能性があります (シミュレーション)。4.17.21以上にアップグレードしてください。',
                    'affected_versions': ['<4.17.21'],
                    'fixed_versions': ['>=4.17.21']
                })
            elif package_name == 'axios' and installed_v < parse_version('0.21.2'): # 脆弱性バージョン例を少し更新
                vulnerabilities.append({
                    'id': 'CVE-2020-AAAA', # ダミーのCVE ID
                    'severity': 'MEDIUM',
                    'description': 'axios < 0.21.2 にはSSRF (Server-Side Request Forgery) の脆弱性が存在する可能性があります (シミュレーション)。0.21.2以上にアップグレードしてください。',
                    'affected_versions': ['<0.21.2'],
                    'fixed_versions': ['>=0.21.2']
                })

    except InvalidVersion:
        logger.debug(f"{package_name} のバージョン '{version_str}' は不正な形式です。セキュリティチェックをスキップします。")
    except Exception as e:
        logger.debug(f"{package_name} のセキュリティチェック中に予期しないエラー: {e}")

    return vulnerabilities


def detect_language_from_filename(filename: str) -> Optional[str]:
    """
    ファイルの拡張子からプログラミング言語を検出します。
    """
    extension_map = {
        '.py': 'python',
        '.js': 'javascript',
        '.jsx': 'javascript', # React
        '.ts': 'javascript', # TypeScript (トランスパイル後はJavaScriptとして扱われることが多い)
        '.tsx': 'javascript'  # TypeScript with React
    }
    _, ext = os.path.splitext(filename)
    return extension_map.get(ext.lower())

def detect_language_from_content(content: str) -> Optional[str]:
    """
    ファイルの内容からプログラミング言語を検出します (簡易的なヒューリスティック)。
    """
    # Python特有のキーワードや構文の出現頻度
    python_indicators = ['import ', 'from ', 'def ', 'class ', 'elif ', 'async def', 'yield ', 'print(']
    # JavaScript特有のキーワードや構文の出現頻度
    js_indicators = ['import ', 'require(', 'export ', 'const ', 'let ', 'var ', 'function*', '=>', 'async function', 'document.', 'window.']

    python_score = sum(indicator in content for indicator in python_indicators)
    # 'from ' はPythonでもJSでも使われるので、Pythonのスコアへの寄与を少し下げるか、JSのスコアを上げる
    python_score += content.count("if __name__ == \"__main__\":") * 3 # Python特有のイディオム

    js_score = sum(indicator in content for indicator in js_indicators)
    js_score += content.count("module.exports") * 2 # CommonJS
    js_score += content.count("console.log") # JSで非常に一般的

    # より多くの指標、重み付け、コメントや文字列リテラルの除外などを考慮すると精度が向上する
    if python_score > js_score:
        return 'python'
    if js_score > python_score:
        return 'javascript'
    if "python" in content.lower() and "javascript" not in content.lower(): # shebang やコメントなど
        return 'python'
    if "javascript" in content.lower() and "python" not in content.lower():
        return 'javascript'

    logger.debug("ファイル内容からの言語検出が困難でした。")
    return None

# --- Checkers ---
class DependencyChecker:
    """
    コードファイル内の依存関係を分析するためのメインクラス。
    """

    def __init__(self, language: str, base_dir: str):
        """
        依存関係チェッカーを初期化します。
        """
        if language not in SUPPORTED_LANGUAGES:
            raise ValueError(f"サポートされていない言語です: {language}")
        self.language = language
        self.base_dir = base_dir # プロジェクトのルートディレクトリを期待

    def check(self, code: str, filename: Optional[str] = None) -> Dict[str, Dict]:
        """
        指定されたコード内の依存関係をチェックします。
        """
        if self.language == 'python':
            return self._check_python(code, filename)
        elif self.language == 'javascript':
            return self._check_javascript(code, filename)
        return {} # 到達不能のはず

    def _check_python(self, code: str, filename: Optional[str] = None) -> Dict[str, Dict]:
        """
        AST解析を使用してPythonの依存関係をチェックします。
        ネストされたインポートも検出するように修正。相対インポートはスキップ。
        """
        try:
            tree = ast.parse(code, filename=filename or "<unknown>")
        except SyntaxError as e:
            logger.error(f"Python構文エラー ({filename or 'code string'}): {e}")
            return {'error': f"構文エラー: {e}"}
        except Exception as e:
            logger.error(f"Pythonコードの解析中にエラー ({filename or 'code string'}): {e}")
            return {'error': f"Pythonコード解析エラー: {e}"}

        imports_info: Dict[str, Dict[str, Union[str, int, bool, List[Any], None]]] = {}

        for node in ast.walk(tree): # ast.iter_child_nodes から ast.walk に変更
            module_name: Optional[str] = None
            line_no: int = node.lineno

            if isinstance(node, ast.Import):
                if node.names:
                    # 例: import requests, numpy -> 'requests' と 'numpy' を取得
                    module_name = node.names[0].name.split('.')[0]
                    # 複数モジュールが一行に書かれている場合 (import os, sys)
                    # ast.Import は一つだが node.names に複数エイリアスが含まれる
                    for alias in node.names:
                        mod_root = alias.name.split('.')[0]
                        self._process_python_module(mod_root, line_no, imports_info)

            elif isinstance(node, ast.ImportFrom):
                if node.level > 0: # 相対インポート (from . import foo, from ..bar import baz)
                    logger.debug(f"相対インポートをスキップ: from {''.join('.' * node.level)}{node.module or ''} (line {line_no})")
                    continue # スキップ

                if node.module:
                    # 例: from django.http import HttpResponse -> 'django' を取得
                    module_name = node.module.split('.')[0]
                    if module_name:
                         self._process_python_module(module_name, line_no, imports_info)
                # else: from . import X のようなケース、既にlevel>0でハンドル

        return imports_info

    def _process_python_module(self, module_name: str, line_no: int, imports_info: Dict[str, Any]):
        """Pythonモジュール情報を処理して imports_info に追加するヘルパー"""
        if module_name in PYTHON_STDLIB_MODULES or module_name in sys.builtin_module_names:
            logger.debug(f"標準ライブラリモジュールをスキップ: {module_name}")
            return
        if module_name in imports_info: # 既に処理済みなら行番号だけ更新 (より早い出現箇所)
            imports_info[module_name]['line'] = min(imports_info[module_name]['line'], line_no)
            return

        version = get_installed_python_version(module_name)
        public_versions = get_public_versions(module_name, 'python')
        similar_match = find_similar_name(module_name, 'python')
        vulnerabilities = check_security_vulnerabilities(module_name, version, 'python') if version else []

        imports_info[module_name] = {
            'installed': version is not None,
            'version': version or 'N/A',
            'line': line_no,
            'unusual_version': is_version_unusual(version, public_versions) if version else False,
            'similar_package': similar_match,
            'vulnerabilities': vulnerabilities
        }

    def _check_javascript(self, code: str, filename: Optional[str] = None) -> Dict[str, Dict]:
        """
        regexを使用してJavaScriptの依存関係をチェックします。
        注意: この方法は複雑なJavaScriptコード (動的インポート、条件付きインポートなど) では
        不完全である可能性があります。より堅牢な解析のためには、Acorn, Esprima, or Babel
        などのJavaScriptパーサーライブラリの使用を検討してください。
        """
        # ES6 imports: import ... from 'package'; import 'package';
        # CommonJS requires: require('package');
        # Dynamic imports: import('package');
        # Regexは完璧ではないが、一般的なケースをカバー
        # スコープ付きパッケージ (@scope/package) も考慮
        patterns = [
            r"import\s+(?:(?:\w+\s*,\s*)?\{[^}]*\}|\w+|\*\s+as\s+\w+)?\s+from\s+['\"]((?:@[\w.-]+[\/])?[\w.-]+)['\"]", # import x from 'pkg'
            r"import\s+['\"]((?:@[\w.-]+[\/])?[\w.-]+)['\"]", # import 'pkg'
            r"(?:const|let|var)\s+\w+\s*=\s*require\s*\(\s*['\"]((?:@[\w.-]+[\/])?[\w.-]+)['\"]\s*\)", # const x = require('pkg')
            r"require\s*\(\s*['\"]((?:@[\w.-]+[\/])?[\w.-]+)['\"]\s*\)", # require('pkg')
            r"import\s*\(\s*['\"]((?:@[\w.-]+[\/])?[\w.-]+)['\"]\s*\)", # import('pkg')
        ]
        
        found_modules: Set[str] = set()
        for pattern in patterns:
            try:
                matches = re.findall(pattern, code)
                for match_group in matches:
                    # match_group がタプルか文字列かで処理を分ける
                    # (パターンが複数のキャプチャグループを持つ可能性があるが、このケースでは最初のものを使う)
                    mod = match_group if isinstance(match_group, str) else match_group[0]
                    if mod and not mod.startswith('.') and not os.path.isabs(mod) and mod not in NODE_BUILTIN_MODULES:
                        found_modules.add(mod)
            except re.error as e:
                logger.error(f"JavaScript依存関係解析中の正規表現エラー ({filename or 'code string'}): {e}")


        results: Dict[str, Dict[str, Any]] = {}
        if not found_modules:
            return results

        # package.json や lock ファイルからインストール済みバージョンを取得
        # この部分はプロジェクト全体のコンテキストが必要
        installed_deps = self._get_js_installed_dependencies()

        for module_name in found_modules:
            installed_info = installed_deps.get(module_name, {})
            version = installed_info.get('version', 'N/A')

            public_versions = get_public_versions(module_name, 'javascript')
            similar_match = find_similar_name(module_name, 'javascript')
            vulnerabilities = check_security_vulnerabilities(module_name, version, 'javascript') if version != 'N/A' else []

            results[module_name] = {
                'installed': version != 'N/A',
                'version': version,
                # 'line': N/A for regex based JS, could be added with more sophisticated parsing
                'unusual_version': is_version_unusual(version, public_versions) if version != 'N/A' else False,
                'similar_package': similar_match,
                'vulnerabilities': vulnerabilities
            }
        return results

    @lru_cache(maxsize=1) # プロジェクトごとに一度だけ実行されることを想定
    def _get_js_installed_dependencies(self) -> Dict[str, Dict[str, str]]:
        """
        JavaScriptプロジェクトのインストール済み依存関係のバージョンを取得します。
        npm, yarn, pnpm の順でチェックし、package.json をフォールバックとします。
        """
        package_manager_commands = {
            'pnpm': (os.path.join(self.base_dir, 'pnpm-lock.yaml'), ['pnpm', 'list', '--depth=0', '--json', '--prod']), # --prod で devDependencies を除く場合
            'yarn': (os.path.join(self.base_dir, 'yarn.lock'), ['yarn', 'list', '--depth=0', '--json', '--no-progress']),
            'npm': (os.path.join(self.base_dir, 'package-lock.json'), ['npm', 'list', '--depth=0', '--json', '--omit=dev']) # npm v7+
        }
        # npm旧バージョンのためのコマンド (npm ls --json --depth=0) も考慮に入れるか、バージョンで分岐
        # ここでは簡単のため npm v7+ を想定

        installed_data: Optional[Dict[str, Any]] = None
        error_msg: Optional[str] = None

        for pm, (lockfile, cmd) in package_manager_commands.items():
            if os.path.exists(lockfile):
                logger.info(f"{pm} のロックファイル ({lockfile}) を検出しました。依存関係情報を取得します...")
                installed_data, error_msg = safe_run(cmd, cwd=self.base_dir)
                if installed_data is not None and not error_msg: # installed_data が空辞書の場合も成功とみなす
                    logger.info(f"{pm} から依存関係情報を取得しました。")
                    break
                else:
                    logger.warning(f"{pm} での依存関係情報取得に失敗しました: {error_msg}")
                    installed_data = None # エラーの場合はクリア
            else:
                logger.debug(f"{pm} のロックファイル ({lockfile}) が見つかりません。")


        dependencies: Dict[str, Dict[str, str]] = {}
        if installed_data and 'dependencies' in installed_data:
            # `npm list --json` や `yarn list --json` の出力形式は異なる場合があるため、
            # より堅牢なパースが必要。以下は npm list --json の一般的な形式を想定。
            raw_deps = installed_data.get('dependencies', {})
            for name, info in raw_deps.items():
                if isinstance(info, dict) and 'version' in info:
                    dependencies[name] = {'version': str(info['version'])}
        elif error_msg or installed_data is None : # コマンド実行に失敗した場合、またはデータがない場合
            logger.warning("パッケージマネージャからの依存関係情報取得に失敗したため、package.json にフォールバックします。")
            package_json_path = os.path.join(self.base_dir, 'package.json')
            if os.path.exists(package_json_path):
                try:
                    with open(package_json_path, 'r', encoding='utf-8') as f:
                        package_json_content = json.load(f)
                    # dependencies と devDependencies の両方を見るか選択
                    for dep_type in ['dependencies', 'devDependencies', 'peerDependencies']:
                        if dep_type in package_json_content:
                            for name, version_specifier in package_json_content[dep_type].items():
                                if name not in dependencies: # 上書きしない
                                    # version_specifier は "^1.0.0" や "~2.3.4" のような範囲指定なので、
                                    # これを実際のバージョンに解決するロジックが必要だが、ここではそのまま格納。
                                    # 正確なバージョン解決には `semver` ライブラリなどが必要。
                                    dependencies[name] = {'version': str(version_specifier)}
                    logger.info(f"{package_json_path} から依存関係情報を読み込みました (バージョンは範囲指定の可能性あり)。")
                except Exception as e:
                    logger.error(f"{package_json_path} の解析に失敗しました: {e}")
            else:
                logger.warning(f"{package_json_path} が見つかりません。JavaScriptのインストール済みバージョン情報を取得できません。")
        return dependencies


    def check_file(self, file_path: str) -> Dict[str, Dict]:
        """
        ファイル内の依存関係をチェックします。
        """
        logger.info(f"ファイルをチェック中: {file_path} (言語: {self.language})")
        try:
            # エンコーディングエラーを無視するオプションを追加 (ただし、根本解決ではない)
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            return self.check(code, filename=os.path.basename(file_path))
        except FileNotFoundError:
            logger.error(f"ファイルが見つかりません: {file_path}")
            return {'error': f"ファイルが見つかりません: {file_path}"}
        except UnicodeDecodeError as e:
            logger.error(f"ファイルのデコードに失敗しました ({file_path}): {e}。UTF-8エンコーディングで再試行してください。")
            # 他のエンコーディングで試すことも可能だが、複雑になるためここではエラーとする
            return {'error': f"ファイルデコードエラー: {e}"}
        except Exception as e:
            logger.error(f"ファイル処理中にエラーが発生しました ({file_path}): {e}")
            return {'error': f"ファイル処理エラー: {e}"}

    def get_installation_command(self, module: str, language: str) -> str:
        """
        不足しているパッケージのインストールコマンドを生成します。
        """
        if language == 'python':
            return f"pip install {module}"
        elif language == 'javascript':
            # プロジェクトのパッケージマネージャを推定
            if os.path.exists(os.path.join(self.base_dir, 'pnpm-lock.yaml')):
                return f"pnpm add {module}"
            if os.path.exists(os.path.join(self.base_dir, 'yarn.lock')):
                return f"yarn add {module}"
            # デフォルトは npm
            return f"npm install {module}"
        return f"不明な言語 ({language}) のためインストールコマンドを生成できません。"

# --- CLI Interface ---
def main():
    """コマンドラインインターフェースのエントリーポイント。"""
    parser = argparse.ArgumentParser(
        description="PythonおよびJavaScriptプロジェクトの依存関係チェッカー。\n"
                    "依存関係のバージョン、潜在的なタイプミス、既知の脆弱性(シミュレーション)を報告します。",
        formatter_class=argparse.RawTextHelpFormatter, # 改行を保持
        epilog="""
使用例:
  単一ファイルをチェック:
    python check_dependencies.py -f app.py
    python check_dependencies.py --file ./src/main.js --language javascript

  ディレクトリ内の全サポートファイルをチェック (プロジェクトルートを指定推奨):
    python check_dependencies.py -d ./my_project

  JSON形式で出力:
    python check_dependencies.py -f app.py --json

  詳細ログ出力:
    python check_dependencies.py -f app.py -v

注意: JavaScriptの依存関係バージョンチェックは、プロジェクトのルートディレクトリで
      実行するか、-dオプションでプロジェクトルートを指定した方が正確です。
"""
    )
    parser.add_argument('-f', '--file', help='解析する単一ファイルへのパス。')
    parser.add_argument('-d', '--directory', help='解析するディレクトリ。サポートされている全ファイルを再帰的に検索します。\n'
                                               'JavaScriptプロジェクトの場合、正確なバージョン情報を得るために、プロジェクトのルートディレクトリを指定することを推奨します。')
    parser.add_argument('-l', '--language', choices=SUPPORTED_LANGUAGES,
                        help='プログラミング言語を明示的に指定します。\n'
                             '指定しない場合はファイル拡張子や内容から自動判別を試みます。')
    parser.add_argument('--json', action='store_true', help='結果をJSON形式で出力します。')
    parser.add_argument('-v', '--verbose', action='store_true', help='デバッグレベルの詳細ログを有効にします。')
    # --security-check オプションは削除 (常に実行、ただしシミュレーションである旨を明記)

    args = parser.parse_args()

    if args.verbose:
        logger.parent.setLevel(logging.DEBUG) # ルートロガーのレベルを変更
        for handler in logger.parent.handlers: # ハンドラにも設定
            handler.setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)
        logger.info("詳細ログモードが有効になりました。")


    if not args.file and not args.directory:
        parser.print_help()
        sys.exit(1)

    base_path_for_js = "." # デフォルトはカレントディレクトリ
    if args.directory:
        if not os.path.isdir(args.directory):
            print(f"エラー: ディレクトリが見つかりません: {args.directory}", file=sys.stderr)
            sys.exit(1)
        base_path_for_js = os.path.abspath(args.directory)
        process_directory(args, base_path_for_js)
    elif args.file:
        if not os.path.isfile(args.file):
            print(f"エラー: ファイルが見つかりません: {args.file}", file=sys.stderr)
            sys.exit(1)
        # 単一ファイルの場合、そのファイルのディレクトリをJSのベースパスとするか、
        # カレントディレクトリをベースパスとするか選択が必要。
        # ここではカレントディレクトリ、または別途 --project-root のようなオプションを設けるのが良い。
        # 今回は、JSの場合は -d を推奨する旨をヘルプに記載。
        # 単一ファイル指定時のJSのbase_dirは、そのファイルが存在するディレクトリとする。
        base_path_for_js = os.path.dirname(os.path.abspath(args.file)) or "."
        process_single_file(args, base_path_for_js)


def display_results(results_map: Dict[str, Dict[str, Any]], args: argparse.Namespace, language_map: Dict[str,str] = {}):
    """整形された結果を表示、またはJSONで出力する。"""
    if args.json:
        # JSON出力用に少し整形 (Setなどをリストに変換)
        # この例では特にSetはないが、将来的に追加された場合のため
        def json_serializable(obj):
            if isinstance(obj, Set):
                return list(obj)
            if isinstance(obj, tuple) and hasattr(obj, '_asdict'): # namedtuple
                return obj._asdict()
            try:
                return obj.__dict__
            except AttributeError:
                try:
                    # for things like packaging.version.Version
                    return str(obj)
                except:
                    raise TypeError(f"Type not serializable: {type(obj)}")

        print(json.dumps(results_map, indent=2, default=json_serializable))
        return

    summary = {
        "total_files": len(results_map),
        "total_dependencies": 0,
        "missing_dependencies": 0,
        "vulnerable_dependencies": 0,
        "typosquatting_suggestions": 0,
        "unusual_versions": 0
    }

    severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0}
    severity_icons = {
        'CRITICAL': '[C]',
        'HIGH':   '[H]',
        'MEDIUM': '[M]',
        'LOW':    '[L]',
        'INFO':   '[I]', # シミュレーションで追加した INFO レベルなど
        'UNKNOWN':'[?]'
    }

    for file_path, dependencies in results_map.items():
        if not dependencies or 'error' in dependencies:
            status_msg = f"エラー: {dependencies.get('error', '不明なエラー')}" if 'error' in dependencies else "依存関係は見つかりませんでした。"
            print(f"\n--- {os.path.basename(file_path)} ({language_map.get(file_path, 'N/A')}) ---")
            print(status_msg)
            continue

        print(f"\n--- {os.path.basename(file_path)} ({language_map.get(file_path, 'N/A')}) の依存関係チェック結果 ---")
        summary["total_dependencies"] += len(dependencies)

        sorted_deps = sorted(dependencies.items())

        for dep_name, info in sorted_deps:
            version_str = f"v{info['version']}" if info['version'] != 'N/A' else "バージョン不明"
            status = "インストール済み" if info['installed'] else "未検出/未インストール"
            line_info = f"(L{info['line']})" if 'line' in info and info['line'] else ""

            print(f"\n  {dep_name} {line_info}")
            print(f"    ステータス: {status}, {version_str}")

            if not info['installed']:
                summary["missing_dependencies"] += 1
                install_cmd = DependencyChecker(language_map.get(file_path, DEFAULT_LANGUAGE), os.path.dirname(file_path)).get_installation_command(dep_name, language_map.get(file_path, DEFAULT_LANGUAGE))
                print(f"    提案: {install_cmd}")

            if info.get('unusual_version'):
                summary["unusual_versions"] += 1
                print(f"    警告: インストールバージョン ({info['version']}) は公開されている最新安定版より新しい可能性があります。")
                print(f"          (開発版、プライベートビルド、または悪意のあるパッケージの可能性)")

            if info.get('similar_package'):
                summary["typosquatting_suggestions"] += 1
                similar_name, score = info['similar_package']
                print(f"    提案 (タイポ?): もしかして -> {similar_name} (類似度: {score:.2f})")

            if info.get('vulnerabilities'):
                summary["vulnerable_dependencies"] +=1
                print("    脆弱性 (シミュレーション):")
                # 深刻度でソートして表示
                sorted_vulns = sorted(info['vulnerabilities'], key=lambda v: severity_order.get(v.get('severity', 'UNKNOWN').upper(), 0), reverse=True)
                for vuln in sorted_vulns:
                    severity = vuln.get('severity', 'UNKNOWN').upper()
                    icon = severity_icons.get(severity, '[?]')
                    vuln_id = f"({vuln.get('id', 'N/A')}) " if vuln.get('id') else ""
                    print(f"      {icon} {severity}: {vuln_id}{vuln['description']}")
                    if 'affected_versions' in vuln:
                        print(f"        影響バージョン: {vuln['affected_versions']}")
                    if 'fixed_versions' in vuln:
                        print(f"        修正済みバージョン: {vuln['fixed_versions']}")
        print("-" * 40)

    print("\n--- 全体サマリー ---")
    print(f"スキャンファイル数: {summary['total_files']}")
    print(f"総依存関係数: {summary['total_dependencies']}")
    print(f"未検出/未インストール: {summary['missing_dependencies']}")
    print(f"脆弱性のある依存関係 (シミュレーション): {summary['vulnerable_dependencies']}")
    print(f"タイポスクワッティングの可能性: {summary['typosquatting_suggestions']}")
    print(f"異常なバージョンの可能性: {summary['unusual_versions']}")
    print("---")
    if summary['vulnerable_dependencies'] > 0:
        print("\n注意: 脆弱性情報はシミュレーションです。実際の判断には専用のセキュリティスキャンツールをご利用ください。")


def process_single_file(args: argparse.Namespace, base_dir_for_js: str):
    """単一のファイルを処理します。"""
    file_path = args.file
    language = args.language

    if not language: # 言語が指定されていない場合、自動判別
        language = detect_language_from_filename(file_path)
        if not language:
            logger.info(f"{file_path} の言語を拡張子から判別できませんでした。内容から判別を試みます...")
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(2048) # 先頭2KBで判別
                language = detect_language_from_content(content)
            except Exception as e:
                logger.error(f"ファイル内容読み取り中にエラー ({file_path}): {e}")
                print(f"エラー: {file_path} のファイル内容読み取り中にエラーが発生しました。", file=sys.stderr)
                sys.exit(1)

    if not language or language not in SUPPORTED_LANGUAGES:
        print(f"エラー: {file_path} の言語を判別できませんでした。サポートされている言語は {SUPPORTED_LANGUAGES} です。\n"
              f"--language オプションで明示的に指定してください。", file=sys.stderr)
        sys.exit(1)

    # JavaScriptの場合、base_dir はプロジェクトルートを指すことが望ましい
    effective_base_dir = base_dir_for_js if language == 'javascript' else os.path.dirname(os.path.abspath(file_path))

    checker = DependencyChecker(language, effective_base_dir)
    result = checker.check_file(file_path)

    results_map = {file_path: result}
    language_map = {file_path: language}
    display_results(results_map, args, language_map)


def process_directory(args: argparse.Namespace, base_dir_for_js: str):
    """ディレクトリ内のサポートされているすべてのファイルを処理します。"""
    scan_dir = args.directory
    all_results: Dict[str, Dict[str, Any]] = {}
    language_map: Dict[str, str] = {} # 各ファイルの言語を保存

    logger.info(f"ディレクトリ {scan_dir} をスキャン中...")

    supported_extensions = tuple(ext for lang_ext_map in [{'.py'}, {'.js', '.jsx', '.ts', '.tsx'}] for ext in lang_ext_map)

    for root, _, files in os.walk(scan_dir):
        # .git, node_modules, venv などの一般的なディレクトリをスキップ
        if any(excluded in root for excluded in ['.git', 'node_modules', 'venv', '__pycache__', '.idea', '.vscode']):
            logger.debug(f"スキップディレクトリ: {root}")
            continue

        for file in files:
            if not file.endswith(supported_extensions):
                continue

            file_path = os.path.join(root, file)
            language_to_use = args.language # CLIで指定された言語を優先

            if not language_to_use:
                language_to_use = detect_language_from_filename(file_path)
                # 拡張子で不明な場合、内容からの判別はコストがかかるため、
                # ディレクトリモードではスキップするか、限定的に行う。
                # ここでは拡張子ベースのみとする。必要なら内容ベースも追加。
                if not language_to_use:
                    logger.debug(f"スキップ (言語不明): {file_path}")
                    continue

            if language_to_use not in SUPPORTED_LANGUAGES:
                logger.warning(f"スキップ (非対応言語 {language_to_use}): {file_path}")
                continue

            language_map[file_path] = language_to_use
            # JavaScriptの場合、base_dir はプロジェクトルート (scan_dir) を使う
            effective_base_dir = base_dir_for_js if language_to_use == 'javascript' else os.path.dirname(file_path)

            checker = DependencyChecker(language_to_use, effective_base_dir)
            result = checker.check_file(file_path)
            all_results[file_path] = result

    if not all_results:
        print(f"ディレクトリ {scan_dir} 内にサポートされているファイルが見つかりませんでした。")
        return

    display_results(all_results, args, language_map)


# --- Tests ---
# (テストコードは長いため、主要なロジックの変更に合わせて更新が必要です)
# ここでは省略しますが、実際の開発ではテストの更新と拡充が不可欠です。
class DependencyCheckerTests(unittest.TestCase):
    """DependencyCheckerクラスのユニットテスト。"""

    def setUp(self):
        # テスト用のベースディレクトリを作成
        self.test_dir = tempfile.TemporaryDirectory()
        self.test_base_dir = self.test_dir.name

        # Pythonチェッカー (ベースディレクトリはテストごとに設定)
        self.python_checker = DependencyChecker('python', self.test_base_dir)

        # JavaScriptチェッカー用のダミーpackage.jsonとlockファイル
        # (テストケースに応じてこれらを作成・削除する必要がある)
        self.js_project_dir = os.path.join(self.test_base_dir, "js_project")
        os.makedirs(self.js_project_dir, exist_ok=True)
        with open(os.path.join(self.js_project_dir, "package.json"), "w") as f:
            json.dump({
                "name": "test-js-project",
                "dependencies": {"axios": "^0.21.0", "lodash": "4.17.20"},
                "devDependencies": {"jest": "^27.0.0"}
            }, f)
        # ダミーのlockファイル (例: package-lock.json)
        with open(os.path.join(self.js_project_dir, "package-lock.json"), "w") as f:
            json.dump({"name": "test-js-project", "version": "1.0.0", "dependencies": {
                "axios": {"version": "0.21.4"}, # safe_run をモックしない場合、実際に近いデータ構造
                "lodash": {"version": "4.17.21"}
            }}, f)

        self.js_checker = DependencyChecker('javascript', self.js_project_dir)


    def tearDown(self):
        self.test_dir.cleanup()
        # lru_cacheをクリア (テスト間で影響しないように)
        get_installed_python_version.cache_clear()
        get_public_versions.cache_clear()
        check_security_vulnerabilities.cache_clear()
        # DependencyChecker._get_js_installed_dependencies.cache_clear() # インスタンスメソッドのキャッシュクリアは注意

    def test_python_imports_basic(self):
        code = "import requests\nfrom django.http import HttpResponse\nimport flask.app"
        # get_installed_python_version と get_public_versions をモック
        with patch(__name__ + '.get_installed_python_version', return_value="2.25.1") as mock_get_ver, \
             patch(__name__ + '.get_public_versions', return_value=["2.25.0", "2.25.1"]) as mock_get_pub:
            result = self.python_checker.check(code)

        self.assertIn('requests', result)
        self.assertTrue(result['requests']['installed'])
        self.assertEqual(result['requests']['version'], "2.25.1")
        self.assertIn('django', result)
        self.assertIn('flask', result)
        mock_get_ver.assert_any_call('requests') # 呼び出しを検証
        mock_get_pub.assert_any_call('requests', 'python')


    def test_python_stdlib_exclusion(self):
        code = "import os\nimport sys\nimport json\nimport datetime\nimport requests"
        with patch(__name__ + '.get_installed_python_version', return_value="1.0.0"), \
             patch(__name__ + '.get_public_versions', return_value=[]):
            result = self.python_checker.check(code)
        self.assertNotIn('os', result)
        self.assertNotIn('sys', result)
        self.assertNotIn('json', result)
        self.assertIn('requests', result)


    def test_python_relative_import_exclusion(self):
        code = "from . import local_module\nfrom ..parent_module import another_thing"
        result = self.python_checker.check(code)
        self.assertEqual(len(result), 0, "相対インポートは外部依存としてカウントされるべきではありません")


    def test_python_nested_imports(self):
        code = """
def my_func():
    import numpy as np
class MyClass:
    def method(self):
        from pandas import DataFrame
"""
        with patch(__name__ + '.get_installed_python_version', return_value=None) as mock_get_ver, \
             patch(__name__ + '.get_public_versions', return_value=[]) as mock_get_pub:
            result = self.python_checker.check(code)
        self.assertIn('numpy', result)
        self.assertIn('pandas', result)
        self.assertFalse(result['numpy']['installed'])


    @patch(__name__ + '.safe_run') # safe_runをモックしてJSの依存関係取得を制御
    def test_javascript_imports_with_mocked_deps(self, mock_safe_run):
        # safe_run が返す npm list --json のような出力をシミュレート
        mock_safe_run.return_value = (
            {
                "dependencies": {
                    "react": {"version": "17.0.2"},
                    "axios": {"version": "0.21.4"}
                }
            },
            None # no error
        )

        code = """
import React from 'react';
import { useState } from 'react'; // reactの一部として扱われるべきだが、現状は 'react' のみ検出
const axios = require('axios');
const _ = require('lodash'); // lodash は package.json にないので未インストール扱いになるはず
import('./dynamic-import.js'); // これはモジュール名として扱われない
require('./local-file.js'); // これもローカルパス
import '@scoped/package';
"""
        # _get_js_installed_dependencies.cache_clear() # 必要なら
        # js_checker を再初期化してキャッシュをクリアするか、メソッドのキャッシュをクリアする
        # (インスタンスメソッドのlru_cacheはクラス修飾ではクリアできない)
        # ここでは、setUpで毎回js_checkerが作られるので、safe_runのモックで十分
        # ただし、_get_js_installed_dependenciesがキャッシュされるので、
        # checkerインスタンスをテストごとに変えるか、キャッシュの扱いを工夫する必要がある。
        # このテストでは、safe_runがモックされるので、キャッシュされた古い結果は使われないはず。

        # 1つの DependencyCheckerインスタンスで複数のテストケースを実行する場合、
        # _get_js_installed_dependencies のキャッシュが問題になることがある。
        # テストの独立性を保つために、各テストメソッドでチェッカーをインスタンス化するか、
        # キャッシュを明示的にクリアする手段を提供する。
        # ここでは setUp で毎回新しい js_checker が作られることを期待。

        # js_checker の _get_js_installed_dependencies のキャッシュをクリア
        type(self.js_checker)._get_js_installed_dependencies.fget.cache_clear()


        result = self.js_checker.check(code)

        self.assertIn('react', result)
        self.assertTrue(result['react']['installed'])
        self.assertEqual(result['react']['version'], '17.0.2')

        self.assertIn('axios', result)
        self.assertTrue(result['axios']['installed'])
        self.assertEqual(result['axios']['version'], '0.21.4')

        self.assertIn('lodash', result) # package.jsonにないので未検出になる
        self.assertFalse(result['lodash']['installed'])
        self.assertEqual(result['lodash']['version'], 'N/A')

        self.assertIn('@scoped/package', result) # スコープ付きパッケージも検出
        self.assertFalse(result['@scoped/package']['installed'])


        self.assertNotIn('./local-file.js', result)
        self.assertNotIn('./dynamic-import.js', result) # これらは現状の regex ではモジュール名として抽出されない (それで良い)
        mock_safe_run.assert_called_once() # safe_run が一度だけ呼ばれたか (キャッシュが効いていないか確認)

    @patch('requests.get')
    def test_get_public_versions_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = {'releases': {'1.0.0': {}, '1.1.0': {}}}
        mock_response.raise_for_status.return_value = None # エラーなし
        mock_get.return_value = mock_response

        versions = get_public_versions('test-package', 'python')
        self.assertEqual(versions, ['1.0.0', '1.1.0'])
        mock_get.assert_called_once_with(Config.PYPI_API_URL.format(package='test-package'), timeout=Config.REQUEST_TIMEOUT)

    @patch('requests.get')
    def test_get_public_versions_not_found(self, mock_get):
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = RequestException(response=MagicMock(status_code=404))
        mock_get.return_value = mock_response

        versions = get_public_versions('nonexistent-package', 'python')
        self.assertEqual(versions, [])


    def test_is_version_unusual(self):
        self.assertTrue(is_version_unusual('2.0.0', ['1.0.0', '1.1.0', '1.2.0']))
        self.assertFalse(is_version_unusual('1.1.0', ['1.0.0', '1.1.0', '1.2.0']))
        self.assertFalse(is_version_unusual('1.0.0', [])) # 公開バージョンなし
        self.assertTrue(is_version_unusual('1.0.0', ['0.9.0', '0.8.0']))
        self.assertFalse(is_version_unusual('1.0.0-beta', ['1.0.0', '1.1.0'])) # pre-release は通常、より低い
        self.assertTrue(is_version_unusual('2.0.0', ['1.0.0', '1.1.0-beta']))


    def test_find_similar_name_typo(self):
        self.assertEqual(find_similar_name('reqeusts', 'python'), ('requests', 1.0))
        self.assertEqual(find_similar_name('djanga', 'python'), ('django', 1.0))

    def test_find_similar_name_suggestion(self):
        similar, score = find_similar_name('numpyarray', 'python') # numpy との類似性を期待
        self.assertEqual(similar, 'numpy')
        self.assertGreater(score, 0.7) # 閾値による

        self.assertIsNone(find_similar_name('completely_unique_package_name_xyz', 'python'))

    def test_vulnerability_simulation(self):
        # シミュレーションなので、ハードコードされたロジックが期待通り動くか確認
        vulns_requests_old = check_security_vulnerabilities('requests', '2.0.0', 'python')
        self.assertTrue(any('CVE-2023-XXXX' in v.get('id','') for v in vulns_requests_old if isinstance(v,dict) and v.get('id') ))

        vulns_requests_new = check_security_vulnerabilities('requests', '2.25.1', 'python')
        self.assertFalse(any('CVE-2023-XXXX' in v.get('id','') for v in vulns_requests_new if isinstance(v,dict) and v.get('id') ))

        vulns_lodash_old = check_security_vulnerabilities('lodash', '4.17.20', 'javascript')
        self.assertTrue(any('CVE-2021-ZZZZ' in v.get('id','') for v in vulns_lodash_old if isinstance(v,dict) and v.get('id') ))

# --- Main execution ---
if __name__ == '__main__':
    # unittest.main() は sys.argv を変更するため、条件分岐を先に持ってくる
    if '--test' in sys.argv:
        # '--test' 引数を削除して unittest.main に渡す
        test_argv = [sys.argv[0]] + [arg for arg in sys.argv[1:] if arg != '--test']
        # verboseオプションもテストに渡す
        if '-v' in sys.argv or '--verbose' in sys.argv:
             # unittest の verbose (-v) は -v のみ、--verboseは非対応の場合がある
            if '-v' not in test_argv: test_argv.append('-v')

        # unittest.main(argv=test_argv, verbosity=2 if '-v' in test_argv else 1)
        # verbosityはmainの引数ではない。-vで渡すのが一般的。
        unittest.main(argv=test_argv)
    else:
        main()
