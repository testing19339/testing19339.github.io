import atexit
import getpass
import math
import os
import re
import shutil
import sys
import tempfile
import zipfile
from datetime import datetime
from os.path import basename, dirname, exists, expanduser, isdir, join
from typing import List, Optional, Tuple

try:
    from tqdm import tqdm as _tqdm
    _HAS_TQDM = True
except ImportError:
    _HAS_TQDM = False

from . import __version__
from .colors import col, BOLD, DIM, RED, GREEN, YELLOW, CYAN, WHITE, BLUE
from .vault import Vault, create_vault

VAULTS_DIR       = expanduser('~/pymator')
_SIZE_W          = 9
_DATE_W          = 10
_ZERO_BUF        = bytearray(65536)
_FIND_LIMIT      = 500
_FIND_SCAN_LIMIT = 10000
_ANSI_RE         = re.compile(r'\033\[[^m]*m')

_SECURE_TMPDIR: Optional[str] = None

_BAR_FMT = '  {percentage:3.0f}% |{bar:28}| {n_fmt}/{total_fmt}'
_FILE_FMT = '  {percentage:3.0f}% |{bar:28}| {n}/{total} files'


def _get_secure_tmpdir() -> str:
    global _SECURE_TMPDIR
    if _SECURE_TMPDIR is None or not os.path.isdir(_SECURE_TMPDIR):
        _SECURE_TMPDIR = tempfile.mkdtemp(prefix='.pymator-tmp-')
        os.chmod(_SECURE_TMPDIR, 0o700)
    return _SECURE_TMPDIR


def _cleanup_secure_tmpdir() -> None:
    global _SECURE_TMPDIR
    d = _SECURE_TMPDIR
    if d and os.path.isdir(d):
        try:
            shutil.rmtree(d)
        except Exception:
            pass
    _SECURE_TMPDIR = None


atexit.register(_cleanup_secure_tmpdir)


def _visible_len(s: str) -> int:
    return len(_ANSI_RE.sub('', s))


def _term_width() -> int:
    return shutil.get_terminal_size((80, 24)).columns


def _clear():
    os.system('cls' if os.name == 'nt' else 'clear')


def _hr():
    w = min(_term_width() - 2, 64)
    print(col('  ' + '─' * w, DIM))


def _header(title: str, sub: str = ''):
    w = min(_term_width() - 4, 62)
    if sub:
        max_sub   = max(0, w - 12)
        max_title = max(0, w - min(len(sub), max_sub) - 3)
        title = title if len(title) <= max_title else title[:max_title - 1] + '~'
        sub   = sub   if len(sub)   <= max_sub   else '…' + sub[-(max_sub - 1):]
        gap   = w - len(title) - len(sub) - 2
        print()
        print(col('  ╭' + '─' * w + '╮', CYAN))
        inner = (col('  │', CYAN) + col(f' {title}', BOLD, WHITE)
                 + ' ' * max(1, gap) + col(f'{sub} ', DIM) + col('│', CYAN))
    else:
        max_title = max(0, w - 1)
        title = title if len(title) <= max_title else title[:max_title - 1] + '~'
        print()
        print(col('  ╭' + '─' * w + '╮', CYAN))
        inner = (col('  │', CYAN) + col(f' {title}', BOLD, WHITE)
                 + ' ' * max(1, w - len(title) - 1) + col('│', CYAN))
    print(inner)
    print(col('  ╰' + '─' * w + '╯', CYAN))
    print()


def _ask(prompt: str = '> ') -> str:
    try:
        return input(col(f'  {prompt}', BOLD, CYAN)).strip()
    except (KeyboardInterrupt, EOFError):
        print()
        return ''


def _ask_password(prompt: str = 'Password: ') -> str:
    try:
        return getpass.getpass(col(f'  {prompt}', BOLD, YELLOW))
    except (KeyboardInterrupt, EOFError):
        print()
        return ''


def _ok(msg: str):
    print(col('  ✓  ', BOLD, GREEN) + msg)


def _err(msg: str):
    print(col('  ✗  ', BOLD, RED) + col(msg, RED))


def _warn(msg: str):
    print(col('  !  ', BOLD, YELLOW) + col(msg, YELLOW))


def _pause():
    try:
        input(col('  Press Enter to continue…', DIM))
    except (KeyboardInterrupt, EOFError):
        pass


def _fmt_size(n: int) -> str:
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024 or unit == 'TB':
            return f'{n:.0f} B' if unit == 'B' else f'{n:.1f} {unit}'
        n /= 1024
    return str(n)


def _fmt_date(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime('%Y-%m-%d')


def _sanitize(name: str) -> str:
    name = re.sub(r'[<>:\"/\\|?*\x00-\x1F\x7F]', '_', name.strip())
    name = name.strip('. ')
    return name[:200] if len(name) > 200 else name


def _truncate(s: str, max_len: int) -> str:
    return s if len(s) <= max_len else s[:max_len - 1] + '~'


def _secure_unlink(path: str):
    try:
        size = os.path.getsize(path)
        if size > 0:
            mv = memoryview(_ZERO_BUF)
            with open(path, 'r+b') as f:
                remaining = size
                while remaining > 0:
                    to_write  = min(len(_ZERO_BUF), remaining)
                    f.write(mv[:to_write])
                    remaining -= to_write
                f.flush()
                os.fsync(f.fileno())
    except Exception:
        pass
    try:
        os.unlink(path)
    except OSError:
        pass


def _password_strength(pw: str) -> Tuple[str, str]:
    if not pw:
        return 'None', RED
    charset = 0
    if any(c.islower()     for c in pw): charset += 26
    if any(c.isupper()     for c in pw): charset += 26
    if any(c.isdigit()     for c in pw): charset += 10
    if any(not c.isalnum() for c in pw): charset += 32
    if charset == 0:
        charset = 1
    entropy = len(pw) * math.log2(charset)
    if entropy < 36:
        return 'Weak', RED
    if entropy < 56:
        return 'Fair', YELLOW
    if entropy < 80:
        return 'Strong', GREEN
    return 'Very strong', BOLD + GREEN


def _friendly_error(exc: Exception) -> str:
    msg = str(exc)
    if 'Wrong password' in msg or 'Key unwrap' in msg:
        return 'Wrong password or corrupted vault key.'
    if 'authentication failed' in msg.lower():
        return 'Authentication failed — file may be corrupted or tampered with.'
    if 'File too short' in msg:
        return 'File is too short to be valid — it may be corrupted.'
    if 'No space left' in msg:
        return 'Not enough disk space.'
    if 'Permission denied' in msg:
        return 'Permission denied — check file permissions.'
    if isinstance(exc, FileNotFoundError):
        return f'File not found: {msg}'
    return msg


def _count_vault_files(vault: Vault, vpath: str) -> int:
    return sum(len(files) for _, _, files in vault.walk(vpath))


def _local_pick_file(start_dir: str) -> Optional[str]:
    cwd = os.path.abspath(start_dir)
    while True:
        _clear()
        path_disp = cwd if len(cwd) <= 40 else '…' + cwd[-39:]
        _header('Upload — select file', path_disp)

        try:
            raw       = list(os.scandir(cwd))
            raw_dirs  = sorted([e for e in raw if e.is_dir(follow_symlinks=False)],
                               key=lambda e: e.name.lower())
            raw_files = sorted([e for e in raw if e.is_file(follow_symlinks=False)],
                               key=lambda e: e.name.lower())
        except Exception as e:
            _err(str(e))
            _pause()
            return None

        tw     = _term_width()
        name_w = max(10, tw - _SIZE_W - 8)
        idx    = 0

        for e in raw_dirs:
            idx += 1
            n = _truncate(e.name + '/', name_w)
            print(col(f'  {idx:<3}', BOLD, CYAN) + col(n, BOLD, BLUE))

        if raw_dirs and raw_files:
            print()

        file_start = idx + 1
        for e in raw_files:
            idx += 1
            try:
                sz = _fmt_size(e.stat().st_size).rjust(_SIZE_W)
            except OSError:
                sz = '?'.rjust(_SIZE_W)
            n = _truncate(e.name, name_w)
            print(col(f'  {idx:<3}', BOLD, CYAN) + n.ljust(name_w) + col(sz, DIM))

        if not raw_dirs and not raw_files:
            print(col('  (empty)', DIM))

        print()
        _hr()
        print()

        has_parent = os.path.dirname(cwd) != cwd
        a_up   = idx + 1 if has_parent else None
        a_path = idx + 2 if has_parent else idx + 1

        if has_parent:
            print(col(f'  {a_up:<3}', BOLD, YELLOW) + 'Go up')
        print(col(f'  {a_path:<3}', BOLD, YELLOW) + 'Type path')
        print(col('  0  ', BOLD, RED) + 'Cancel')
        print()

        ch = _ask()
        if not ch or ch == '0':
            return None

        if a_up is not None and ch == str(a_up):
            cwd = os.path.dirname(cwd)
            continue

        if ch == str(a_path):
            typed = _ask('Path: ')
            if not typed:
                continue
            typed = os.path.expanduser(typed.strip())
            if os.path.isfile(typed):
                return typed
            if os.path.isdir(typed):
                cwd = os.path.abspath(typed)
            else:
                _err('Not found.')
                _pause()
            continue

        try:
            n = int(ch)
        except ValueError:
            continue

        if n < 1 or n > idx:
            continue

        if n < file_start:
            cwd = os.path.join(cwd, raw_dirs[n - 1].name)
        else:
            return os.path.join(cwd, raw_files[n - file_start].name)


def _local_pick_dir(start_dir: str, title: str = 'Choose destination') -> Optional[str]:
    cwd = os.path.abspath(start_dir)
    while True:
        _clear()
        path_disp = cwd if len(cwd) <= 40 else '…' + cwd[-39:]
        _header(title, path_disp)

        try:
            raw  = list(os.scandir(cwd))
            dirs = sorted([e for e in raw if e.is_dir(follow_symlinks=False)],
                          key=lambda e: e.name.lower())
        except Exception as e:
            _err(str(e))
            _pause()
            return None

        tw     = _term_width()
        name_w = max(10, tw - 8)
        idx    = 0

        for e in dirs:
            idx += 1
            n = _truncate(e.name + '/', name_w)
            print(col(f'  {idx:<3}', BOLD, CYAN) + col(n, BOLD, BLUE))

        if not dirs:
            print(col('  (no subdirectories)', DIM))

        print()
        _hr()
        print()

        has_parent = os.path.dirname(cwd) != cwd
        a_here = idx + 1
        a_up   = idx + 2 if has_parent else None
        a_path = idx + 3 if has_parent else idx + 2

        print(col(f'  {a_here:<3}', BOLD, GREEN) + 'Save here  ' + col(path_disp, DIM))
        if has_parent:
            print(col(f'  {a_up:<3}', BOLD, YELLOW) + 'Go up')
        print(col(f'  {a_path:<3}', BOLD, YELLOW) + 'Type path')
        print(col('  0  ', BOLD, RED) + 'Cancel')
        print()

        ch = _ask()
        if not ch or ch == '0':
            return None

        if ch == str(a_here):
            return cwd

        if a_up is not None and ch == str(a_up):
            cwd = os.path.dirname(cwd)
            continue

        if ch == str(a_path):
            typed = _ask('Path: ')
            if not typed:
                continue
            typed = os.path.expanduser(typed.strip())
            if os.path.isdir(typed):
                cwd = os.path.abspath(typed)
            else:
                _err('Not a directory or not found.')
                _pause()
            continue

        try:
            n = int(ch)
        except ValueError:
            continue

        if 1 <= n <= len(dirs):
            cwd = os.path.join(cwd, dirs[n - 1].name)


class _ProgressReader:

    def __init__(self, f, bar):
        self._f   = f
        self._bar = bar

    def read(self, n: int = -1) -> bytes:
        data = self._f.read(n)
        if data:
            self._bar.update(len(data))
        return data

    def __getattr__(self, name: str):
        return getattr(self._f, name)


class _ProgressWriter:

    def __init__(self, f, bar):
        self._f   = f
        self._bar = bar

    def write(self, data: bytes) -> int:
        if data:
            self._bar.update(len(data))
        return self._f.write(data)

    def __getattr__(self, name: str):
        return getattr(self._f, name)


class Browser:

    def __init__(self, vault: Vault, vault_name: str):
        self.vault     = vault
        self.name      = vault_name
        self.cwd       = '/'
        self.local_dir = expanduser('~')

    def run(self):
        while True:
            if not self._browse():
                break

    def _browse(self) -> bool:
        _clear()
        try:
            entries = self.vault.listdir(self.cwd)
        except Exception as e:
            _err(str(e))
            _pause()
            return False

        dirs  = [e for e in entries if e['type'] == 'dir']
        files = [e for e in entries if e['type'] in ('file', 'symlink')]

        path_disp = self.cwd if len(self.cwd) <= 32 else '…' + self.cwd[-31:]
        _header(self.name, path_disp)

        if entries:
            parts = []
            if dirs:  parts.append(f'{len(dirs)} folder{"s" if len(dirs)  != 1 else ""}')
            if files: parts.append(f'{len(files)} file{"s"  if len(files) != 1 else ""}')
            print(col('  ' + ',  '.join(parts), DIM))
            print()

        tw        = _term_width()
        show_date = tw >= 62
        meta_w    = _SIZE_W + (2 + _DATE_W if show_date else 0)
        name_w    = max(10, tw - meta_w - 8)

        idx      = 0
        item_map: dict = {}

        for e in dirs:
            idx += 1
            item_map[idx] = e
            n = _truncate(e['name'] + '/', name_w)
            print(col(f'  {idx:<3}', BOLD, CYAN) + col(n, BOLD, BLUE))

        if dirs and files:
            print()

        for e in files:
            idx += 1
            item_map[idx] = e
            n   = _truncate(e['name'], name_w)
            sz  = _fmt_size(e['size']).rjust(_SIZE_W)
            dt  = _fmt_date(e['mtime'])
            row = col(f'  {idx:<3}', BOLD, CYAN) + n.ljust(name_w)
            if show_date:
                row += col(f'{sz}  {dt}', DIM)
            else:
                row += col(sz, DIM)
            print(row)

        if not entries:
            print(col('  (empty)', DIM))

        print()
        _hr()
        print()

        has_up = self.cwd != '/'
        half   = max(30, (tw - 2) // 2)

        def _act(k: str, label: str) -> str:
            return col(f'  {k:<4}', BOLD, YELLOW) + label

        def _act_row(left: str, right: str):
            pad = max(2, half - _visible_len(left))
            print(left + ' ' * pad + right)

        _act_row(_act('n', 'New folder'),   _act('u', 'Upload'))
        _act_row(_act('g', 'Download'),     _act('m', 'Move / rename'))
        _act_row(_act('/', 'Search'),       _act('x', 'Delete'))

        if has_up:
            parent_raw  = dirname(self.cwd) or '/'
            max_plen    = max(8, tw // 2 - 22)
            parent_disp = (parent_raw if len(parent_raw) <= max_plen
                           else '…' + parent_raw[-(max_plen - 1):])
            _act_row(
                _act('..', 'Go up  ' + col(parent_disp, DIM)),
                _act('0',  col('Lock & exit', RED)),
            )
        else:
            print(_act('0', col('Lock & exit', RED)))

        print()

        choice = _ask()
        if not choice:
            return True
        if choice == '0':
            return False

        ch = choice.lower().strip()

        if ch == 'n':
            self._new_folder()
        elif ch == 'u':
            self._upload_menu()
        elif ch == 'g':
            self._download_menu(files)
        elif ch == 'm':
            self._move_menu(entries)
        elif ch in ('/', 'f'):
            self._find()
        elif ch == 'x':
            self._delete_menu(entries)
        elif ch == '..' and has_up:
            self.cwd = dirname(self.cwd) or '/'
        else:
            try:
                n = int(choice)
                if 1 <= n <= idx:
                    e = item_map[n]
                    if e['type'] == 'dir':
                        self.cwd = self.vault._normalize(self.cwd + '/' + e['name'])
                    else:
                        self._file_menu(e)
            except ValueError:
                pass

        return True

    def _file_menu(self, entry: dict):
        vpath = self.vault._normalize(self.cwd + '/' + entry['name'])
        _clear()
        _header(entry['name'], f"{_fmt_size(entry['size'])}  {_fmt_date(entry['mtime'])}")
        print(col('  1  ', BOLD, CYAN) + 'Download')
        print(col('  2  ', BOLD, CYAN) + 'Move to another folder')
        print(col('  3  ', BOLD, CYAN) + 'Rename')
        print(col('  4  ', BOLD, RED)  + 'Delete')
        print(col('  0  ', DIM)        + 'Back')
        print()
        ch = _ask()
        if ch == '1':
            self._download_file(vpath, entry['name'])
        elif ch == '2':
            self._do_move_file(vpath, entry['name'])
        elif ch == '3':
            self._do_rename(vpath, entry['name'], is_dir=False)
        elif ch == '4':
            self._do_delete_file(vpath, entry['name'])

    def _new_folder(self):
        _clear()
        _header('New Folder', self.cwd)
        name = _ask('Name: ')
        if not name:
            return
        name = _sanitize(name)
        if not name:
            _err('Invalid name.')
            _pause()
            return
        vpath = self.vault._normalize(self.cwd + '/' + name)
        try:
            self.vault.mkdir(vpath)
            _ok(f'Created: {vpath}')
        except FileExistsError:
            _warn('Already exists.')
        except Exception as e:
            _err(_friendly_error(e))
        _pause()

    def _upload_menu(self):
        _clear()
        _header('Upload', self.cwd)
        print(col('  1  ', BOLD, CYAN) + 'File(s)         ' + col('(1,2,3 & all)', DIM))
        print(col('  2  ', BOLD, CYAN) + 'Entire folder   ' + col('(recursive)', DIM))
        print(col('  0  ', DIM)        + 'Cancel')
        print()
        ch = _ask()
        if ch == '1':
            self._pick_and_upload_files()
        elif ch == '2':
            self._upload_folder()

    def _pick_and_upload_files(self):
        cwd = os.path.abspath(self.local_dir)
        while True:
            _clear()
            path_disp = cwd if len(cwd) <= 40 else '…' + cwd[-39:]
            _header('Upload — select file(s)', path_disp)

            try:
                raw       = list(os.scandir(cwd))
                raw_dirs  = sorted([e for e in raw if e.is_dir(follow_symlinks=False)],
                                   key=lambda e: e.name.lower())
                raw_files = sorted([e for e in raw if e.is_file(follow_symlinks=False)],
                                   key=lambda e: e.name.lower())
            except Exception as e:
                _err(str(e))
                _pause()
                return

            tw     = _term_width()
            name_w = max(10, tw - _SIZE_W - 8)
            idx    = 0

            for e in raw_dirs:
                idx += 1
                n = _truncate(e.name + '/', name_w)
                print(col(f'  {idx:<3}', BOLD, CYAN) + col(n, BOLD, BLUE))

            if raw_dirs and raw_files:
                print()

            file_start = idx + 1
            for e in raw_files:
                idx += 1
                try:
                    sz = _fmt_size(e.stat().st_size).rjust(_SIZE_W)
                except OSError:
                    sz = '?'.rjust(_SIZE_W)
                n = _truncate(e.name, name_w)
                print(col(f'  {idx:<3}', BOLD, CYAN) + n.ljust(name_w) + col(sz, DIM))

            if not raw_dirs and not raw_files:
                print(col('  (empty)', DIM))

            print()
            _hr()
            print()

            has_parent = os.path.dirname(cwd) != cwd
            a_up   = idx + 1 if has_parent else None
            a_path = idx + 2 if has_parent else idx + 1

            if has_parent:
                print(col(f'  {a_up:<3}', BOLD, YELLOW) + 'Go up')
            print(col(f'  {a_path:<3}', BOLD, YELLOW) + 'Type path')
            print(col('  0  ', BOLD, RED) + 'Cancel')
            print()

            ch = _ask()
            if not ch or ch == '0':
                return

            if ch.strip().lower() == 'all':
                if not raw_files:
                    _warn('No files here.')
                    _pause()
                    continue
                self._do_upload_files(cwd, raw_files)
                return

            if ',' in ch:
                sel_entries: List = []
                skipped: List[str] = []
                for part in ch.split(','):
                    part = part.strip()
                    if not part:
                        continue
                    try:
                        n = int(part)
                        if file_start <= n <= idx:
                            entry = raw_files[n - file_start]
                            if entry.path not in [x.path for x in sel_entries]:
                                sel_entries.append(entry)
                        else:
                            skipped.append(part)
                    except ValueError:
                        skipped.append(part)
                if skipped:
                    _warn(f'Skipped (not valid): {", ".join(skipped)}')
                if not sel_entries:
                    _warn('No valid file selection.')
                    _pause()
                    continue
                self._do_upload_files(cwd, sel_entries)
                return

            try:
                n = int(ch)
            except ValueError:
                continue

            if a_up is not None and n == a_up:
                cwd = os.path.dirname(cwd)
                continue

            if n == a_path:
                typed = _ask('Path: ')
                if not typed:
                    continue
                typed = os.path.expanduser(typed.strip())
                if os.path.isdir(typed):
                    cwd = os.path.abspath(typed)
                else:
                    _err('Not found.')
                    _pause()
                continue

            if n < 1 or n > idx:
                continue

            if n < file_start:
                cwd = os.path.join(cwd, raw_dirs[n - 1].name)
                continue

            self._do_upload_files(cwd, [raw_files[n - file_start]])
            return

    def _do_upload_files(self, src_dir: str, entries: list):
        self.local_dir = src_dir
        if len(entries) == 1:
            e        = entries[0]
            fname    = e.name
            src_path = e.path
            dest     = self.vault._normalize(self.cwd + '/' + fname)
            force    = False
            try:
                info = self.vault.resolve(dest)
                if info.exists:
                    _clear()
                    _warn(f'{fname} already exists in vault.')
                    print(col('  1  ', BOLD, CYAN) + 'Overwrite')
                    print(col('  0  ', DIM)        + 'Cancel')
                    if _ask() != '1':
                        return
                    force = True
            except Exception:
                pass
            src_size = 0
            mtime    = None
            try:
                st       = os.stat(src_path)
                src_size = st.st_size
                mtime    = st.st_mtime
            except OSError:
                pass
            print(col(f'  Encrypting {fname} …', DIM))
            try:
                with open(src_path, 'rb') as f:
                    if _HAS_TQDM and src_size > 0:
                        with _tqdm(
                            total      = src_size,
                            unit       = 'B',
                            unit_scale = True,
                            desc       = '  ',
                            leave      = False,
                            bar_format = _BAR_FMT,
                            file       = sys.stderr,
                        ) as bar:
                            self.vault.put_stream(
                                _ProgressReader(f, bar), dest, force=force, mtime=mtime
                            )
                    else:
                        self.vault.put_stream(f, dest, force=force, mtime=mtime)
                size_str = f'  ({_fmt_size(src_size)})' if src_size > 0 else ''
                _ok(f'Uploaded: {fname}{size_str}')
            except Exception as ex:
                _err(_friendly_error(ex))
            _pause()
        else:
            print(col(f'  Uploading {len(entries)} file(s)…', DIM))
            ok_count  = 0
            err_count = 0
            for e in entries:
                fname = e.name
                dest  = self.vault._normalize(self.cwd + '/' + fname)
                try:
                    st = os.stat(e.path)
                    with open(e.path, 'rb') as f:
                        self.vault.put_stream(f, dest, force=True, mtime=st.st_mtime)
                    _ok(fname)
                    ok_count += 1
                except Exception as ex:
                    _err(f'{fname}: {_friendly_error(ex)}')
                    err_count += 1
            print()
            summary = col(f'  Done: {ok_count} uploaded', DIM)
            if err_count:
                summary += col(f', {err_count} failed', RED)
            print(summary)
            _pause()

    def _upload_folder(self):
        src_dir = _local_pick_dir(self.local_dir, 'Select folder to upload')
        if src_dir is None:
            return
        self.local_dir = src_dir
        folder_name = os.path.basename(src_dir.rstrip(os.sep))
        if not folder_name:
            _err('Cannot determine folder name.')
            _pause()
            return
        folder_name = _sanitize(folder_name)
        if not folder_name:
            _err('Invalid folder name.')
            _pause()
            return
        all_files: List[str] = []
        for root, dirs, fnames in os.walk(src_dir):
            dirs.sort()
            for fname in sorted(fnames):
                all_files.append(os.path.join(root, fname))
        if not all_files:
            _warn('Folder is empty — nothing to upload.')
            _pause()
            return
        _clear()
        path_disp = src_dir if len(src_dir) <= 40 else '…' + src_dir[-39:]
        dest_vpath = self.vault._normalize(self.cwd + '/' + folder_name)
        _header('Upload Folder', path_disp)
        print(col('  Folder:  ', DIM) + col(folder_name, BOLD, WHITE))
        print(col('  Files:   ', DIM) + str(len(all_files)))
        print(col('  Into:    ', DIM) + dest_vpath)
        print()
        print(col('  1  ', BOLD, CYAN) + 'Upload')
        print(col('  0  ', DIM)        + 'Cancel')
        print()
        if _ask() != '1':
            return
        print(col(f'  Encrypting {len(all_files)} file(s)…', DIM))
        ok_count  = 0
        err_count = 0
        if _HAS_TQDM:
            with _tqdm(
                total      = len(all_files),
                unit       = 'file',
                desc       = '  ',
                leave      = False,
                bar_format = _FILE_FMT,
                file       = sys.stderr,
            ) as bar:
                for local_path in all_files:
                    rel       = os.path.relpath(local_path, src_dir)
                    rel_parts = rel.replace(os.sep, '/')
                    vpath     = self.vault._normalize(dest_vpath + '/' + rel_parts)
                    try:
                        st = os.stat(local_path)
                        with open(local_path, 'rb') as f:
                            self.vault.put_stream(f, vpath, force=True, mtime=st.st_mtime)
                        ok_count += 1
                    except Exception:
                        err_count += 1
                    bar.update(1)
        else:
            for local_path in all_files:
                rel       = os.path.relpath(local_path, src_dir)
                rel_parts = rel.replace(os.sep, '/')
                vpath     = self.vault._normalize(dest_vpath + '/' + rel_parts)
                try:
                    st = os.stat(local_path)
                    with open(local_path, 'rb') as f:
                        self.vault.put_stream(f, vpath, force=True, mtime=st.st_mtime)
                    ok_count += 1
                except Exception:
                    err_count += 1
        _ok(f'Done: {ok_count} file(s) uploaded to {dest_vpath}')
        if err_count:
            _err(f'{err_count} file(s) failed.')
        _pause()

    def _move_menu(self, entries: List[dict]):
        if not entries:
            _warn('Nothing here to move.')
            _pause()
            return
        _clear()
        _header('Move / Rename', self.cwd)
        for i, e in enumerate(entries, 1):
            suffix = '/' if e['type'] == 'dir' else ''
            c      = BLUE  if e['type'] == 'dir' else WHITE
            b      = BOLD  if e['type'] == 'dir' else ''
            print(col(f'  {i:<3}', BOLD, CYAN) + col(e['name'] + suffix, b, c))
        print(col('  0  ', DIM) + 'Cancel')
        print()
        ch = _ask('Item #: ')
        if not ch or ch == '0':
            return
        try:
            n = int(ch)
            if n < 1 or n > len(entries):
                return
        except ValueError:
            return
        e     = entries[n - 1]
        vpath = self.vault._normalize(self.cwd + '/' + e['name'])
        if e['type'] == 'dir':
            print()
            print(col('  1  ', BOLD, CYAN) + 'Move to another folder')
            print(col('  2  ', BOLD, CYAN) + 'Rename')
            print(col('  0  ', DIM)        + 'Cancel')
            ch2 = _ask()
            if ch2 == '1':
                self._do_move_dir(vpath, e['name'])
            elif ch2 == '2':
                self._do_rename(vpath, e['name'], is_dir=True)
        else:
            self._do_move_file(vpath, e['name'])

    def _download_menu(self, files: List[dict]):
        if not files:
            _warn('No files here.')
            _pause()
            return
        _clear()
        _header('Download', self.cwd)
        tw     = _term_width()
        name_w = max(10, tw - _SIZE_W - 8)
        for i, e in enumerate(files, 1):
            sz = _fmt_size(e['size']).rjust(_SIZE_W)
            n  = _truncate(e['name'], name_w)
            print(col(f'  {i:<3}', BOLD, CYAN) + n.ljust(name_w) + col(sz, DIM))
        print(col('  0  ', DIM) + 'Cancel')
        print()
        ch = _ask('File #: ')
        if not ch or ch == '0':
            return
        try:
            n = int(ch)
            if n < 1 or n > len(files):
                return
        except ValueError:
            return
        e     = files[n - 1]
        vpath = self.vault._normalize(self.cwd + '/' + e['name'])
        self._download_file(vpath, e['name'])

    def _delete_menu(self, entries: List[dict]):
        if not entries:
            _warn('Nothing to delete.')
            _pause()
            return
        _clear()
        _header('Delete', self.cwd)
        for i, e in enumerate(entries, 1):
            suffix = '/' if e['type'] == 'dir' else ''
            if e['type'] == 'dir':
                print(col(f'  {i:<3}', BOLD, CYAN) + col(e['name'] + suffix, BOLD, BLUE))
            else:
                print(col(f'  {i:<3}', BOLD, CYAN) + e['name'] + suffix)
        print(col('  0  ', DIM) + 'Cancel')
        print()
        ch = _ask('Item #: ')
        if not ch or ch == '0':
            return
        try:
            n = int(ch)
            if n < 1 or n > len(entries):
                return
        except ValueError:
            return
        e     = entries[n - 1]
        vpath = self.vault._normalize(self.cwd + '/' + e['name'])
        if e['type'] == 'dir':
            self._do_delete_dir(vpath, e['name'])
        else:
            self._do_delete_file(vpath, e['name'])

    def _find(self):
        _clear()
        _header('Search', self.cwd)
        print(col(f'  Searching under: {self.cwd}', DIM))
        print()
        term = _ask('Search term: ')
        if not term:
            return
        term_low = term.lower()
        print()
        print(col('  Searching…', DIM))
        results = []
        stack   = [self.cwd]
        scanned = 0
        try:
            while stack:
                if scanned >= _FIND_SCAN_LIMIT:
                    break
                cur = stack.pop()
                scanned += 1
                try:
                    sub_entries = self.vault.listdir(cur)
                except Exception:
                    continue
                for e in sub_entries:
                    if term_low in e['name'].lower():
                        results.append({
                            'name':  e['name'],
                            'path':  e['virtual_path'],
                            'type':  e['type'],
                            'size':  e['size'],
                            'mtime': e['mtime'],
                        })
                    if e['type'] == 'dir':
                        stack.append(e['virtual_path'])
        except Exception as e:
            _err(str(e))
            _pause()
            return

        results.sort(key=lambda r: (r['type'] != 'dir', r['path'].lower()))

        _clear()
        found = len(results)
        _header(f'Search: "{term}"', f'{found} result{"s" if found != 1 else ""}')

        if not results:
            _warn('No matches found.')
            _pause()
            return

        shown  = results[:_FIND_LIMIT]
        hidden = found - len(shown)

        tw     = _term_width()
        path_w = max(10, tw - _SIZE_W - 8)

        for i, r in enumerate(shown, 1):
            suffix = '/' if r['type'] == 'dir' else ''
            disp   = _truncate(r['path'] + suffix, path_w)
            if r['type'] == 'dir':
                print(col(f'  {i:<3}', BOLD, CYAN) + col(disp, BOLD, BLUE))
            else:
                sz = _fmt_size(r['size']).rjust(_SIZE_W)
                print(col(f'  {i:<3}', BOLD, CYAN) + disp.ljust(path_w) + col(sz, DIM))

        if hidden:
            print(col(f'  … {hidden} more — refine your search term to narrow results', DIM))

        print()
        print(col('  0  ', DIM) + 'Back')
        print()
        ch = _ask()
        if not ch or ch == '0':
            return
        try:
            n = int(ch)
            if n < 1 or n > len(shown):
                return
        except ValueError:
            return

        r = shown[n - 1]
        if r['type'] == 'dir':
            self.cwd = r['path']
        else:
            parent   = dirname(r['path'])
            self.cwd = parent if parent and parent != r['path'] else '/'
            self._file_menu(r)

    def _vault_pick_dir(self, exclude_path: str) -> Optional[str]:
        cwd = '/'
        while True:
            _clear()
            path_disp = cwd if len(cwd) <= 40 else '…' + cwd[-39:]
            _header('Move to…', path_disp)

            try:
                all_entries = self.vault.listdir(cwd)
            except Exception as e:
                _err(str(e))
                _pause()
                return None

            dirs = []
            for e in all_entries:
                if e['type'] != 'dir':
                    continue
                p = self.vault._normalize(cwd + '/' + e['name'])
                if p == exclude_path or p.startswith(exclude_path + '/'):
                    continue
                dirs.append(e)

            tw     = _term_width()
            name_w = max(10, tw - 8)
            idx    = 0

            for e in dirs:
                idx += 1
                n = _truncate(e['name'] + '/', name_w)
                print(col(f'  {idx:<3}', BOLD, CYAN) + col(n, BOLD, BLUE))

            if not dirs:
                print(col('  (no subdirectories)', DIM))

            print()
            _hr()
            print()

            has_parent = cwd != '/'
            a_here = idx + 1
            a_up   = idx + 2 if has_parent else None

            print(col(f'  {a_here:<3}', BOLD, GREEN) + 'Move here  ' + col(path_disp, DIM))
            if has_parent:
                print(col(f'  {a_up:<3}', BOLD, YELLOW) + 'Go up')
            print(col('  0  ', BOLD, RED) + 'Cancel')
            print()

            ch = _ask('Destination: ')
            if not ch or ch == '0':
                return None

            if ch == str(a_here):
                return cwd

            if has_parent and ch == str(a_up):
                cwd = dirname(cwd) or '/'
                continue

            try:
                n = int(ch)
                if 1 <= n <= len(dirs):
                    cwd = self.vault._normalize(cwd + '/' + dirs[n - 1]['name'])
            except ValueError:
                pass

    def _do_move_file(self, vpath: str, name: str):
        dest_dir = self._vault_pick_dir(vpath)
        if dest_dir is None:
            return
        dest = self.vault._normalize(dest_dir + '/' + name)
        if dest == vpath:
            _warn('Same location.')
            _pause()
            return
        fd, tmp_path = tempfile.mkstemp(dir=_get_secure_tmpdir(), prefix='.pymator-mv-')
        try:
            os.close(fd)
            print(col(f'  Moving {name} …', DIM))
            if _HAS_TQDM:
                try:
                    clear_sz = self.vault.size(vpath)
                except Exception:
                    clear_sz = 0
                if clear_sz > 0:
                    with open(tmp_path, 'wb') as tmp_f:
                        with _tqdm(
                            total      = clear_sz,
                            unit       = 'B',
                            unit_scale = True,
                            desc       = '  ',
                            leave      = False,
                            bar_format = _BAR_FMT,
                            file       = sys.stderr,
                        ) as bar:
                            self.vault.get_to_stream(vpath, _ProgressWriter(tmp_f, bar))
                    self.vault.put(tmp_path, dest, force=False)
                    self.vault.rm(vpath)
                else:
                    self.vault.get(vpath, tmp_path, force=True)
                    self.vault.put(tmp_path, dest, force=False)
                    self.vault.rm(vpath)
            else:
                self.vault.get(vpath, tmp_path, force=True)
                self.vault.put(tmp_path, dest, force=False)
                self.vault.rm(vpath)
            _ok(f'Moved → {dest}')
        except Exception as e:
            _err(_friendly_error(e))
        finally:
            _secure_unlink(tmp_path)
        _pause()

    def _do_move_dir(self, vpath: str, name: str):
        dest_dir = self._vault_pick_dir(vpath)
        if dest_dir is None:
            return
        dest = self.vault._normalize(dest_dir + '/' + name)
        if dest == vpath:
            _warn('Same location.')
            _pause()
            return
        try:
            if _HAS_TQDM:
                total = _count_vault_files(self.vault, vpath)
                print(col(f'  Moving {name}/ …', DIM))
                with _tqdm(
                    total      = max(total, 1),
                    unit       = 'file',
                    desc       = '  ',
                    leave      = False,
                    bar_format = _FILE_FMT,
                    file       = sys.stderr,
                ) as bar:
                    self._move_dir_recursive(vpath, dest, bar=bar)
            else:
                self._move_dir_recursive(vpath, dest)
            _ok(f'Moved → {dest}')
        except Exception as e:
            _err(_friendly_error(e))
        _pause()

    def _move_dir_recursive(self, src: str, dst: str, bar=None):
        self.vault.mkdir(dst)
        for e in self.vault.listdir(src):
            cs = self.vault._normalize(src + '/' + e['name'])
            cd = self.vault._normalize(dst + '/' + e['name'])
            if e['type'] == 'dir':
                self._move_dir_recursive(cs, cd, bar=bar)
            else:
                fd, tmp_path = tempfile.mkstemp(
                    dir=_get_secure_tmpdir(), prefix='.pymator-mv-'
                )
                try:
                    os.close(fd)
                    self.vault.get(cs, tmp_path, force=True)
                    self.vault.put(tmp_path, cd, force=False)
                    self.vault.rm(cs)
                    if bar is not None:
                        bar.update(1)
                finally:
                    _secure_unlink(tmp_path)
        self.vault.rmdir(src, recursive=False)

    def _do_rename(self, vpath: str, name: str, is_dir: bool):
        _clear()
        _header('Rename', vpath)
        new_name = _ask(f'New name [{name}]: ')
        if not new_name or new_name == name:
            return
        new_name = _sanitize(new_name)
        if not new_name:
            _err('Invalid name.')
            _pause()
            return
        dest = self.vault._normalize(self.cwd + '/' + new_name)
        try:
            if is_dir:
                if _HAS_TQDM:
                    total = _count_vault_files(self.vault, vpath)
                    print(col(f'  Renaming {name}/ …', DIM))
                    with _tqdm(
                        total      = max(total, 1),
                        unit       = 'file',
                        desc       = '  ',
                        leave      = False,
                        bar_format = _FILE_FMT,
                        file       = sys.stderr,
                    ) as bar:
                        self._move_dir_recursive(vpath, dest, bar=bar)
                else:
                    self._move_dir_recursive(vpath, dest)
            else:
                fd, tmp_path = tempfile.mkstemp(
                    dir=_get_secure_tmpdir(), prefix='.pymator-mv-'
                )
                try:
                    os.close(fd)
                    self.vault.get(vpath, tmp_path, force=True)
                    self.vault.put(tmp_path, dest, force=False)
                    self.vault.rm(vpath)
                finally:
                    _secure_unlink(tmp_path)
            _ok(f'Renamed → {new_name}')
        except Exception as e:
            _err(_friendly_error(e))
        _pause()

    def _do_delete_file(self, vpath: str, name: str):
        print()
        _warn(f"Delete '{name}'?")
        print(col('  1  ', BOLD, RED) + 'Yes, delete permanently')
        print(col('  0  ', DIM)       + 'Cancel')
        if _ask() != '1':
            _warn('Cancelled.')
            _pause()
            return
        try:
            self.vault.rm(vpath)
            _ok(f'Deleted: {name}')
        except Exception as e:
            _err(_friendly_error(e))
        _pause()

    def _do_delete_dir(self, vpath: str, name: str):
        print()
        _warn(f"Delete '{name}/' and ALL its contents?")
        print()
        confirm = _ask('Type folder name to confirm: ')
        if confirm != name:
            _warn('Cancelled.')
            _pause()
            return
        try:
            if _HAS_TQDM:
                all_walk    = list(self.vault.walk(vpath))
                all_files   = [(root, f) for root, dirs, files in all_walk for f in files]
                total       = len(all_files)
                print(col(f'  Deleting {name}/ …', DIM))
                with _tqdm(
                    total      = max(total, 1),
                    unit       = 'file',
                    desc       = '  ',
                    leave      = False,
                    bar_format = _FILE_FMT,
                    file       = sys.stderr,
                ) as bar:
                    for root, fname in all_files:
                        try:
                            self.vault.rm(self.vault._normalize(root + '/' + fname))
                        except Exception:
                            pass
                        bar.update(1)
                for root, dirs, files in reversed(all_walk):
                    for d in dirs:
                        try:
                            self.vault.rmdir(
                                self.vault._normalize(root + '/' + d), recursive=False
                            )
                        except Exception:
                            pass
                try:
                    self.vault.rmdir(vpath, recursive=False)
                except Exception:
                    pass
            else:
                self.vault.rmdir(vpath, recursive=True)
            _ok(f'Deleted: {name}/')
        except Exception as e:
            _err(_friendly_error(e))
        _pause()

    def _download_file(self, vpath: str, name: str):
        safe = os.path.basename(_sanitize(name.replace('/', '_').replace('\\', '_')))
        if not safe:
            _err('Unsafe filename — cannot download.')
            _pause()
            return
        dest_dir = _local_pick_dir(self.local_dir, 'Choose download destination')
        if dest_dir is None:
            return
        self.local_dir = dest_dir
        dest  = join(dest_dir, safe)
        force = False

        if exists(dest):
            _warn(f'{name} already exists at destination.')
            print(col('  1  ', BOLD, CYAN) + 'Overwrite')
            print(col('  0  ', DIM)        + 'Cancel')
            if _ask() != '1':
                return
            force = True

        try:
            clear_sz = self.vault.size(vpath)
        except Exception:
            clear_sz = 0

        print(col(f'  Decrypting {_fmt_size(clear_sz)} …', DIM))

        try:
            if _HAS_TQDM and clear_sz > 0:
                out_dir = dirname(dest) or '.'
                os.makedirs(out_dir, exist_ok=True)
                fd2, tmp_dl = tempfile.mkstemp(dir=out_dir, prefix='.pymator-dl-')
                tmp_dl_ref  = tmp_dl
                try:
                    with os.fdopen(fd2, 'wb') as raw_f:
                        with _tqdm(
                            total      = clear_sz,
                            unit       = 'B',
                            unit_scale = True,
                            desc       = '  ',
                            leave      = False,
                            bar_format = _BAR_FMT,
                            file       = sys.stderr,
                        ) as bar:
                            self.vault.get_to_stream(vpath, _ProgressWriter(raw_f, bar))
                    fd2 = -1
                    if force:
                        os.replace(tmp_dl, dest)
                    else:
                        os.rename(tmp_dl, dest)
                    tmp_dl_ref = None
                finally:
                    if tmp_dl_ref is not None:
                        try:
                            os.unlink(tmp_dl_ref)
                        except OSError:
                            pass
            else:
                self.vault.get(vpath, dest, force=force)
            _ok(f'Saved to: {dest}')
        except Exception as e:
            _err(_friendly_error(e))
        _pause()


class Menu:

    def __init__(self):
        os.makedirs(VAULTS_DIR, exist_ok=True)

    def _get_vaults(self) -> List[Tuple[str, str]]:
        out = []
        try:
            for name in sorted(os.listdir(VAULTS_DIR)):
                path = join(VAULTS_DIR, name)
                if isdir(path) and exists(join(path, 'vault.cryptomator')):
                    out.append((name, path))
        except OSError:
            pass
        return out

    def run(self):
        while True:
            _clear()
            vaults = self._get_vaults()
            vault_hint = (
                f'{len(vaults)} vault{"s" if len(vaults) != 1 else ""}'
                if vaults else 'no vaults yet'
            )
            _header(f'pymator  v{__version__}', vault_hint)
            print(col('  1  ', BOLD, CYAN)   + 'Open')
            print(col('  2  ', BOLD, CYAN)   + 'Create')
            print(col('  3  ', BOLD, CYAN)   + 'Manage vault')
            print(col('  4  ', BOLD, CYAN)   + 'Help')
            print(col('  0  ', BOLD, YELLOW) + 'Exit')
            print()
            ch = _ask()
            if ch == '0':
                _clear()
                sys.exit(0)
            elif ch == '1':
                self._open_vault()
            elif ch == '2':
                self._create_vault()
            elif ch == '3':
                self._manage_menu()
            elif ch == '4':
                self._help()

    def _open_vault(self):
        while True:
            _clear()
            _header('Open Vault')
            vaults = self._get_vaults()
            if not vaults:
                _warn('No vaults found.')
                _pause()
                return
            for i, (name, _) in enumerate(vaults, 1):
                print(col(f'  {i:<3}', BOLD, CYAN) + name)
            print(col('  0  ', DIM) + 'Back')
            print()
            ch = _ask()
            if not ch or ch == '0':
                return
            try:
                n = int(ch)
                if n < 1 or n > len(vaults):
                    continue
            except ValueError:
                continue
            name, vault_dir = vaults[n - 1]
            pw = _ask_password(f'Password [{name}]: ')
            if not pw:
                continue
            print(col('  Unlocking…', DIM))
            try:
                vault = Vault(vault_dir, pw)
            except Exception as e:
                pw = None
                _err(_friendly_error(e))
                _pause()
                continue
            finally:
                pw = None
            try:
                Browser(vault, name).run()
            finally:
                vault.close()
            return

    def _create_vault(self):
        _clear()
        _header('Create Vault')
        name = _ask('Vault name: ')
        if not name:
            return
        name = _sanitize(name)
        if not name:
            _err('Invalid name.')
            _pause()
            return
        vault_dir = join(VAULTS_DIR, name)
        if exists(vault_dir):
            _err(f"'{name}' already exists.")
            _pause()
            return
        pw = _ask_password('New password: ')
        if not pw:
            return
        strength, scolor = _password_strength(pw)
        print(col('  Strength: ', DIM) + col(strength, scolor))
        pw2 = _ask_password('Confirm: ')
        if pw != pw2:
            pw = pw2 = None
            _err('Passwords do not match.')
            _pause()
            return
        pw2 = None
        print(col('  Generating keys…', DIM))
        try:
            os.makedirs(vault_dir)
            create_vault(vault_dir, pw)
        except Exception as e:
            shutil.rmtree(vault_dir, ignore_errors=True)
            pw = None
            _err(_friendly_error(e))
            _pause()
            return
        _ok(f"Vault '{name}' created.")
        print()
        print(col('  1  ', BOLD, CYAN) + 'Open')
        print(col('  0  ', DIM)        + 'Back')
        ch = _ask()
        if ch == '1':
            try:
                vault = Vault(vault_dir, pw)
            except Exception as e:
                pw = None
                _err(_friendly_error(e))
                _pause()
                return
            finally:
                pw = None
            try:
                Browser(vault, name).run()
            finally:
                vault.close()
        else:
            pw = None

    def _manage_menu(self):
        while True:
            _clear()
            _header('Manage Vault')
            vaults = self._get_vaults()
            if not vaults:
                _warn('No vaults found.')
                _pause()
                return
            for i, (name, _) in enumerate(vaults, 1):
                print(col(f'  {i:<3}', BOLD, CYAN) + name)
            print(col('  0  ', DIM) + 'Back')
            print()
            ch = _ask()
            if not ch or ch == '0':
                return
            try:
                n = int(ch)
                if n < 1 or n > len(vaults):
                    continue
            except ValueError:
                continue
            name, vault_dir = vaults[n - 1]
            self._vault_manage(name, vault_dir)
            return

    def _vault_manage(self, name: str, vault_dir: str):
        while True:
            _clear()
            _header(f'Manage: {name}')
            print(col('  1  ', BOLD, CYAN) + 'Change password')
            print(col('  2  ', BOLD, CYAN) + 'Rename vault')
            print(col('  3  ', BOLD, CYAN) + 'Backup vault (.zip)')
            print(col('  4  ', BOLD, RED)  + 'Delete vault')
            print(col('  0  ', DIM)        + 'Back')
            print()
            ch = _ask()
            if not ch or ch == '0':
                return
            elif ch == '1':
                self._change_password(name, vault_dir)
            elif ch == '2':
                result = self._rename_vault(name, vault_dir)
                if result:
                    name, vault_dir = result
            elif ch == '3':
                self._backup_vault(name, vault_dir)
            elif ch == '4':
                if self._delete_vault(name, vault_dir):
                    return

    def _change_password(self, name: str, vault_dir: str):
        pw = _ask_password(f'Current password [{name}]: ')
        if not pw:
            return
        print(col('  Verifying…', DIM))
        try:
            with Vault(vault_dir, pw) as vault:
                pw = None
                new_pw = _ask_password('New password: ')
                if not new_pw:
                    return
                strength, scolor = _password_strength(new_pw)
                print(col('  Strength: ', DIM) + col(strength, scolor))
                new_pw2 = _ask_password('Confirm: ')
                if new_pw != new_pw2:
                    new_pw = new_pw2 = None
                    _err('Passwords do not match.')
                    _pause()
                    return
                new_pw2 = None
                vault.change_password(new_pw)
                new_pw = None
                _ok('Password changed.')
        except Exception as e:
            _err(_friendly_error(e))
        finally:
            pw = None
        _pause()

    def _rename_vault(self, name: str, vault_dir: str) -> Optional[Tuple[str, str]]:
        pw = _ask_password(f'Password [{name}]: ')
        if not pw:
            return None
        print(col('  Verifying…', DIM))
        try:
            with Vault(vault_dir, pw) as _:
                pass
        except Exception as e:
            pw = None
            _err(_friendly_error(e))
            _pause()
            return None
        finally:
            pw = None

        new_name = _ask(f'New name [{name}]: ')
        if not new_name or new_name == name:
            return None
        new_name = _sanitize(new_name)
        if not new_name:
            _err('Invalid name.')
            _pause()
            return None
        new_path = join(VAULTS_DIR, new_name)
        if exists(new_path):
            _err(f"'{new_name}' already exists.")
            _pause()
            return None
        try:
            os.rename(vault_dir, new_path)
            _ok(f'Renamed → {new_name}')
            _pause()
            return new_name, new_path
        except Exception as e:
            _err(_friendly_error(e))
            _pause()
            return None

    def _backup_vault(self, name: str, vault_dir: str):
        dest_dir = _local_pick_dir(expanduser('~'), 'Choose backup destination')
        if dest_dir is None:
            return
        dest = join(dest_dir, f'{name}-backup.zip')
        print(col(f'  Output: {dest}', DIM))
        if exists(dest):
            _warn(f'{basename(dest)} already exists.')
            print(col('  1  ', BOLD, CYAN) + 'Overwrite')
            print(col('  0  ', DIM)        + 'Cancel')
            if _ask() != '1':
                return
        try:
            all_items = []
            for root, dirs, fnames in os.walk(vault_dir):
                rel_root = os.path.relpath(root, vault_dir)
                if rel_root != '.':
                    all_items.append((root, rel_root))
                for f in fnames:
                    full = join(root, f)
                    all_items.append((full, os.path.relpath(full, vault_dir)))
            if _HAS_TQDM:
                with _tqdm(
                    total      = len(all_items),
                    unit       = 'file',
                    desc       = '  ',
                    leave      = False,
                    bar_format = _FILE_FMT,
                    file       = sys.stderr,
                ) as bar:
                    with zipfile.ZipFile(dest, 'w', zipfile.ZIP_STORED) as zf:
                        for full, rel in all_items:
                            zf.write(full, rel)
                            bar.update(1)
            else:
                with zipfile.ZipFile(dest, 'w', zipfile.ZIP_STORED) as zf:
                    for full, rel in all_items:
                        zf.write(full, rel)
            _ok(f'Saved: {dest}  ({len(all_items)} items)')
        except Exception as e:
            _err(_friendly_error(e))
        _pause()

    def _delete_vault(self, name: str, vault_dir: str) -> bool:
        print()
        _warn(f"Delete '{name}'? irreversible.")
        pw = _ask_password(f'Password [{name}]: ')
        if not pw:
            _warn('Cancelled.')
            _pause()
            return False
        print(col('  Verifying…', DIM))
        try:
            with Vault(vault_dir, pw) as _:
                pass
        except Exception as e:
            pw = None
            _err(_friendly_error(e))
            _pause()
            return False
        finally:
            pw = None
        confirm = _ask('Type vault name to confirm: ')
        if confirm != name:
            _warn('Cancelled.')
            _pause()
            return False
        try:
            shutil.rmtree(vault_dir)
            _ok(f"Deleted: '{name}'")
        except Exception as e:
            _err(_friendly_error(e))
            _pause()
            return False
        _pause()
        return True

    def _help(self):
        _clear()
        _header('Help')
        sections = [
            ('Vault browser', [
                ('Number',         'Select folder to open, or file'),
                ('n',              'New folder at current location'),
                ('u',              'Upload & encrypt'),
                ('1,3,5 & all',    'File number to upload one'),
                ('g',              'Download & decrypt'),
                ('m',              'Move or rename'),
                ('/',              'Search recursively by name'),
                ('x',              'Delete a file or folder'),
                ('..',             'Go up to parent directory'),
                ('0',              'Lock & return to main menu'),
            ]),
            ('Vault management', [
                ('Create vault',    'In ~/pymator/'),
                ('Change password', 'Re-encrypts the master key'),
                ('Rename vault',    'Requires password & renames'),
                ('Backup vault',    'Exports entire vault as .zip'),
                ('Delete vault',    'Requires password + name'),
            ]),
            ('Format', [
                ('Cryptomator', 'v8'),
                ('Location',       '~/pymator/'),
            ]),
        ]
        for section, items in sections:
            print(col(f'  {section}', BOLD, CYAN))
            _hr()
            for k, v in items:
                print(f"  {col(k.ljust(20), BOLD, WHITE)}  {col(v, DIM)}")
            print()
        _pause()


def run_menu():
    Menu().run()


"""pymator — GPL-3.0"""
