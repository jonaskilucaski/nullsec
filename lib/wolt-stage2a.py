#!/usr/bin/python3
"""Wolt Stage 2A: strictly offline framed-evidence classification.

Trust boundary: processes with another non-root UID, repository files, input
evidence, and provider output are untrusted. Processes with this process's real
and effective UID are trusted. Root, the kernel, ptrace-capable processes, and
a compromised current account are out of scope. Snapshot sealing and a final
descriptor-relative identity rewalk protect the later validated pathname use.
"""

import ctypes
import datetime
import errno
import hashlib
import json
import os
import re
import secrets
import selectors
import stat
import subprocess
import sys
import time

EXIT_OK, EXIT_INTEGRITY, EXIT_INPUT, EXIT_SCHEMA = 0, 2, 3, 4
EXIT_CLASSIFIER, EXIT_PUBLICATION, EXIT_USAGE = 5, 6, 64
ERROR_TOKEN = {
    2: "STAGE2A_INTEGRITY_ERROR", 3: "STAGE2A_INPUT_ERROR",
    4: "STAGE2A_SCHEMA_ERROR", 5: "STAGE2A_CLASSIFIER_ERROR",
    6: "STAGE2A_PUBLICATION_ERROR", 64: "STAGE2A_USAGE_ERROR",
}
SOURCE_IDS = frozenset(("subfinder", "assetfinder", "amass", "virustotal", "shodan"))
SOURCE_ERRORS = frozenset(("COLLECTION_FAILED", "TIMEOUT", "TOOL_ERROR",
                           "OUTPUT_TRUNCATED", "CREDENTIAL_ERROR", "POLICY_BLOCKED"))
TOKENS = ("APPROVED_EXACT", "EXCLUDED", "PENDING_WILDCARD_REVIEW",
          "NON_WOLT", "MOBILE_ASSET", "MALFORMED")
TOKEN_SET = frozenset(TOKENS)
EXCLUSIONS = frozenset(("wolt.atlassian.net", "press.wolt.com", "links.wolt.com",
                        "gettest.wolt.com", "blog.wolt.com"))
DATA_FILES = ("approved-exact.txt", "wildcard-candidates-unreviewed.txt",
              "explicitly-excluded.txt", "rejected-non-wolt.txt",
              "rejected-mobile-assets.txt", "rejected-malformed.txt",
              "source-errors.txt", "provenance.tsv")
FINAL_FILES = frozenset(DATA_FILES + ("run-metadata.json", "COMPLETE"))
TOKEN_FILE = {"APPROVED_EXACT": DATA_FILES[0], "PENDING_WILDCARD_REVIEW": DATA_FILES[1],
              "EXCLUDED": DATA_FILES[2], "NON_WOLT": DATA_FILES[3],
              "MOBILE_ASSET": DATA_FILES[4]}
STAGE1_FILES = ("nullsec-wolt.sh", "config/wolt-approved-exact.txt",
                "config/wolt-excluded.txt", "config/wolt-mobile-assets.txt",
                "config/wolt-policy.json")
STAGE1_LIMITS = {"nullsec-wolt.sh": 1024 * 1024,
                 "config/wolt-approved-exact.txt": 65536,
                 "config/wolt-excluded.txt": 65536,
                 "config/wolt-mobile-assets.txt": 65536,
                 "config/wolt-policy.json": 1024 * 1024}
MAX_INPUT = 8 * 1024 * 1024
MAX_RECORDS = 100000
MAX_RECORD_BYTES = 4096
MAX_CLASSIFIER_OUTPUT = 4 * 1024 * 1024
CLASSIFIER_TIMEOUT = 120
RUN_RE = re.compile(r"^[0-9]{8}T[0-9]{6}\.[0-9]{9}Z-[0-9a-f]{16}$", re.ASCII)
SHA_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)


class Failure(Exception):
    def __init__(self, code, reason, source=None):
        super().__init__(reason)
        self.code, self.reason, self.source = code, reason, source


def abort(code, reason, source=None):
    raise Failure(code, reason, source)


def verify_identity(ops=os):
    if ops.getuid() != ops.geteuid(): abort(EXIT_INTEGRITY, "UID_MISMATCH")
    if ops.getgid() != ops.getegid(): abort(EXIT_INTEGRITY, "GID_MISMATCH")


def duplicate_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError("duplicate")
        result[key] = value
    return result


def parse_json(data, code, reason):
    if b"\0" in data: abort(code, reason + "_NUL")
    try:
        return json.loads(data.decode("utf-8", "strict"), object_pairs_hook=duplicate_object,
                          parse_constant=lambda _x: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, ValueError, json.JSONDecodeError):
        abort(code, reason + "_JSON")


def unsafe_mode(mode):
    return bool(mode & (stat.S_IWGRP | stat.S_IWOTH))


def identity_tuple(st):
    return (st.st_dev, st.st_ino, st.st_size, stat.S_IFMT(st.st_mode), st.st_uid,
            stat.S_IMODE(st.st_mode), st.st_mtime_ns, st.st_ctime_ns)


def validate_regular(st, code, reason, exact_mode=None):
    if not stat.S_ISREG(st.st_mode): abort(code, reason + "_TYPE")
    if st.st_uid != os.getuid(): abort(code, reason + "_OWNER")
    if unsafe_mode(st.st_mode): abort(code, reason + "_MODE")
    if exact_mode is not None and stat.S_IMODE(st.st_mode) != exact_mode:
        abort(code, reason + "_EXACT_MODE")


def open_dir_absolute(path, code, reason):
    if not os.path.isabs(path): abort(code, reason + "_ABSOLUTE")
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open("/", flags)
    try:
        for part in (p for p in path.split("/") if p):
            if part in (".", ".."): abort(code, reason + "_TRAVERSAL")
            newfd = os.open(part, flags, dir_fd=fd)
            os.close(fd); fd = newfd
        return fd
    except BaseException:
        os.close(fd); raise


def open_trusted_ancestor_chain(path, code=EXIT_INTEGRITY, reason="ANCESTOR", ops=os,
                                retain_parent=False):
    """Open and validate every directory from / through path without symlinks."""
    if not os.path.isabs(path): abort(code, reason + "_ABSOLUTE")
    flags = ops.O_RDONLY | ops.O_DIRECTORY | getattr(ops, "O_CLOEXEC", 0) | getattr(ops, "O_NOFOLLOW", 0)
    try: fd = ops.open("/", flags)
    except OSError: abort(code, reason + "_OPEN")
    parent_fd = None
    try:
        components = [""] + [part for part in path.split("/") if part]
        for index, part in enumerate(components):
            if part in (".", ".."): abort(code, reason + "_TRAVERSAL")
            if index:
                try: newfd = ops.open(part, flags, dir_fd=fd)
                except OSError: abort(code, reason + "_OPEN")
                if retain_parent and index == len(components) - 1:
                    parent_fd = fd
                else: ops.close(fd)
                fd = newfd
            try: st = ops.fstat(fd)
            except OSError: abort(code, reason + "_STAT")
            if (not stat.S_ISDIR(st.st_mode) or st.st_uid not in (0, ops.geteuid()) or
                    unsafe_mode(st.st_mode)):
                abort(code, reason + "_TRUST")
        return (fd, parent_fd, components[-1]) if retain_parent else fd
    except BaseException:
        ops.close(fd)
        if parent_fd is not None:
            try: ops.close(parent_fd)
            except OSError: pass
        raise


def open_file_absolute(path, code, reason):
    parent, name = os.path.split(path)
    if not os.path.isabs(path) or not name or name in (".", ".."):
        abort(code, reason + "_PATH")
    dfd = open_dir_absolute(parent, code, reason + "_PARENT")
    try:
        fd = os.open(name, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
                     getattr(os, "O_NOFOLLOW", 0), dir_fd=dfd)
    except BaseException:
        os.close(dfd); raise
    os.close(dfd)
    return fd


def read_fd_verified(fd, limit, code, reason, ops=os):
    before = ops.fstat(fd)
    validate_regular(before, code, reason)
    if before.st_size > limit: abort(code, reason + "_TOO_LARGE")
    pieces, total = [], 0
    while True:
        chunk = ops.read(fd, min(65536, limit + 1 - total))
        if not chunk: break
        total += len(chunk)
        if total > limit: abort(code, reason + "_TOO_LARGE")
        pieces.append(chunk)
    after = ops.fstat(fd)
    validate_regular(after, code, reason)
    if identity_tuple(before) != identity_tuple(after) or total != after.st_size:
        abort(code, reason + "_CHANGED")
    return b"".join(pieces), before


def read_path_verified(path, limit, code, reason):
    try: fd = open_file_absolute(path, code, reason)
    except Failure: raise
    except OSError: abort(code, reason + "_OPEN")
    try: return read_fd_verified(fd, limit, code, reason)
    finally: os.close(fd)


def validate_envelope(cli_source, data):
    value = parse_json(data, EXIT_SCHEMA, "ENVELOPE")
    if not isinstance(value, dict): abort(EXIT_SCHEMA, "ENVELOPE_TYPE", cli_source)
    status = value.get("collection_status")
    common = {"schema_version", "source_id", "collection_status", "record_count", "records"}
    expected = common if status == "success" else common | {"error_code"} if status == "failed" else set()
    if not expected or set(value) != expected: abort(EXIT_SCHEMA, "ENVELOPE_KEYS", cli_source)
    if value["schema_version"] != 1: abort(EXIT_SCHEMA, "ENVELOPE_VERSION", cli_source)
    if value["source_id"] != cli_source: abort(EXIT_SCHEMA, "SOURCE_MISMATCH", cli_source)
    count, records = value["record_count"], value["records"]
    if isinstance(count, bool) or not isinstance(count, int) or count < 0 or count > MAX_RECORDS:
        abort(EXIT_SCHEMA, "RECORD_COUNT", cli_source)
    if not isinstance(records, list) or len(records) > MAX_RECORDS:
        abort(EXIT_SCHEMA, "RECORDS", cli_source)
    if status == "failed":
        if value["error_code"] not in SOURCE_ERRORS: abort(EXIT_SCHEMA, "ERROR_CODE", cli_source)
        if count != 0 or records: abort(EXIT_SCHEMA, "FAILED_RECORDS", cli_source)
        abort(EXIT_SCHEMA, value["error_code"], cli_source)
    if count != len(records): abort(EXIT_SCHEMA, "COUNT_MISMATCH", cli_source)
    for record in records:
        if not isinstance(record, str): abort(EXIT_SCHEMA, "RECORD_TYPE", cli_source)
        try: encoded = record.encode("ascii", "strict")
        except UnicodeError: abort(EXIT_SCHEMA, "RECORD_ASCII", cli_source)
        if len(encoded) > MAX_RECORD_BYTES: abort(EXIT_SCHEMA, "RECORD_LENGTH", cli_source)
        if any(c in record for c in ("\0", "\r", "\n")):
            abort(EXIT_SCHEMA, "RECORD_CONTROL", cli_source)
    return records


def parse_cli(argv):
    repo = launcher = root = validate = None; imports = []; help_requested = False; i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in ("--repository", "--launcher", "--evidence-root", "--validate-run"):
            if i + 1 >= len(argv): abort(EXIT_USAGE, "ARGUMENT")
            val = argv[i + 1]; i += 2
            if arg == "--repository" and repo is None: repo = val
            elif arg == "--launcher" and launcher is None: launcher = val
            elif arg == "--evidence-root" and root is None: root = val
            elif arg == "--validate-run" and validate is None: validate = val
            else: abort(EXIT_USAGE, "DUPLICATE_ARGUMENT")
        elif arg == "--import-source":
            if i + 2 >= len(argv): abort(EXIT_USAGE, "IMPORT_ARGUMENT")
            imports.append((argv[i + 1], argv[i + 2])); i += 3
        elif arg == "--help":
            if help_requested: abort(EXIT_USAGE, "DUPLICATE_ARGUMENT")
            help_requested = True; i += 1
        else: abort(EXIT_USAGE, "UNKNOWN_ARGUMENT")
    if not repo or not launcher or not os.path.isabs(repo) or not os.path.isabs(launcher):
        abort(EXIT_INTEGRITY, "LAUNCH_CONTEXT")
    if help_requested:
        if root or imports or validate: abort(EXIT_USAGE, "HELP_ARGUMENT")
        return {"mode": "help", "repo": repo, "launcher": launcher}
    if validate:
        if root or imports or not os.path.isabs(validate): abort(EXIT_USAGE, "VALIDATE_ARGUMENT")
        return {"mode": "validate", "repo": repo, "launcher": launcher, "run": validate}
    if not root or not os.path.isabs(root) or not imports: abort(EXIT_USAGE, "PROCESS_ARGUMENT")
    seen = set()
    for sid, path in imports:
        if sid not in SOURCE_IDS: abort(EXIT_SCHEMA, "SOURCE_ID")
        if sid in seen: abort(EXIT_SCHEMA, "SOURCE_DUPLICATE", sid)
        if not os.path.isabs(path): abort(EXIT_INPUT, "INPUT_ABSOLUTE", sid)
        seen.add(sid)
    return {"mode": "process", "repo": repo, "launcher": launcher, "root": root, "imports": imports}


def verify_program(cfg):
    expected_launcher = os.path.join(cfg["repo"], "nullsec-wolt-stage2a.sh")
    core = os.path.join(cfg["repo"], "lib", "wolt-stage2a.py")
    if cfg["launcher"] != expected_launcher: abort(EXIT_INTEGRITY, "LAUNCHER_PATH")
    result = {}
    for key, path, limit in (("launcher_sha256", expected_launcher, 1024 * 1024),
                             ("python_core_sha256", core, 4 * 1024 * 1024)):
        data, st = read_path_verified(path, limit, EXIT_INTEGRITY, "PROGRAM")
        result[key] = hashlib.sha256(data).hexdigest()
        if key == "launcher_sha256" and not st.st_mode & stat.S_IXUSR:
            abort(EXIT_INTEGRITY, "LAUNCHER_EXECUTABLE")
    h = hashlib.sha256()
    for key in ("launcher_sha256", "python_core_sha256"):
        h.update(key.encode() + b"\0" + result[key].encode() + b"\n")
    result["aggregate_program_sha256"] = h.hexdigest()
    return result


def load_integrity(repo):
    path = os.path.join(repo, "config", "wolt-stage2a-integrity.json")
    data, _ = read_path_verified(path, 65536, EXIT_INTEGRITY, "MANIFEST")
    obj = parse_json(data, EXIT_INTEGRITY, "MANIFEST")
    if not isinstance(obj, dict) or set(obj) != {"schema_version", "aggregate_algorithm", "stage1_files"}:
        abort(EXIT_INTEGRITY, "MANIFEST_KEYS")
    if obj["schema_version"] != 1 or obj["aggregate_algorithm"] != "named-sha256-v1":
        abort(EXIT_INTEGRITY, "MANIFEST_VALUES")
    if not isinstance(obj["stage1_files"], dict) or set(obj["stage1_files"]) != set(STAGE1_FILES):
        abort(EXIT_INTEGRITY, "MANIFEST_FILES")
    for digest in obj["stage1_files"].values():
        if not isinstance(digest, str) or not SHA_RE.fullmatch(digest): abort(EXIT_INTEGRITY, "MANIFEST_DIGEST")
    return obj["stage1_files"]


def create_file(dfd, name, data, mode, code=EXIT_PUBLICATION):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try: fd = os.open(name, flags, mode, dir_fd=dfd)
    except OSError: abort(code, "CREATE_FILE")
    try:
        sent = 0
        while sent < len(data):
            n = os.write(fd, data[sent:])
            if n <= 0: abort(code, "WRITE_FILE")
            sent += n
        os.fsync(fd)
    except OSError: abort(code, "WRITE_FSYNC")
    finally: os.close(fd)


def create_run(root_fd):
    ns = time.time_ns(); sec, nano = divmod(ns, 1000000000)
    stamp = datetime.datetime.fromtimestamp(sec, datetime.timezone.utc).strftime("%Y%m%dT%H%M%S") + f".{nano:09d}Z"
    started = datetime.datetime.fromtimestamp(sec, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + f".{nano:09d}Z"
    run_id = stamp + "-" + secrets.token_hex(8); incomplete = "INCOMPLETE-" + run_id
    try: os.mkdir(incomplete, 0o700, dir_fd=root_fd)
    except OSError: abort(EXIT_PUBLICATION, "RUN_CREATE")
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try: fd = os.open(incomplete, flags, dir_fd=root_fd)
    except OSError: abort(EXIT_PUBLICATION, "RUN_OPEN")
    return {"id": run_id, "name": incomplete, "fd": fd, "started": started}


def snapshot_stage1(repo, run_fd, manifest, records_by_source):
    try:
        os.mkdir(".stage1-runtime", 0o700, dir_fd=run_fd)
        sfd = os.open(".stage1-runtime", os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0), dir_fd=run_fd)
        os.mkdir("config", 0o700, dir_fd=sfd)
        cfd = os.open("config", os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0), dir_fd=sfd)
    except OSError: abort(EXIT_PUBLICATION, "SNAPSHOT_CREATE")
    verified = {}
    try:
        for name in STAGE1_FILES:
            data, _ = read_path_verified(os.path.join(repo, *name.split("/")), STAGE1_LIMITS[name],
                                         EXIT_INTEGRITY, "STAGE1")
            digest = hashlib.sha256(data).hexdigest()
            if digest != manifest[name]: abort(EXIT_INTEGRITY, "STAGE1_DIGEST")
            verified[name] = digest
            if name == "nullsec-wolt.sh": create_file(sfd, name, data, 0o500)
            else: create_file(cfd, name.split("/")[-1], data, 0o400)
        lines = []
        positions = []
        for sid in sorted(records_by_source):
            for ordinal, record in enumerate(records_by_source[sid], 1):
                lines.append(record.encode("ascii") + b"\n"); positions.append((sid, ordinal, record))
        create_file(sfd, "classifier-input.txt", b"".join(lines), 0o400)
        os.fsync(cfd); os.fsync(sfd)
        os.fchmod(cfd, 0o500); os.fchmod(sfd, 0o500); os.fsync(run_fd)
        verify_snapshot(sfd, cfd, verified, len(positions))
        return {"sfd": sfd, "cfd": cfd, "positions": positions, "digests": verified,
                "s_identity": descriptor_identity(os.fstat(sfd)),
                "wrapper_identity": snapshot_entry_identity(sfd, "nullsec-wolt.sh"),
                "input_identity": snapshot_entry_identity(sfd, "classifier-input.txt")}
    except BaseException:
        os.close(cfd); os.close(sfd); raise


def read_snapshot_file(dfd, name, mode, limit):
    try: fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=dfd)
    except OSError: abort(EXIT_INTEGRITY, "SNAPSHOT_OPEN")
    try:
        data, st = read_fd_verified(fd, limit, EXIT_INTEGRITY, "SNAPSHOT")
        validate_regular(st, EXIT_INTEGRITY, "SNAPSHOT", mode)
        return data
    finally: os.close(fd)


def verify_snapshot(sfd, cfd, expected, record_count):
    sst, cst = os.fstat(sfd), os.fstat(cfd)
    if (not stat.S_ISDIR(sst.st_mode) or not stat.S_ISDIR(cst.st_mode) or
        sst.st_uid != os.getuid() or cst.st_uid != os.getuid() or
        stat.S_IMODE(sst.st_mode) != 0o500 or stat.S_IMODE(cst.st_mode) != 0o500):
        abort(EXIT_INTEGRITY, "SNAPSHOT_DIRECTORY_MODE")
    try: config_at = os.stat("config", dir_fd=sfd, follow_symlinks=False)
    except OSError: abort(EXIT_INTEGRITY, "SNAPSHOT_CONFIG_DIRECTORY")
    if (not stat.S_ISDIR(config_at.st_mode) or config_at.st_dev != cst.st_dev or
        config_at.st_ino != cst.st_ino or config_at.st_uid != os.getuid() or
        stat.S_IMODE(config_at.st_mode) != 0o500):
        abort(EXIT_INTEGRITY, "SNAPSHOT_CONFIG_DIRECTORY")
    if set(os.listdir(sfd)) != {"nullsec-wolt.sh", "classifier-input.txt", "config"}:
        abort(EXIT_INTEGRITY, "SNAPSHOT_INVENTORY")
    if set(os.listdir(cfd)) != {n.split("/")[-1] for n in STAGE1_FILES[1:]}:
        abort(EXIT_INTEGRITY, "SNAPSHOT_CONFIG_INVENTORY")
    wrapper = read_snapshot_file(sfd, "nullsec-wolt.sh", 0o500, STAGE1_LIMITS["nullsec-wolt.sh"])
    if hashlib.sha256(wrapper).hexdigest() != expected["nullsec-wolt.sh"]: abort(EXIT_INTEGRITY, "SNAPSHOT_DIGEST")
    for name in STAGE1_FILES[1:]:
        data = read_snapshot_file(cfd, name.split("/")[-1], 0o400, STAGE1_LIMITS[name])
        if hashlib.sha256(data).hexdigest() != expected[name]: abort(EXIT_INTEGRITY, "SNAPSHOT_DIGEST")
    inp = read_snapshot_file(sfd, "classifier-input.txt", 0o400, MAX_INPUT * len(SOURCE_IDS))
    if len(inp.splitlines()) != record_count: abort(EXIT_INTEGRITY, "SNAPSHOT_RECORD_COUNT")


def descriptor_identity(st):
    return (st.st_dev, st.st_ino, stat.S_IFMT(st.st_mode), st.st_uid, stat.S_IMODE(st.st_mode))


def snapshot_entry_identity(dfd, name):
    try: st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
    except OSError: abort(EXIT_INTEGRITY, "SNAPSHOT_IDENTITY")
    return descriptor_identity(st)


def final_classifier_rewalk(root_fd, run, snap):
    """Re-open the launch objects relative to validated descriptors and match identities."""
    dflags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fflags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    opened = []
    try:
        if descriptor_identity(os.fstat(root_fd)) != run["root_identity"]:
            abort(EXIT_INTEGRITY, "LAUNCH_ROOT_IDENTITY")
        current_root = os.open(run["root_name"], dflags, dir_fd=run["root_parent_fd"]); opened.append(current_root)
        if descriptor_identity(os.fstat(current_root)) != run["root_identity"]:
            abort(EXIT_INTEGRITY, "LAUNCH_ROOT_IDENTITY")
        rfd = os.open(run["name"], dflags, dir_fd=current_root); opened.append(rfd)
        if descriptor_identity(os.fstat(rfd)) != run["identity"]:
            abort(EXIT_INTEGRITY, "LAUNCH_RUN_IDENTITY")
        sfd = os.open(".stage1-runtime", dflags, dir_fd=rfd); opened.append(sfd)
        if descriptor_identity(os.fstat(sfd)) != snap["s_identity"]:
            abort(EXIT_INTEGRITY, "LAUNCH_RUNTIME_IDENTITY")
        for name, expected, mode in (("nullsec-wolt.sh", snap["wrapper_identity"], 0o500),
                                     ("classifier-input.txt", snap["input_identity"], 0o400)):
            fd = os.open(name, fflags, dir_fd=sfd); opened.append(fd)
            st = os.fstat(fd)
            validate_regular(st, EXIT_INTEGRITY, "LAUNCH_FILE", mode)
            if descriptor_identity(st) != expected:
                abort(EXIT_INTEGRITY, "LAUNCH_FILE_IDENTITY")
    except Failure:
        raise
    except OSError:
        abort(EXIT_INTEGRITY, "LAUNCH_REWALK")
    finally:
        for fd in reversed(opened):
            try: os.close(fd)
            except OSError: pass


def bounded_process(argv, timeout=CLASSIFIER_TIMEOUT, limit=MAX_CLASSIFIER_OUTPUT, popen=subprocess.Popen):
    try:
        proc = popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                     env={"LC_ALL": "C"}, shell=False)
    except OSError: abort(EXIT_CLASSIFIER, "CLASSIFIER_MISSING")
    selector = selectors.DefaultSelector(); out = bytearray(); err = bytearray()
    selector.register(proc.stdout, selectors.EVENT_READ, out); selector.register(proc.stderr, selectors.EVENT_READ, err)
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                proc.kill(); proc.wait(); abort(EXIT_CLASSIFIER, "CLASSIFIER_TIMEOUT")
            for key, _ in selector.select(remaining):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk: selector.unregister(key.fileobj); continue
                key.data.extend(chunk)
                if len(out) + len(err) > limit:
                    proc.kill(); proc.wait(); abort(EXIT_CLASSIFIER, "CLASSIFIER_OUTPUT_LIMIT")
        rc = proc.wait(timeout=max(0.0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        proc.kill(); proc.wait(); abort(EXIT_CLASSIFIER, "CLASSIFIER_TIMEOUT")
    finally:
        selector.close()
        if proc.stdout is not None: proc.stdout.close()
        if proc.stderr is not None: proc.stderr.close()
    return rc, bytes(out), bytes(err)


def validate_classifier_result(rc, stdout, stderr, count):
    if rc not in (0, 20): abort(EXIT_CLASSIFIER, "CLASSIFIER_STATUS")
    if stderr: abort(EXIT_CLASSIFIER, "CLASSIFIER_STDERR")
    if stdout and not stdout.endswith(b"\n"): abort(EXIT_CLASSIFIER, "CLASSIFIER_TERMINATION")
    try: tokens = stdout.decode("ascii", "strict").splitlines()
    except UnicodeError: abort(EXIT_CLASSIFIER, "CLASSIFIER_ENCODING")
    if len(tokens) != count: abort(EXIT_CLASSIFIER, "CLASSIFIER_COUNT")
    if any(t not in TOKEN_SET for t in tokens): abort(EXIT_CLASSIFIER, "CLASSIFIER_TOKEN")
    if (rc == 0) != all(t == "APPROVED_EXACT" for t in tokens): abort(EXIT_CLASSIFIER, "CLASSIFIER_STATUS_TOKENS")
    return tokens


def cleanup_snapshot(run_fd, snap):
    sfd, cfd = snap["sfd"], snap["cfd"]
    try:
        os.fchmod(sfd, 0o700); os.fchmod(cfd, 0o700)
        os.unlink("classifier-input.txt", dir_fd=sfd)
        os.unlink("nullsec-wolt.sh", dir_fd=sfd)
        for name in (n.split("/")[-1] for n in STAGE1_FILES[1:]): os.unlink(name, dir_fd=cfd)
        os.close(cfd); snap["cfd"] = -1
        os.rmdir("config", dir_fd=sfd)
        os.close(sfd); snap["sfd"] = -1
        os.rmdir(".stage1-runtime", dir_fd=run_fd)
        os.fsync(run_fd)
    except OSError: abort(EXIT_PUBLICATION, "SNAPSHOT_CLEANUP")


def aggregate(positions, tokens):
    cats = {name: set() for name in DATA_FILES[:5]}; malformed = set(); provenance = set()
    counts = {t: 0 for t in TOKENS}
    for (sid, ordinal, raw), token in zip(positions, tokens):
        canonical = raw.lower(); canonical = canonical[:-1] if canonical.endswith(".") else canonical
        if canonical in EXCLUSIONS: token = "EXCLUDED"
        counts[token] += 1
        if token == "MALFORMED": malformed.add((sid, ordinal)); continue
        cats[TOKEN_FILE[token]].add(canonical); provenance.add((canonical, token, sid))
    out = {name: "".join(x + "\n" for x in sorted(cats[name])).encode("ascii") for name in DATA_FILES[:5]}
    out[DATA_FILES[5]] = "".join(f"{s}\t{o}\tMALFORMED\n" for s, o in sorted(malformed)).encode("ascii")
    out[DATA_FILES[6]] = b""
    out[DATA_FILES[7]] = ("hostname\tclassification\tsource_id\n" +
                          "".join(f"{h}\t{t}\t{s}\n" for h, t, s in sorted(provenance))).encode("ascii")
    return out, counts


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                       separators=(",", ":")) + "\n").encode("ascii")


def rename_noreplace(root_fd, source, destination, libc=None):
    lib = libc or ctypes.CDLL(None, use_errno=True); fn = getattr(lib, "renameat2", None)
    if fn is None: abort(EXIT_PUBLICATION, "RENAME_UNAVAILABLE")
    fn.restype = ctypes.c_int
    if fn(root_fd, source.encode(), root_fd, destination.encode(), 1) != 0:
        number = ctypes.get_errno()
        abort(EXIT_PUBLICATION, "RENAME_EXDEV" if number == errno.EXDEV else
              "RENAME_EXISTS" if number == errno.EEXIST else "RENAME_FAILED")


def publish(root_fd, run, outputs, metadata):
    if os.listdir(run["fd"]): abort(EXIT_PUBLICATION, "PREOUTPUT_INVENTORY")
    for name in DATA_FILES: create_file(run["fd"], name, outputs[name], 0o600)
    if set(os.listdir(run["fd"])) != set(DATA_FILES): abort(EXIT_PUBLICATION, "DATA_INVENTORY")
    create_file(run["fd"], "run-metadata.json", json_bytes(metadata), 0o600)
    create_file(run["fd"], "COMPLETE", b"", 0o600)
    os.fsync(run["fd"])
    rename_noreplace(root_fd, run["name"], run["id"])
    try: os.fsync(root_fd)
    except OSError: abort(EXIT_PUBLICATION, "ROOT_FSYNC_AFTER_RENAME")


def metadata_schema(value, run_id):
    keys = {"schema_version", "run_id", "started_at_utc", "completed_at_utc", "completion_state",
            "approved_source_ids", "per_source_status", "per_source_record_counts",
            "classification_counts", "launcher_sha256", "python_core_sha256",
            "aggregate_program_sha256", "stage1_policy_sha256", "output_files"}
    if not isinstance(value, dict) or set(value) != keys or value.get("schema_version") != 1 or \
       value.get("run_id") != run_id or value.get("completion_state") != "COMPLETE": return False
    for key in ("started_at_utc", "completed_at_utc"):
        if not isinstance(value.get(key), str) or not value[key]: return False
    for key in ("launcher_sha256", "python_core_sha256", "aggregate_program_sha256", "stage1_policy_sha256"):
        if not isinstance(value.get(key), str) or not SHA_RE.fullmatch(value[key]): return False
    sources = value.get("approved_source_ids")
    if (not isinstance(sources, list) or sources != sorted(sources) or
        len(sources) != len(set(sources)) or any(source not in SOURCE_IDS for source in sources)):
        return False
    statuses, source_counts = value.get("per_source_status"), value.get("per_source_record_counts")
    if (not isinstance(statuses, dict) or not isinstance(source_counts, dict) or
        set(statuses) != set(sources) or set(source_counts) != set(sources) or
        any(status != "success" for status in statuses.values()) or
        any(isinstance(count, bool) or not isinstance(count, int) or count < 0 or count > MAX_RECORDS
            for count in source_counts.values())):
        return False
    class_counts = value.get("classification_counts")
    if (not isinstance(class_counts, dict) or set(class_counts) != TOKEN_SET or
        any(isinstance(count, bool) or not isinstance(count, int) or count < 0
            for count in class_counts.values())):
        return False
    if set(value.get("output_files", {})) != set(DATA_FILES): return False
    for name, entry in value["output_files"].items():
        if not isinstance(entry, dict) or set(entry) != {"byte_size", "sha256"}: return False
        if isinstance(entry["byte_size"], bool) or not isinstance(entry["byte_size"], int) or entry["byte_size"] < 0: return False
        if not isinstance(entry["sha256"], str) or not SHA_RE.fullmatch(entry["sha256"]): return False
    return True


def validate_run(path):
    parent, run_id = os.path.split(path.rstrip("/"))
    if not RUN_RE.fullmatch(run_id) or run_id.startswith("INCOMPLETE-"): abort(EXIT_PUBLICATION, "RUN_NAME")
    pfd = open_dir_absolute(parent, EXIT_PUBLICATION, "RUN_PARENT")
    pst = os.fstat(pfd)
    if not stat.S_ISDIR(pst.st_mode) or pst.st_uid != os.getuid() or unsafe_mode(pst.st_mode):
        os.close(pfd); abort(EXIT_PUBLICATION, "RUN_PARENT_TRUST")
    try:
        rfd = os.open(run_id, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0), dir_fd=pfd)
    except OSError:
        os.close(pfd); abort(EXIT_PUBLICATION, "RUN_OPEN")
    os.close(pfd)
    try:
        rst = os.fstat(rfd)
        if (not stat.S_ISDIR(rst.st_mode) or rst.st_uid != os.getuid() or
            stat.S_IMODE(rst.st_mode) != 0o700):
            abort(EXIT_PUBLICATION, "RUN_DIRECTORY_TRUST")
        if set(os.listdir(rfd)) != FINAL_FILES: abort(EXIT_PUBLICATION, "RUN_INVENTORY")
        def read_local(name, limit):
            try:
                fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=rfd)
            except OSError:
                abort(EXIT_PUBLICATION, "RUN_FILE_OPEN")
            try: return read_fd_verified(fd, limit, EXIT_PUBLICATION, "RUN_FILE")[0]
            finally: os.close(fd)
        complete = read_local("COMPLETE", 1)
        if complete: abort(EXIT_PUBLICATION, "COMPLETE_SIZE")
        metadata = parse_json(read_local("run-metadata.json", 1024 * 1024), EXIT_PUBLICATION, "METADATA")
        if not metadata_schema(metadata, run_id): abort(EXIT_PUBLICATION, "METADATA_SCHEMA")
        for name in DATA_FILES:
            data = read_local(name, MAX_INPUT * 8)
            expected = metadata["output_files"][name]
            if len(data) != expected["byte_size"] or hashlib.sha256(data).hexdigest() != expected["sha256"]:
                abort(EXIT_PUBLICATION, "OUTPUT_DIGEST")
    finally: os.close(rfd)


def process(cfg, program, manifest):
    root_fd, root_parent_fd, root_name = open_trusted_ancestor_chain(cfg["root"], retain_parent=True)
    rst = os.fstat(root_fd)
    if rst.st_uid != os.getuid():
        os.close(root_fd)
        if root_parent_fd is not None: os.close(root_parent_fd)
        abort(EXIT_INTEGRITY, "ROOT_OWNER")
    try: run = create_run(root_fd)
    except BaseException:
        os.close(root_fd)
        if root_parent_fd is not None: os.close(root_parent_fd)
        raise
    snap = None
    run["root_identity"] = descriptor_identity(rst)
    run["root_parent_fd"] = root_parent_fd
    run["root_name"] = root_name
    run["identity"] = descriptor_identity(os.fstat(run["fd"]))
    try:
        records = {}; source_counts = {}
        for sid, path in cfg["imports"]:
            try:
                data, _ = read_path_verified(path, MAX_INPUT, EXIT_INPUT, "EVIDENCE")
                records[sid] = validate_envelope(sid, data)
                source_counts[sid] = len(records[sid])
            except Failure as exc:
                reason = re.sub(r"[^A-Z0-9_]", "_", exc.reason)[:80]
                create_file(run["fd"], "source-errors.txt", f"{sid}\t{reason}\n".encode("ascii"), 0o600)
                os.fsync(run["fd"])
                raise
        snap = snapshot_stage1(cfg["repo"], run["fd"], manifest, records)
        if snap["positions"]:
            final_classifier_rewalk(root_fd, run, snap)
            base = os.path.join(cfg["root"], run["name"], ".stage1-runtime")
            rc, stdout, stderr = bounded_process(["/bin/bash", os.path.join(base, "nullsec-wolt.sh"),
                                                  "--classify-file", os.path.join(base, "classifier-input.txt")])
            tokens = validate_classifier_result(rc, stdout, stderr, len(snap["positions"]))
        else: tokens = []
        cleanup_snapshot(run["fd"], snap)
        outputs, counts = aggregate(snap["positions"], tokens)
        _, completed = (lambda ns: (ns, datetime.datetime.fromtimestamp(ns // 1000000000, datetime.timezone.utc)
                                    .strftime("%Y-%m-%dT%H:%M:%S") + f".{ns % 1000000000:09d}Z"))(time.time_ns())
        h = hashlib.sha256()
        for name in STAGE1_FILES: h.update(name.encode() + b"\0" + manifest[name].encode() + b"\n")
        meta = {"schema_version": 1, "run_id": run["id"], "started_at_utc": run["started"],
                "completed_at_utc": completed, "completion_state": "COMPLETE",
                "approved_source_ids": sorted(records),
                "per_source_status": {s: "success" for s in sorted(records)},
                "per_source_record_counts": {s: source_counts[s] for s in sorted(records)},
                "classification_counts": {t: counts[t] for t in sorted(TOKENS)},
                **program, "stage1_policy_sha256": h.hexdigest(),
                "output_files": {n: {"byte_size": len(outputs[n]), "sha256": hashlib.sha256(outputs[n]).hexdigest()}
                                 for n in DATA_FILES}}
        publish(root_fd, run, outputs, meta)
    finally:
        if snap:
            for key in ("cfd", "sfd"):
                if snap.get(key, -1) >= 0:
                    try: os.close(snap[key])
                    except OSError: pass
        os.close(run["fd"]); os.close(root_fd)
        if root_parent_fd is not None: os.close(root_parent_fd)


def help_text():
    return ("Usage: nullsec-wolt-stage2a.sh --evidence-root ABSOLUTE_DIR "
            "--import-source SOURCE_ID ABSOLUTE_JSON [...]\n"
            "       nullsec-wolt-stage2a.sh --validate-run ABSOLUTE_RUN\n"
            "Offline only. Source IDs are provenance labels, never executable providers.\n"
            "Invoke the executable launcher directly; plain Bash/source invocation is unsupported.\n"
        "Same-UID processes are trusted. Classifier launch uses a final descriptor identity rewalk.\n"
            "Every INCOMPLETE-* directory is non-consumable, even if COMPLETE exists.\n")


def main(argv=None):
    try: verify_identity()
    except Failure as exc:
        sys.stderr.write(ERROR_TOKEN[exc.code] + "\n"); return exc.code
    try:
        cfg = parse_cli(sys.argv[1:] if argv is None else argv)
        program = verify_program(cfg); manifest = load_integrity(cfg["repo"])
        if cfg["mode"] == "help": sys.stdout.write(help_text())
        elif cfg["mode"] == "validate": validate_run(cfg["run"])
        else: process(cfg, program, manifest)
        return 0
    except Failure as exc:
        sys.stderr.write(ERROR_TOKEN.get(exc.code, "STAGE2A_INTERNAL_ERROR") + "\n"); return exc.code
    except BaseException:
        sys.stderr.write("STAGE2A_INTERNAL_ERROR\n"); return EXIT_INTEGRITY


if __name__ == "__main__": raise SystemExit(main())
