#!/usr/bin/python3
"""Wolt Stage 2B Phase 1: strictly offline retained-evidence adapters."""

import ctypes
import errno
import hashlib
import json
import os
import secrets
import stat
import sys


EXIT_OK = 0
EXIT_INTEGRITY = 2
EXIT_INPUT = 3
EXIT_SCHEMA = 4
EXIT_PUBLICATION = 6
EXIT_USAGE = 64

ERROR_TOKEN = {
    EXIT_INTEGRITY: "STAGE2B_INTEGRITY_ERROR",
    EXIT_INPUT: "STAGE2B_INPUT_ERROR",
    EXIT_SCHEMA: "STAGE2B_SCHEMA_ERROR",
    EXIT_PUBLICATION: "STAGE2B_PUBLICATION_ERROR",
    EXIT_USAGE: "STAGE2B_USAGE_ERROR",
}

SOURCE_IDS = frozenset(("subfinder", "assetfinder", "amass", "virustotal", "shodan"))
LINE_SOURCES = frozenset(("subfinder", "assetfinder", "amass"))
PROFILES = frozenset(("hostname-lines-v1", "retained-provider-failure-v1"))
ERROR_CODES = frozenset((
    "COLLECTION_FAILED", "TIMEOUT", "TOOL_ERROR", "OUTPUT_TRUNCATED",
    "CREDENTIAL_ERROR", "POLICY_BLOCKED",
))

MAX_INPUT = 8 * 1024 * 1024
MAX_RECEIPT = 65536
MAX_RECORDS = 100000
MAX_RECORD_BYTES = 4096
MAX_MANIFEST = 65536
MAX_JSON_DEPTH = 16
AGGREGATE_ALGORITHM = "sorted-path-sha256-v1"
RENAME_NOREPLACE = 1

ORIGINAL_PATHS = (
    ".gitignore", "LICENSE", "README.md",
    "config/wolt-approved-exact.txt", "config/wolt-excluded.txt",
    "config/wolt-mobile-assets.txt", "config/wolt-policy.json",
    "config/wolt-stage2a-integrity.json", "lib/wolt-stage2a.py",
    "nullsec-wolt-stage2a.sh", "nullsec-wolt.sh", "nullsec.sh",
    "tests/fixtures/wolt-stage2a/expected/approved-exact.txt",
    "tests/fixtures/wolt-stage2a/expected/explicitly-excluded.txt",
    "tests/fixtures/wolt-stage2a/expected/provenance.tsv",
    "tests/fixtures/wolt-stage2a/expected/rejected-malformed.txt",
    "tests/fixtures/wolt-stage2a/expected/rejected-mobile-assets.txt",
    "tests/fixtures/wolt-stage2a/expected/rejected-non-wolt.txt",
    "tests/fixtures/wolt-stage2a/expected/source-errors.txt",
    "tests/fixtures/wolt-stage2a/expected/wildcard-candidates-unreviewed.txt",
    "tests/fixtures/wolt-stage2a/inputs/amass-empty.json",
    "tests/fixtures/wolt-stage2a/inputs/assetfinder-success.json",
    "tests/fixtures/wolt-stage2a/inputs/shodan-failed.json",
    "tests/fixtures/wolt-stage2a/inputs/subfinder-success.json",
    "tests/test-wolt-stage2a.py", "tests/test-wolt-stage2a.sh",
    "tests/test-wolt-wrapper.sh",
)
PROGRAM_PATHS = ("nullsec-wolt-stage2b.sh", "lib/wolt-stage2b.py")
PROTECTED_PATHS = frozenset(ORIGINAL_PATHS + PROGRAM_PATHS)


class Failure(Exception):
    """Internal deterministic failure; reasons are never printed publicly."""

    def __init__(self, code, reason):
        super().__init__(reason)
        self.code = code
        self.reason = reason


def abort(code, reason):
    raise Failure(code, reason)


def verify_identity(ops=os):
    if ops.getuid() != ops.geteuid():
        abort(EXIT_INTEGRITY, "UID_MISMATCH")
    if ops.getgid() != ops.getegid():
        abort(EXIT_INTEGRITY, "GID_MISMATCH")


def unsafe_mode(mode):
    return bool(mode & (stat.S_IWGRP | stat.S_IWOTH))


def file_identity(st):
    return (
        st.st_dev, st.st_ino, st.st_size, stat.S_IFMT(st.st_mode), st.st_uid,
        st.st_gid, stat.S_IMODE(st.st_mode), st.st_mtime_ns, st.st_ctime_ns,
    )


def directory_identity(st):
    return (st.st_dev, st.st_ino, stat.S_IFMT(st.st_mode), st.st_uid,
            st.st_gid, stat.S_IMODE(st.st_mode))


def validate_regular(st, code, reason, exact_mode=None, ops=os):
    if not stat.S_ISREG(st.st_mode):
        abort(code, reason + "_TYPE")
    if st.st_uid != ops.geteuid():
        abort(code, reason + "_OWNER")
    if unsafe_mode(st.st_mode):
        abort(code, reason + "_MODE")
    if exact_mode is not None and stat.S_IMODE(st.st_mode) != exact_mode:
        abort(code, reason + "_EXACT_MODE")


def open_trusted_directory(path, code, reason, ops=os):
    """Open and validate every ancestor from / through path without symlinks."""
    if not isinstance(path, str) or not os.path.isabs(path):
        abort(code, reason + "_ABSOLUTE")
    flags = (ops.O_RDONLY | ops.O_DIRECTORY | getattr(ops, "O_CLOEXEC", 0) |
             getattr(ops, "O_NOFOLLOW", 0))
    try:
        fd = ops.open("/", flags)
    except OSError:
        abort(code, reason + "_OPEN")
    try:
        st = ops.fstat(fd)
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid not in (0, ops.geteuid()) or
                unsafe_mode(st.st_mode)):
            abort(code, reason + "_TRUST")
        for part in (item for item in path.split("/") if item):
            if part in (".", ".."):
                abort(code, reason + "_TRAVERSAL")
            try:
                new_fd = ops.open(part, flags, dir_fd=fd)
            except OSError:
                abort(code, reason + "_OPEN")
            ops.close(fd)
            fd = new_fd
            st = ops.fstat(fd)
            if (not stat.S_ISDIR(st.st_mode) or st.st_uid not in (0, ops.geteuid()) or
                    unsafe_mode(st.st_mode)):
                abort(code, reason + "_TRUST")
        return fd
    except BaseException:
        try:
            ops.close(fd)
        except OSError:
            pass
        raise


def split_absolute_file(path, code, reason):
    if not isinstance(path, str) or not os.path.isabs(path) or path.endswith("/"):
        abort(code, reason + "_PATH")
    parent, name = os.path.split(path)
    if not parent or not name or name in (".", ".."):
        abort(code, reason + "_PATH")
    if any(part in (".", "..") for part in path.split("/")):
        abort(code, reason + "_TRAVERSAL")
    return parent, name


def open_parent(path, code, reason, ops=os):
    parent, name = split_absolute_file(path, code, reason)
    fd = open_trusted_directory(parent, code, reason + "_PARENT", ops)
    st = ops.fstat(fd)
    if st.st_uid != ops.geteuid():
        ops.close(fd)
        abort(code, reason + "_PARENT_OWNER")
    return fd, name, directory_identity(st), parent


def open_regular_at(parent_fd, name, code, reason, ops=os):
    flags = (ops.O_RDONLY | getattr(ops, "O_CLOEXEC", 0) |
             getattr(ops, "O_NOFOLLOW", 0) | getattr(ops, "O_NONBLOCK", 0))
    try:
        fd = ops.open(name, flags, dir_fd=parent_fd)
    except OSError:
        abort(code, reason + "_OPEN")
    try:
        validate_regular(ops.fstat(fd), code, reason, ops=ops)
    except BaseException:
        ops.close(fd)
        raise
    return fd


def read_fd_stable(fd, limit, code, reason, ops=os):
    try:
        before = ops.fstat(fd)
    except OSError:
        abort(code, reason + "_STAT")
    validate_regular(before, code, reason, ops=ops)
    if before.st_size > limit:
        abort(code, reason + "_TOO_LARGE")
    chunks = []
    total = 0
    try:
        while True:
            remaining = limit + 1 - total
            if remaining <= 0:
                abort(code, reason + "_TOO_LARGE")
            chunk = ops.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                abort(code, reason + "_TOO_LARGE")
        after = ops.fstat(fd)
    except Failure:
        raise
    except OSError:
        abort(code, reason + "_READ")
    validate_regular(after, code, reason, ops=ops)
    if file_identity(before) != file_identity(after) or total != after.st_size:
        abort(code, reason + "_CHANGED")
    return b"".join(chunks), before


def read_absolute_stable(path, limit, code, reason, ops=os):
    parent_fd, name, _identity, _parent = open_parent(path, code, reason, ops)
    fd = -1
    try:
        fd = open_regular_at(parent_fd, name, code, reason, ops)
        data, snapshot = read_fd_stable(fd, limit, code, reason, ops)
        return data, snapshot
    finally:
        if fd >= 0:
            ops.close(fd)
        ops.close(parent_fd)


def duplicate_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate")
        value[key] = item
    return value


def reject_excessive_json_nesting(data, code, reason, maximum=MAX_JSON_DEPTH):
    depth = 0
    in_string = False
    escaped = False
    for byte in data:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in (0x7B, 0x5B):
            depth += 1
            if depth > maximum:
                abort(code, reason + "_DEPTH")
        elif byte in (0x7D, 0x5D):
            depth -= 1


def parse_strict_json(data, code, reason):
    if b"\0" in data:
        abort(code, reason + "_NUL")
    reject_excessive_json_nesting(data, code, reason)
    try:
        text = data.decode("utf-8", "strict")
        return json.loads(
            text,
            object_pairs_hook=duplicate_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("constant")),
        )
    except (UnicodeError, ValueError, json.JSONDecodeError, RecursionError):
        abort(code, reason + "_JSON")


def parse_cli(argv):
    if len(argv) < 4 or argv[0] != "--repository" or argv[2] != "--launcher":
        abort(EXIT_INTEGRITY, "LAUNCH_CONTEXT")
    repository, launcher = argv[1], argv[3]
    if (not repository or not launcher or not os.path.isabs(repository) or
            not os.path.isabs(launcher)):
        abort(EXIT_INTEGRITY, "LAUNCH_CONTEXT")
    public = argv[4:]
    if public == ["--help"]:
        return {"mode": "help", "repository": repository, "launcher": launcher}
    if "--help" in public:
        abort(EXIT_USAGE, "HELP_ARGUMENT")
    accepted = ("--source", "--profile", "--input", "--output")
    values = {}
    index = 0
    while index < len(public):
        option = public[index]
        if option not in accepted:
            abort(EXIT_USAGE, "UNKNOWN_ARGUMENT")
        if option in values:
            abort(EXIT_USAGE, "DUPLICATE_ARGUMENT")
        if index + 1 >= len(public):
            abort(EXIT_USAGE, "MISSING_VALUE")
        value = public[index + 1]
        if value in accepted or value.startswith("-"):
            abort(EXIT_USAGE, "MISSING_VALUE")
        if not value:
            abort(EXIT_USAGE, "EMPTY_VALUE")
        values[option] = value
        index += 2
    if set(values) != set(accepted):
        abort(EXIT_USAGE, "MISSING_ARGUMENT")
    source, profile = values["--source"], values["--profile"]
    if source not in SOURCE_IDS:
        abort(EXIT_SCHEMA, "SOURCE_UNSUPPORTED")
    if profile not in PROFILES:
        abort(EXIT_SCHEMA, "PROFILE_UNSUPPORTED")
    if profile == "hostname-lines-v1" and source not in LINE_SOURCES:
        abort(EXIT_SCHEMA, "SOURCE_PROFILE_MISMATCH")
    for option in ("--input", "--output"):
        if not os.path.isabs(values[option]):
            abort(EXIT_USAGE, "RELATIVE_PATH")
        split_absolute_file(values[option], EXIT_USAGE, "CLI")
    return {
        "mode": "convert", "repository": repository, "launcher": launcher,
        "source": source, "profile": profile,
        "input": values["--input"], "output": values["--output"],
    }


def expected_context():
    core = os.path.abspath(__file__)
    repository = os.path.dirname(os.path.dirname(core))
    return repository, os.path.join(repository, "nullsec-wolt-stage2b.sh"), core


def verify_context(cfg):
    repository, launcher, core = expected_context()
    if cfg["repository"] != repository or cfg["launcher"] != launcher:
        abort(EXIT_INTEGRITY, "CONTEXT_MISMATCH")
    repo_fd = open_trusted_directory(repository, EXIT_INTEGRITY, "REPOSITORY")
    try:
        if os.fstat(repo_fd).st_uid != os.geteuid():
            abort(EXIT_INTEGRITY, "REPOSITORY_OWNER")
    finally:
        os.close(repo_fd)
    return repository, launcher, core


def aggregate_digest(files):
    digest = hashlib.sha256()
    for path in sorted(files):
        digest.update(path.encode("ascii") + b"\0" + files[path].encode("ascii") + b"\n")
    return digest.hexdigest()


def load_manifest(repository):
    path = os.path.join(repository, "config", "wolt-stage2b-integrity.json")
    data, _snapshot = read_absolute_stable(path, MAX_MANIFEST, EXIT_INTEGRITY, "MANIFEST")
    manifest = parse_strict_json(data, EXIT_INTEGRITY, "MANIFEST")
    keys = {"schema_version", "aggregate_algorithm", "aggregate_sha256", "protected_files"}
    if not isinstance(manifest, dict) or set(manifest) != keys:
        abort(EXIT_INTEGRITY, "MANIFEST_KEYS")
    if (isinstance(manifest["schema_version"], bool) or
            manifest["schema_version"] != 1 or
            manifest["aggregate_algorithm"] != AGGREGATE_ALGORITHM):
        abort(EXIT_INTEGRITY, "MANIFEST_VALUES")
    files = manifest["protected_files"]
    if not isinstance(files, dict) or set(files) != PROTECTED_PATHS:
        abort(EXIT_INTEGRITY, "MANIFEST_INVENTORY")
    for path, digest in files.items():
        if (not isinstance(path, str) or not isinstance(digest, str) or
                len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest)):
            abort(EXIT_INTEGRITY, "MANIFEST_DIGEST")
    aggregate = manifest["aggregate_sha256"]
    if (not isinstance(aggregate, str) or aggregate != aggregate_digest(files)):
        abort(EXIT_INTEGRITY, "MANIFEST_AGGREGATE")
    return manifest


def protected_limit(path):
    if path == "nullsec-wolt-stage2b.sh":
        return 1024 * 1024
    if path == "lib/wolt-stage2b.py":
        return 4 * 1024 * 1024
    return MAX_INPUT


def verify_integrity(cfg):
    repository, launcher, core = verify_context(cfg)
    manifest = load_manifest(repository)
    observed = {}
    for relative in sorted(PROTECTED_PATHS):
        absolute = os.path.join(repository, *relative.split("/"))
        data, st = read_absolute_stable(
            absolute, protected_limit(relative), EXIT_INTEGRITY, "PROTECTED")
        observed[relative] = hashlib.sha256(data).hexdigest()
        if relative == "nullsec-wolt-stage2b.sh" and not st.st_mode & stat.S_IXUSR:
            abort(EXIT_INTEGRITY, "LAUNCHER_NOT_EXECUTABLE")
    if observed != manifest["protected_files"]:
        abort(EXIT_INTEGRITY, "PROTECTED_DIGEST")
    if aggregate_digest(observed) != manifest["aggregate_sha256"]:
        abort(EXIT_INTEGRITY, "PROTECTED_AGGREGATE")
    return {"repository": repository, "launcher": launcher, "core": core,
            "aggregate": manifest["aggregate_sha256"]}


def parse_hostname_lines(data):
    if b"\0" in data:
        abort(EXIT_INPUT, "LINES_NUL")
    if b"\r" in data:
        abort(EXIT_INPUT, "LINES_CR")
    for byte in data:
        if byte >= 128:
            abort(EXIT_INPUT, "LINES_NON_ASCII")
        if (byte < 32 and byte != 10) or byte == 127:
            abort(EXIT_INPUT, "LINES_CONTROL")
    if not data:
        return []
    body = data[:-1] if data.endswith(b"\n") else data
    raw_records = body.split(b"\n")
    if any(not record for record in raw_records):
        abort(EXIT_INPUT, "LINES_BLANK")
    if len(raw_records) > MAX_RECORDS:
        abort(EXIT_INPUT, "LINES_COUNT")
    if any(len(record) > MAX_RECORD_BYTES for record in raw_records):
        abort(EXIT_INPUT, "LINES_LENGTH")
    return [record.decode("ascii") for record in raw_records]


def parse_failure_receipt(data, cli_source):
    value = parse_strict_json(data, EXIT_SCHEMA, "RECEIPT")
    expected = {"schema_version", "profile", "source_id", "error_code"}
    if not isinstance(value, dict) or set(value) != expected:
        abort(EXIT_SCHEMA, "RECEIPT_KEYS")
    if (isinstance(value["schema_version"], bool) or
            not isinstance(value["schema_version"], int) or
            value["schema_version"] != 1):
        abort(EXIT_SCHEMA, "RECEIPT_VERSION")
    for key in ("profile", "source_id", "error_code"):
        if not isinstance(value[key], str):
            abort(EXIT_SCHEMA, "RECEIPT_TYPE")
    if value["profile"] != "retained-provider-failure-v1":
        abort(EXIT_SCHEMA, "RECEIPT_PROFILE")
    if value["source_id"] != cli_source:
        abort(EXIT_SCHEMA, "RECEIPT_SOURCE")
    if value["source_id"] not in SOURCE_IDS:
        abort(EXIT_SCHEMA, "RECEIPT_SOURCE_UNSUPPORTED")
    if value["error_code"] not in ERROR_CODES:
        abort(EXIT_SCHEMA, "RECEIPT_ERROR")
    return value["error_code"]


def envelope_bytes(source, profile, data):
    if profile == "hostname-lines-v1":
        records = parse_hostname_lines(data)
        value = {
            "schema_version": 1, "source_id": source,
            "collection_status": "success", "record_count": len(records),
            "records": records,
        }
    elif profile == "retained-provider-failure-v1":
        error_code = parse_failure_receipt(data, source)
        value = {
            "schema_version": 1, "source_id": source,
            "collection_status": "failed", "error_code": error_code,
            "record_count": 0, "records": [],
        }
    else:
        abort(EXIT_SCHEMA, "PROFILE_UNSUPPORTED")
    encoded = (json.dumps(value, ensure_ascii=True, sort_keys=True, allow_nan=False,
                          separators=(",", ":")) + "\n").encode("utf-8")
    if len(encoded) > MAX_INPUT:
        abort(EXIT_INPUT, "ENVELOPE_TOO_LARGE")
    return encoded


def open_input(path, profile):
    limit = MAX_INPUT if profile == "hostname-lines-v1" else MAX_RECEIPT
    parent_fd, name, parent_identity, parent_path = open_parent(path, EXIT_INPUT, "INPUT")
    fd = -1
    try:
        fd = open_regular_at(parent_fd, name, EXIT_INPUT, "INPUT")
        data, snapshot = read_fd_stable(fd, limit, EXIT_INPUT, "INPUT")
        return {
            "fd": fd, "parent_fd": parent_fd, "name": name, "path": path,
            "parent_path": parent_path, "parent_identity": parent_identity,
            "snapshot": snapshot, "data": data,
        }
    except BaseException:
        if fd >= 0:
            os.close(fd)
        os.close(parent_fd)
        raise


def revalidate_open_file(context, code=EXIT_INPUT):
    try:
        current = os.fstat(context["fd"])
    except OSError:
        abort(code, "INPUT_REVALIDATE_STAT")
    validate_regular(current, code, "INPUT_REVALIDATE")
    if file_identity(current) != file_identity(context["snapshot"]):
        abort(code, "INPUT_REVALIDATE_CHANGED")
    fresh_parent = open_trusted_directory(context["parent_path"], code, "INPUT_REWALK")
    fresh_fd = -1
    try:
        if directory_identity(os.fstat(fresh_parent)) != context["parent_identity"]:
            abort(code, "INPUT_PARENT_REPLACED")
        fresh_fd = open_regular_at(fresh_parent, context["name"], code, "INPUT_REWALK")
        if file_identity(os.fstat(fresh_fd)) != file_identity(context["snapshot"]):
            abort(code, "INPUT_REPLACED")
    finally:
        if fresh_fd >= 0:
            os.close(fresh_fd)
        os.close(fresh_parent)


def open_output_parent(path):
    parent_fd, name, parent_identity, parent_path = open_parent(
        path, EXIT_PUBLICATION, "OUTPUT")
    try:
        try:
            existing = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        except OSError:
            abort(EXIT_PUBLICATION, "OUTPUT_INSPECT")
        if existing is not None:
            abort(EXIT_PUBLICATION, "OUTPUT_EXISTS")
        return {
            "fd": parent_fd, "name": name, "path": path,
            "parent_path": parent_path, "identity": parent_identity,
        }
    except BaseException:
        os.close(parent_fd)
        raise


def reject_alias(input_context, output_path):
    parent, name = split_absolute_file(output_path, EXIT_PUBLICATION, "OUTPUT")
    dfd = open_trusted_directory(parent, EXIT_PUBLICATION, "OUTPUT_PARENT")
    try:
        try:
            st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
        except FileNotFoundError:
            return
        except OSError:
            abort(EXIT_PUBLICATION, "OUTPUT_INSPECT")
        if (st.st_dev, st.st_ino) == (input_context["snapshot"].st_dev,
                                     input_context["snapshot"].st_ino):
            abort(EXIT_PUBLICATION, "INPUT_OUTPUT_ALIAS")
        abort(EXIT_PUBLICATION, "OUTPUT_EXISTS")
    finally:
        os.close(dfd)


def write_complete(fd, data, ops=os):
    offset = 0
    try:
        while offset < len(data):
            count = ops.write(fd, data[offset:])
            if count <= 0:
                abort(EXIT_PUBLICATION, "WRITE_ZERO")
            offset += count
    except Failure:
        raise
    except OSError:
        abort(EXIT_PUBLICATION, "WRITE_FAILED")


def digest_fd(fd, limit, ops=os):
    try:
        ops.lseek(fd, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = ops.read(fd, min(65536, limit + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                abort(EXIT_PUBLICATION, "TEMP_TOO_LARGE")
            digest.update(chunk)
        return total, digest.hexdigest()
    except Failure:
        raise
    except OSError:
        abort(EXIT_PUBLICATION, "TEMP_VERIFY_READ")


def rename_noreplace(directory_fd, source, destination, libc=None):
    try:
        library = libc if libc is not None else ctypes.CDLL(None, use_errno=True)
        function = getattr(library, "renameat2", None)
        if function is None:
            abort(EXIT_PUBLICATION, "ATOMIC_UNAVAILABLE")
        function.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                             ctypes.c_char_p, ctypes.c_uint)
        function.restype = ctypes.c_int
        ctypes.set_errno(0)
        result = function(directory_fd, source.encode("ascii"), directory_fd,
                          destination.encode("utf-8"), RENAME_NOREPLACE)
    except Failure:
        raise
    except BaseException:
        abort(EXIT_PUBLICATION, "ATOMIC_UNAVAILABLE")
    if result != 0:
        number = ctypes.get_errno()
        if number == errno.EEXIST:
            abort(EXIT_PUBLICATION, "OUTPUT_EXISTS")
        abort(EXIT_PUBLICATION, "ATOMIC_INSTALL")


def revalidate_output_parent(context):
    fresh = open_trusted_directory(
        context["parent_path"], EXIT_PUBLICATION, "OUTPUT_REWALK")
    try:
        if directory_identity(os.fstat(fresh)) != context["identity"]:
            abort(EXIT_PUBLICATION, "OUTPUT_PARENT_REPLACED")
    finally:
        os.close(fresh)
    if directory_identity(os.fstat(context["fd"])) != context["identity"]:
        abort(EXIT_PUBLICATION, "OUTPUT_PARENT_CHANGED")


def cleanup_name(directory_fd, name):
    try:
        os.unlink(name, dir_fd=directory_fd)
        os.fsync(directory_fd)
    except FileNotFoundError:
        return
    except OSError:
        abort(EXIT_PUBLICATION, "CLEANUP_FAILED")


def rollback_installed(context, expected_inode):
    try:
        st = os.stat(context["name"], dir_fd=context["fd"], follow_symlinks=False)
        if (st.st_dev, st.st_ino) != expected_inode:
            abort(EXIT_PUBLICATION, "ROLLBACK_IDENTITY")
        os.unlink(context["name"], dir_fd=context["fd"])
        os.fsync(context["fd"])
    except FileNotFoundError:
        return
    except Failure:
        raise
    except OSError:
        abort(EXIT_PUBLICATION, "ROLLBACK_FAILED")


def publish_atomic(output_context, payload, preinstall_check, ops=os,
                   rename_function=rename_noreplace):
    flags = (ops.O_RDWR | ops.O_CREAT | ops.O_EXCL | getattr(ops, "O_CLOEXEC", 0) |
             getattr(ops, "O_NOFOLLOW", 0))
    temp_name = None
    temp_fd = -1
    installed = False
    expected_inode = None
    payload_digest = hashlib.sha256(payload).hexdigest()
    failure = None
    try:
        for _attempt in range(16):
            candidate = ".stage2b-" + secrets.token_hex(16)
            try:
                temp_fd = ops.open(candidate, flags, 0o600, dir_fd=output_context["fd"])
                temp_name = candidate
                break
            except FileExistsError:
                continue
            except OSError:
                abort(EXIT_PUBLICATION, "TEMP_CREATE")
        if temp_fd < 0:
            abort(EXIT_PUBLICATION, "TEMP_COLLISION")
        write_complete(temp_fd, payload, ops)
        try:
            ops.fsync(temp_fd)
        except OSError:
            abort(EXIT_PUBLICATION, "TEMP_FSYNC")
        st = ops.fstat(temp_fd)
        validate_regular(st, EXIT_PUBLICATION, "TEMP", 0o600, ops)
        if st.st_size != len(payload):
            abort(EXIT_PUBLICATION, "TEMP_SIZE")
        size, digest = digest_fd(temp_fd, len(payload), ops)
        if size != len(payload) or digest != payload_digest:
            abort(EXIT_PUBLICATION, "TEMP_DIGEST")
        try:
            ops.fchmod(temp_fd, 0o400)
            ops.fsync(temp_fd)
        except OSError:
            abort(EXIT_PUBLICATION, "TEMP_SEAL")
        sealed = ops.fstat(temp_fd)
        validate_regular(sealed, EXIT_PUBLICATION, "TEMP", 0o400, ops)
        if sealed.st_size != len(payload):
            abort(EXIT_PUBLICATION, "TEMP_SEALED_SIZE")
        expected_inode = (sealed.st_dev, sealed.st_ino)
        preinstall_check()
        revalidate_output_parent(output_context)
        rename_function(output_context["fd"], temp_name, output_context["name"])
        installed = True
        temp_name = None
        try:
            ops.fsync(output_context["fd"])
        except OSError:
            abort(EXIT_PUBLICATION, "DIRECTORY_FSYNC")
        verify_fd = open_regular_at(output_context["fd"], output_context["name"],
                                    EXIT_PUBLICATION, "PUBLISHED", ops)
        try:
            published = ops.fstat(verify_fd)
            validate_regular(published, EXIT_PUBLICATION, "PUBLISHED", 0o400, ops)
            if ((published.st_dev, published.st_ino) != expected_inode or
                    published.st_size != len(payload)):
                abort(EXIT_PUBLICATION, "PUBLISHED_IDENTITY")
            size, digest = digest_fd(verify_fd, len(payload), ops)
            if size != len(payload) or digest != payload_digest:
                abort(EXIT_PUBLICATION, "PUBLISHED_DIGEST")
        finally:
            ops.close(verify_fd)
    except BaseException as exc:
        failure = exc
    finally:
        if temp_fd >= 0:
            try:
                ops.close(temp_fd)
            except OSError:
                if failure is None:
                    failure = Failure(EXIT_PUBLICATION, "TEMP_CLOSE")
        try:
            if temp_name is not None:
                cleanup_name(output_context["fd"], temp_name)
            elif installed and failure is not None:
                rollback_installed(output_context, expected_inode)
        except BaseException as cleanup_error:
            failure = cleanup_error
    if failure is not None:
        if isinstance(failure, Failure):
            raise failure
        abort(EXIT_PUBLICATION, "PUBLICATION_INTERNAL")


def close_context(context):
    for key in ("fd", "parent_fd"):
        fd = context.get(key, -1)
        if isinstance(fd, int) and fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
            context[key] = -1


def convert(cfg):
    verify_integrity(cfg)
    input_context = open_input(cfg["input"], cfg["profile"])
    output_context = None
    try:
        reject_alias(input_context, cfg["output"])
        output_context = open_output_parent(cfg["output"])
        payload = envelope_bytes(cfg["source"], cfg["profile"], input_context["data"])

        def final_check():
            verify_integrity(cfg)
            revalidate_open_file(input_context)

        publish_atomic(output_context, payload, final_check)
    finally:
        if output_context is not None:
            close_context(output_context)
        close_context(input_context)


def help_text():
    return (
        "Usage: nullsec-wolt-stage2b.sh --source SOURCE --profile PROFILE "
        "--input ABSOLUTE_FILE --output ABSOLUTE_FILE\n"
        "Offline retained-evidence normalization only.\n"
    )


def main(argv=None):
    try:
        verify_identity()
        cfg = parse_cli(sys.argv[1:] if argv is None else argv)
        verify_integrity(cfg)
        if cfg["mode"] == "help":
            sys.stdout.write(help_text())
        else:
            convert(cfg)
            sys.stdout.write("STAGE2B_COMPLETE\n")
        return EXIT_OK
    except Failure as failure:
        sys.stderr.write(ERROR_TOKEN[failure.code] + "\n")
        return failure.code
    except BaseException:
        sys.stderr.write(ERROR_TOKEN[EXIT_INTEGRITY] + "\n")
        return EXIT_INTEGRITY


if __name__ == "__main__":
    raise SystemExit(main())
