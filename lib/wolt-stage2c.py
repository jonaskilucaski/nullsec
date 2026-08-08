#!/usr/bin/python3
"""Wolt Stage 2C Phase 1: strictly offline manifest validation primitives.

Phase 1 validates retained artifacts and publication preconditions.  It does not
invoke another stage, classify evidence, or create/publish an output package.
"""

import ctypes
import errno
import hashlib
import json
import os
import platform
import stat
import sys


EXIT_OK = 0
EXIT_INTERNAL = 1
EXIT_INTEGRITY = 2
EXIT_INPUT = 3
EXIT_SCHEMA = 4
EXIT_PUBLICATION = 6
EXIT_PROVIDER_FAILURE = 7
EXIT_DURABILITY_UNCERTAIN = 8
EXIT_USAGE = 64

ERROR_TOKEN = {
    EXIT_INTERNAL: "STAGE2C_INTERNAL_ERROR",
    EXIT_INTEGRITY: "STAGE2C_INTEGRITY_ERROR",
    EXIT_INPUT: "STAGE2C_INPUT_ERROR",
    EXIT_SCHEMA: "STAGE2C_SCHEMA_ERROR",
    EXIT_PUBLICATION: "STAGE2C_PUBLICATION_ERROR",
    EXIT_PROVIDER_FAILURE: "STAGE2C_PROVIDER_FAILURE",
    EXIT_DURABILITY_UNCERTAIN: "STAGE2C_DURABILITY_UNCERTAIN",
    EXIT_USAGE: "STAGE2C_USAGE_ERROR",
}

# Frozen, non-configurable resource limits.  Boundaries are inclusive.
MAX_MANIFEST_BYTES = 256 * 1024
MAX_JSON_DEPTH = 16
MAX_ARTIFACTS = 32
MAX_ARTIFACT_ID_BYTES = 128
MAX_PATH_BYTES = 4096
MAX_RETAINED_BYTES = 16 * 1024 * 1024
MAX_TOTAL_RETAINED_BYTES = 64 * 1024 * 1024
MAX_PROTECTED_BYTES = 16 * 1024 * 1024
MAX_LAUNCH_RESULT_BYTES = 4096

INTEGRITY_SCHEMA_VERSION = 1
INVENTORY_ALGORITHM = "sorted-path-sha256-v1"
AGGREGATE_ALGORITHM = "sorted-path-sha256-v1"
RENAME_NOREPLACE = 1
MINIMUM_PYTHON = (3, 9)

SOURCE_IDS = frozenset(("subfinder", "assetfinder", "amass", "virustotal", "shodan"))
HOSTNAME_SOURCES = frozenset(("subfinder", "assetfinder", "amass"))
PROFILES = frozenset(("hostname-lines-v1", "retained-provider-failure-v1"))
ARTIFACT_KEYS = frozenset((
    "artifact_id", "source_id", "profile", "retained_path", "sha256", "size_bytes",
))

BASELINE_PATHS = (
    ".gitignore", "LICENSE", "README.md",
    "config/wolt-approved-exact.txt", "config/wolt-excluded.txt",
    "config/wolt-mobile-assets.txt", "config/wolt-policy.json",
    "config/wolt-stage2a-integrity.json", "config/wolt-stage2b-integrity.json",
    "lib/wolt-stage2a.py", "lib/wolt-stage2b.py",
    "nullsec-wolt-stage2a.sh", "nullsec-wolt-stage2b.sh",
    "nullsec-wolt.sh", "nullsec.sh",
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
    "tests/fixtures/wolt-stage2b/failure-receipt.json",
    "tests/fixtures/wolt-stage2b/hostname-lines.txt",
    "tests/test-wolt-stage2a.py", "tests/test-wolt-stage2a.sh",
    "tests/test-wolt-stage2b.py", "tests/test-wolt-stage2b.sh",
    "tests/test-wolt-wrapper.sh",
)
STAGE2C_HASHED_PATHS = ("lib/wolt-stage2c.py", "tests/test-wolt-stage2c.py")
PROTECTED_PATHS = frozenset(BASELINE_PATHS + STAGE2C_HASHED_PATHS)
EXECUTABLE_PROTECTED_PATHS = frozenset((
    "nullsec-wolt-stage2a.sh", "nullsec-wolt-stage2b.sh", "nullsec.sh",
    "tests/test-wolt-stage2a.sh", "tests/test-wolt-stage2b.sh",
))


class Failure(Exception):
    """A classified internal failure whose reason is never printed publicly."""

    def __init__(self, code, reason):
        super().__init__(reason)
        self.code = code
        self.reason = reason


def abort(code, reason):
    raise Failure(code, reason)


def unsafe_mode(mode):
    return bool(mode & (stat.S_IWGRP | stat.S_IWOTH))


def file_identity(value):
    return (
        value.st_dev, value.st_ino, value.st_size, stat.S_IFMT(value.st_mode),
        value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode), value.st_nlink,
        value.st_mtime_ns, value.st_ctime_ns,
    )


def directory_identity(value):
    return (
        value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode), value.st_uid,
        value.st_gid, stat.S_IMODE(value.st_mode),
    )


def ancestor_identity(value):
    return directory_identity(value) + (value.st_nlink,)


def verify_process_identity(ops=os):
    if ops.getuid() != ops.geteuid() or ops.getgid() != ops.getegid():
        abort(EXIT_INTEGRITY, "PROCESS_IDENTITY")


def validate_regular(value, code, reason, *, exact_mode=None, link_count_one=True, ops=os):
    if not stat.S_ISREG(value.st_mode):
        abort(code, reason + "_TYPE")
    if value.st_uid not in (0, ops.geteuid()):
        abort(code, reason + "_OWNER")
    if unsafe_mode(value.st_mode):
        abort(code, reason + "_MODE")
    if exact_mode is not None and stat.S_IMODE(value.st_mode) != exact_mode:
        abort(code, reason + "_EXACT_MODE")
    if link_count_one and value.st_nlink != 1:
        abort(code, reason + "_LINKS")


def validate_simple_name(name, code, reason):
    if (not isinstance(name, str) or not name or name in (".", "..") or
            "/" in name or "\0" in name or len(os.fsencode(name)) > 255):
        abort(code, reason + "_NAME")


def validate_absolute_path(path, code, reason):
    if (not isinstance(path, str) or not path or "\0" in path or
            not os.path.isabs(path) or path.endswith("/") or
            len(os.fsencode(path)) > MAX_PATH_BYTES):
        abort(code, reason + "_PATH")
    parts = path.split("/")
    if any(part in (".", "..") for part in parts):
        abort(code, reason + "_TRAVERSAL")
    parent, name = os.path.split(path)
    if not parent or not name:
        abort(code, reason + "_PATH")
    validate_simple_name(name, code, reason)
    return parent, name


def open_trusted_directory(path, code, reason, ops=os):
    """Open an absolute directory and reject symlinked or writable ancestors."""
    if not isinstance(path, str) or not os.path.isabs(path):
        abort(code, reason + "_ABSOLUTE")
    flags = (ops.O_RDONLY | ops.O_DIRECTORY | ops.O_NOFOLLOW |
             getattr(ops, "O_CLOEXEC", 0))
    try:
        descriptor = ops.open("/", flags)
    except (AttributeError, OSError):
        abort(code, reason + "_OPEN")
    try:
        root = ops.fstat(descriptor)
        if (not stat.S_ISDIR(root.st_mode) or root.st_uid not in (0, ops.geteuid()) or
                unsafe_mode(root.st_mode)):
            abort(code, reason + "_TRUST")
        for component in (part for part in path.split("/") if part):
            validate_simple_name(component, code, reason)
            try:
                next_descriptor = ops.open(component, flags, dir_fd=descriptor)
            except OSError:
                abort(code, reason + "_OPEN")
            ops.close(descriptor)
            descriptor = next_descriptor
            current = ops.fstat(descriptor)
            if (not stat.S_ISDIR(current.st_mode) or
                    current.st_uid not in (0, ops.geteuid()) or
                    unsafe_mode(current.st_mode)):
                abort(code, reason + "_TRUST")
        return descriptor
    except BaseException:
        try:
            ops.close(descriptor)
        except OSError:
            pass
        raise


def _validate_trusted_ancestor(value, code, reason, ops=os):
    if (not stat.S_ISDIR(value.st_mode) or
            value.st_uid not in (0, ops.geteuid()) or
            unsafe_mode(value.st_mode)):
        abort(code, reason + "_TRUST")


def _ancestor_record(descriptor, name, value):
    return {
        "fd": descriptor, "name": name,
        "device": value.st_dev, "inode": value.st_ino,
        "file_type": stat.S_IFMT(value.st_mode), "owner": value.st_uid,
        "group": value.st_gid, "mode": stat.S_IMODE(value.st_mode),
        "link_count": value.st_nlink, "identity": ancestor_identity(value),
    }


def _close_ancestor_chain(chain, ops=os):
    for record in reversed(chain):
        descriptor = record.get("fd", -1)
        if isinstance(descriptor, int) and descriptor >= 0:
            try:
                ops.close(descriptor)
            except OSError:
                pass
            record["fd"] = -1


def _open_trusted_directory_chain(path, code, reason, ops=os):
    """Retain authenticated descriptors and edges for an absolute directory."""
    if not isinstance(path, str) or not os.path.isabs(path):
        abort(code, reason + "_ABSOLUTE")
    flags = (ops.O_RDONLY | ops.O_DIRECTORY | ops.O_NOFOLLOW |
             getattr(ops, "O_CLOEXEC", 0))
    chain = []
    try:
        try:
            root_fd = ops.open("/", flags)
            root = ops.fstat(root_fd)
            _validate_trusted_ancestor(root, code, reason, ops)
        except Failure:
            try:
                ops.close(root_fd)
            except (OSError, UnboundLocalError):
                pass
            raise
        except (AttributeError, OSError):
            try:
                ops.close(root_fd)
            except (OSError, UnboundLocalError):
                pass
            abort(code, reason + "_OPEN")
        chain.append(_ancestor_record(root_fd, None, root))
        for component in (part for part in path.split("/") if part):
            validate_simple_name(component, code, reason)
            parent_fd = chain[-1]["fd"]
            try:
                child_fd = ops.open(component, flags, dir_fd=parent_fd)
            except OSError:
                abort(code, reason + "_OPEN")
            try:
                child = ops.fstat(child_fd)
                named = ops.stat(component, dir_fd=parent_fd,
                                 follow_symlinks=False)
                _validate_trusted_ancestor(child, code, reason, ops)
                _validate_trusted_ancestor(named, code, reason, ops)
                if ancestor_identity(child) != ancestor_identity(named):
                    abort(code, reason + "_EDGE")
            except Failure:
                try:
                    ops.close(child_fd)
                except OSError:
                    pass
                raise
            except OSError:
                try:
                    ops.close(child_fd)
                except OSError:
                    pass
                abort(code, reason + "_OPEN")
            chain.append(_ancestor_record(child_fd, component, child))
        return chain
    except BaseException:
        _close_ancestor_chain(chain, ops)
        raise


def open_parent(path, code, reason, *, require_euid_parent=False, ops=os):
    parent, name = validate_absolute_path(path, code, reason)
    descriptor = open_trusted_directory(parent, code, reason + "_PARENT", ops)
    try:
        value = ops.fstat(descriptor)
        if require_euid_parent and value.st_uid != ops.geteuid():
            abort(code, reason + "_PARENT_OWNER")
        return descriptor, name, parent, directory_identity(value)
    except BaseException:
        ops.close(descriptor)
        raise


def open_regular_at(parent_fd, name, code, reason, *, exact_mode=None, ops=os):
    flags = (ops.O_RDONLY | ops.O_NOFOLLOW | ops.O_NONBLOCK |
             getattr(ops, "O_CLOEXEC", 0))
    try:
        descriptor = ops.open(name, flags, dir_fd=parent_fd)
    except OSError:
        abort(code, reason + "_OPEN")
    try:
        validate_regular(ops.fstat(descriptor), code, reason,
                         exact_mode=exact_mode, ops=ops)
    except BaseException:
        ops.close(descriptor)
        raise
    return descriptor


def read_fd_stable(descriptor, limit, code, reason, *, oversize_code=None, ops=os):
    oversize_code = code if oversize_code is None else oversize_code
    try:
        before = ops.fstat(descriptor)
    except OSError:
        abort(code, reason + "_STAT")
    validate_regular(before, code, reason, ops=ops)
    if before.st_size > limit:
        abort(oversize_code, reason + "_TOO_LARGE")
    digest = hashlib.sha256()
    chunks = []
    total = 0
    try:
        while True:
            chunk = ops.read(descriptor, min(65536, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            digest.update(chunk)
            total += len(chunk)
            if total > limit:
                abort(oversize_code, reason + "_TOO_LARGE")
        after = ops.fstat(descriptor)
    except Failure:
        raise
    except OSError:
        abort(code, reason + "_READ")
    validate_regular(after, code, reason, ops=ops)
    if file_identity(before) != file_identity(after) or total != after.st_size:
        abort(code, reason + "_CHANGED")
    return b"".join(chunks), digest.hexdigest(), after


def open_absolute_regular(path, code, reason, *, require_euid_parent=False, ops=os):
    parent, name = validate_absolute_path(path, code, reason)
    ancestors = _open_trusted_directory_chain(
        parent, code, reason + "_PARENT", ops)
    parent_fd = ancestors[-1]["fd"]
    descriptor = -1
    try:
        parent_value = ops.fstat(parent_fd)
        if require_euid_parent and parent_value.st_uid != ops.geteuid():
            abort(code, reason + "_PARENT_OWNER")
        descriptor = open_regular_at(parent_fd, name, code, reason, ops=ops)
        return {
            "fd": descriptor, "parent_fd": parent_fd, "name": name, "path": path,
            "parent": parent, "parent_identity": directory_identity(parent_value),
            "ancestors": ancestors,
        }
    except BaseException:
        if descriptor >= 0:
            try:
                ops.close(descriptor)
            except OSError:
                pass
        _close_ancestor_chain(ancestors, ops)
        raise


def revalidate_ancestor_chain(context, code, reason, ops=os):
    ancestors = context.get("ancestors")
    if (not isinstance(ancestors, list) or not ancestors or
            ancestors[-1].get("fd") != context.get("parent_fd")):
        abort(code, reason + "_ANCESTOR_RECORD")
    try:
        for index, record in enumerate(ancestors):
            current = ops.fstat(record["fd"])
            _validate_trusted_ancestor(current, code, reason + "_ANCESTOR", ops)
            if ancestor_identity(current) != record["identity"]:
                abort(code, reason + "_ANCESTOR_CHANGED")
            if index:
                named = ops.stat(record["name"], dir_fd=ancestors[index - 1]["fd"],
                                 follow_symlinks=False)
                _validate_trusted_ancestor(named, code, reason + "_ANCESTOR", ops)
                if ancestor_identity(named) != record["identity"]:
                    abort(code, reason + "_ANCESTOR_EDGE")
        if directory_identity(ops.fstat(context["parent_fd"])) != context["parent_identity"]:
            abort(code, reason + "_PARENT_CHANGED")
    except Failure:
        raise
    except (KeyError, OSError, TypeError):
        abort(code, reason + "_ANCESTOR_REPLACED")


def revalidate_open_file(context, code, reason, ops=os):
    revalidate_ancestor_chain(context, code, reason, ops)
    try:
        current = ops.fstat(context["fd"])
        named = ops.stat(context["name"], dir_fd=context["parent_fd"],
                         follow_symlinks=False)
        parent = ops.fstat(context["parent_fd"])
    except OSError:
        abort(code, reason + "_REPLACED")
    if (file_identity(current) != context["identity"] or
            file_identity(named) != context["identity"] or
            directory_identity(parent) != context["parent_identity"]):
        abort(code, reason + "_REPLACED")


def close_context(context, ops=os):
    descriptor = context.get("fd", -1)
    if isinstance(descriptor, int) and descriptor >= 0:
        try:
            ops.close(descriptor)
        except OSError:
            pass
        context["fd"] = -1
    ancestors = context.get("ancestors")
    if isinstance(ancestors, list):
        _close_ancestor_chain(ancestors, ops)
        context["parent_fd"] = -1
    else:
        parent_fd = context.get("parent_fd", -1)
        if isinstance(parent_fd, int) and parent_fd >= 0 and parent_fd != descriptor:
            try:
                ops.close(parent_fd)
            except OSError:
                pass
        if "parent_fd" in context:
            context["parent_fd"] = -1


def duplicate_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def reject_surrogate_strings(value, code=EXIT_SCHEMA, reason="JSON"):
    """Reject surrogate code points everywhere in a decoded JSON value."""
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            abort(code, reason + "_SURROGATE")
        return
    if isinstance(value, list):
        for item in value:
            reject_surrogate_strings(item, code, reason)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            reject_surrogate_strings(key, code, reason)
            reject_surrogate_strings(item, code, reason)


def reject_excessive_json_nesting(data, maximum=MAX_JSON_DEPTH,
                                  code=EXIT_SCHEMA, reason="JSON"):
    depth = 0
    quoted = False
    escaped = False
    for byte in data:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                quoted = False
            continue
        if byte == 0x22:
            quoted = True
        elif byte in (0x7B, 0x5B):
            depth += 1
            if depth > maximum:
                abort(code, reason + "_DEPTH")
        elif byte in (0x7D, 0x5D):
            depth -= 1


def parse_strict_json(data, code=EXIT_SCHEMA, reason="MANIFEST"):
    if not isinstance(data, bytes) or len(data) > MAX_MANIFEST_BYTES or b"\0" in data:
        abort(code, reason + "_SIZE_OR_NUL")
    try:
        reject_excessive_json_nesting(data, code=code, reason=reason)
        text = data.decode("utf-8", "strict")
        value = json.loads(
            text,
            object_pairs_hook=duplicate_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("constant")),
        )
        reject_surrogate_strings(value, code, reason)
        return value
    except Failure:
        raise
    except (UnicodeError, ValueError, json.JSONDecodeError, RecursionError):
        abort(code, reason + "_JSON")


def parse_cli(argv):
    """Parse the fixed launcher context followed by the only public arguments."""
    if (len(argv) < 10 or argv[0] != "--repository" or argv[2] != "--launcher" or
            argv[4] != "--integrity-schema" or argv[6] != "--inventory-identity"):
        abort(EXIT_INTEGRITY, "LAUNCH_CONTEXT")
    if argv[8] != "--inventory-aggregate":
        abort(EXIT_INTEGRITY, "LAUNCH_CONTEXT")
    repository, launcher, schema_text = argv[1], argv[3], argv[5]
    identity, expected_aggregate = argv[7], argv[9]
    if (not repository or not launcher or not os.path.isabs(repository) or
            not os.path.isabs(launcher) or schema_text != str(INTEGRITY_SCHEMA_VERSION) or
            not isinstance(identity, str) or len(identity) != 64 or
            any(character not in "0123456789abcdef" for character in identity) or
            not isinstance(expected_aggregate, str) or len(expected_aggregate) != 64 or
            any(character not in "0123456789abcdef" for character in expected_aggregate)):
        abort(EXIT_INTEGRITY, "LAUNCH_CONTEXT")
    public = argv[10:]
    if public == ["--help"]:
        return {"mode": "help", "repository": repository, "launcher": launcher,
                "inventory_identity": identity, "inventory_aggregate": expected_aggregate}
    if "--help" in public:
        abort(EXIT_USAGE, "HELP_ARGUMENT")
    accepted = ("--manifest", "--output")
    prohibited = frozenset((
        "--config", "--policy", "--provider", "--adapter", "--plugin", "--command",
        "--executable", "--target", "--domain", "--token", "--credential",
        "--max-manifest", "--max-artifacts", "--max-input", "--workspace",
    ))
    values = {}
    index = 0
    while index < len(public):
        option = public[index]
        if option in prohibited or option not in accepted:
            abort(EXIT_USAGE, "UNKNOWN_ARGUMENT")
        if option in values:
            abort(EXIT_USAGE, "DUPLICATE_ARGUMENT")
        if index + 1 >= len(public):
            abort(EXIT_USAGE, "MISSING_VALUE")
        value = public[index + 1]
        if not isinstance(value, str) or not value or value.startswith("-"):
            abort(EXIT_USAGE, "INVALID_VALUE")
        values[option] = value
        index += 2
    if set(values) != set(accepted):
        abort(EXIT_USAGE, "MISSING_ARGUMENT")
    for option in accepted:
        validate_absolute_path(values[option], EXIT_USAGE, "CLI")
    if values["--manifest"] == values["--output"]:
        abort(EXIT_USAGE, "MANIFEST_OUTPUT_ALIAS")
    return {
        "mode": "validate", "repository": repository, "launcher": launcher,
        "inventory_identity": identity, "inventory_aggregate": expected_aggregate,
        "manifest": values["--manifest"], "output": values["--output"],
    }


def expected_context():
    core = os.path.abspath(__file__)
    repository = os.path.dirname(os.path.dirname(core))
    launcher = os.path.join(repository, "nullsec-wolt-stage2c.sh")
    return repository, launcher, core


def inventory_identity(paths):
    digest = hashlib.sha256()
    for path in sorted(paths):
        digest.update(path.encode("ascii") + b"\n")
    return digest.hexdigest()


EXPECTED_INVENTORY_IDENTITY = inventory_identity(PROTECTED_PATHS)


def aggregate_digest(files):
    digest = hashlib.sha256()
    for path in sorted(files):
        digest.update(path.encode("ascii") + b"\0" + files[path].encode("ascii") + b"\n")
    return digest.hexdigest()


def renameat2_function(libc, code, reason):
    try:
        library = libc if libc is not None else ctypes.CDLL(None, use_errno=True)
        function = getattr(library, "renameat2", None)
        if function is None:
            abort(code, reason + "_UNAVAILABLE")
        function.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                             ctypes.c_char_p, ctypes.c_uint)
        function.restype = ctypes.c_int
        return function
    except Failure:
        raise
    except BaseException:
        abort(code, reason + "_UNAVAILABLE")


def probe_rename_noreplace(libc=None):
    """Prove the syscall is implemented and reachable without naming an object."""
    function = renameat2_function(libc, EXIT_INTEGRITY, "RENAMEAT2")
    try:
        ctypes.set_errno(0)
        result = function(-1, None, -1, None, RENAME_NOREPLACE)
        number = ctypes.get_errno()
    except BaseException:
        abort(EXIT_INTEGRITY, "RENAMEAT2_PROBE")
    if result == -1 and number == errno.EFAULT:
        return
    abort(EXIT_INTEGRITY, "RENAMEAT2_PROBE")


def qualify_platform(libc=None):
    if (platform.system() != "Linux" or sys.version_info < MINIMUM_PYTHON or
            not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_NONBLOCK") or
            not hasattr(os, "O_DIRECTORY")):
        abort(EXIT_INTEGRITY, "PLATFORM")
    required_dir_fd = (os.open, os.stat, os.unlink, os.mkdir)
    if any(function not in os.supports_dir_fd for function in required_dir_fd):
        abort(EXIT_INTEGRITY, "DESCRIPTOR_RELATIVE")
    probe_rename_noreplace(libc)


def verify_context(cfg):
    repository, launcher, core = expected_context()
    if (cfg["repository"] != repository or cfg["launcher"] != launcher or
            cfg["inventory_identity"] != EXPECTED_INVENTORY_IDENTITY):
        abort(EXIT_INTEGRITY, "CONTEXT_MISMATCH")
    repository_fd = open_trusted_directory(repository, EXIT_INTEGRITY, "REPOSITORY")
    try:
        repository_stat = os.fstat(repository_fd)
        if repository_stat.st_uid != os.geteuid():
            abort(EXIT_INTEGRITY, "REPOSITORY_OWNER")
    finally:
        os.close(repository_fd)
    launcher_context = open_absolute_regular(launcher, EXIT_INTEGRITY, "LAUNCHER")
    try:
        launcher_stat = os.fstat(launcher_context["fd"])
        validate_regular(launcher_stat, EXIT_INTEGRITY, "LAUNCHER",
                         exact_mode=0o755)
    finally:
        close_context(launcher_context)
    return repository, launcher, core


def load_integrity_manifest(repository, expected_aggregate):
    path = os.path.join(repository, "config", "wolt-stage2c-integrity.json")
    context = open_absolute_regular(path, EXIT_INTEGRITY, "INTEGRITY_MANIFEST")
    try:
        validate_regular(os.fstat(context["fd"]), EXIT_INTEGRITY,
                         "INTEGRITY_MANIFEST", exact_mode=0o644)
        data, _digest, value = read_fd_stable(
            context["fd"], MAX_MANIFEST_BYTES, EXIT_INTEGRITY,
            "INTEGRITY_MANIFEST", ops=os)
        context["identity"] = file_identity(value)
        revalidate_open_file(context, EXIT_INTEGRITY, "INTEGRITY_MANIFEST")
    finally:
        close_context(context)
    manifest = parse_strict_json(data, EXIT_INTEGRITY, "INTEGRITY_MANIFEST")
    expected_keys = frozenset((
        "schema_version", "inventory_algorithm", "inventory_identity",
        "aggregate_algorithm", "aggregate_sha256", "protected_files", "protected_modes",
    ))
    if not isinstance(manifest, dict) or set(manifest) != expected_keys:
        abort(EXIT_INTEGRITY, "INTEGRITY_KEYS")
    if (type(manifest["schema_version"]) is not int or
            manifest["schema_version"] != INTEGRITY_SCHEMA_VERSION or
            manifest["inventory_algorithm"] != INVENTORY_ALGORITHM or
            manifest["aggregate_algorithm"] != AGGREGATE_ALGORITHM or
            manifest["inventory_identity"] != EXPECTED_INVENTORY_IDENTITY):
        abort(EXIT_INTEGRITY, "INTEGRITY_VALUES")
    files = manifest["protected_files"]
    modes = manifest["protected_modes"]
    if (not isinstance(files, dict) or not isinstance(modes, dict) or
            set(files) != PROTECTED_PATHS or set(modes) != PROTECTED_PATHS or
            inventory_identity(files) != EXPECTED_INVENTORY_IDENTITY):
        abort(EXIT_INTEGRITY, "INTEGRITY_INVENTORY")
    for path, digest in files.items():
        expected_mode = 0o755 if path in EXECUTABLE_PROTECTED_PATHS else 0o644
        if (not isinstance(digest, str) or len(digest) != 64 or
                any(character not in "0123456789abcdef" for character in digest) or
                type(modes[path]) is not int or modes[path] != expected_mode):
            abort(EXIT_INTEGRITY, "INTEGRITY_ENTRY")
    if (manifest["aggregate_sha256"] != expected_aggregate or
            manifest["aggregate_sha256"] != aggregate_digest(files)):
        abort(EXIT_INTEGRITY, "INTEGRITY_AGGREGATE")
    return manifest


def verify_integrity(cfg):
    repository, launcher, core = verify_context(cfg)
    manifest = load_integrity_manifest(repository, cfg["inventory_aggregate"])
    observed = {}
    for relative in sorted(PROTECTED_PATHS):
        absolute = os.path.join(repository, *relative.split("/"))
        context = open_absolute_regular(absolute, EXIT_INTEGRITY, "PROTECTED")
        try:
            expected_mode = manifest["protected_modes"][relative]
            before = os.fstat(context["fd"])
            validate_regular(before, EXIT_INTEGRITY, "PROTECTED",
                             exact_mode=expected_mode)
            data, digest, after = read_fd_stable(
                context["fd"], MAX_PROTECTED_BYTES, EXIT_INTEGRITY, "PROTECTED")
            del data
            context["identity"] = file_identity(after)
            revalidate_open_file(context, EXIT_INTEGRITY, "PROTECTED")
            observed[relative] = digest
        finally:
            close_context(context)
    if observed != manifest["protected_files"] or aggregate_digest(observed) != manifest["aggregate_sha256"]:
        abort(EXIT_INTEGRITY, "PROTECTED_DIGEST")
    return {"repository": repository, "launcher": launcher, "core": core,
            "aggregate": manifest["aggregate_sha256"]}


def parse_manifest_document(data, output_path):
    manifest = parse_strict_json(data)
    if not isinstance(manifest, dict) or set(manifest) != {"schema_version", "artifacts"}:
        abort(EXIT_SCHEMA, "MANIFEST_KEYS")
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
        abort(EXIT_SCHEMA, "MANIFEST_VERSION")
    artifacts = manifest["artifacts"]
    if (not isinstance(artifacts, list) or not artifacts or
            len(artifacts) > MAX_ARTIFACTS):
        abort(EXIT_SCHEMA, "ARTIFACT_COUNT")
    identifiers = set()
    paths = set()
    parsed = []
    profiles = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict) or set(artifact) != ARTIFACT_KEYS:
            abort(EXIT_SCHEMA, "ARTIFACT_KEYS")
        artifact_id = artifact["artifact_id"]
        source = artifact["source_id"]
        profile_name = artifact["profile"]
        retained_path = artifact["retained_path"]
        declared_digest = artifact["sha256"]
        declared_size = artifact["size_bytes"]
        if (not isinstance(artifact_id, str) or not artifact_id or
                len(artifact_id.encode("utf-8")) > MAX_ARTIFACT_ID_BYTES or
                artifact_id[0] not in "abcdefghijklmnopqrstuvwxyz0123456789" or
                artifact_id[-1] not in "abcdefghijklmnopqrstuvwxyz0123456789" or
                any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-"
                    for character in artifact_id)):
            abort(EXIT_SCHEMA, "ARTIFACT_ID")
        if artifact_id in identifiers:
            abort(EXIT_SCHEMA, "DUPLICATE_ARTIFACT_ID")
        if not isinstance(source, str) or source not in SOURCE_IDS:
            abort(EXIT_SCHEMA, "SOURCE")
        if not isinstance(profile_name, str) or profile_name not in PROFILES:
            abort(EXIT_SCHEMA, "PROFILE")
        if profile_name == "hostname-lines-v1" and source not in HOSTNAME_SOURCES:
            abort(EXIT_SCHEMA, "SOURCE_PROFILE")
        validate_absolute_path(retained_path, EXIT_SCHEMA, "RETAINED")
        if retained_path == output_path:
            abort(EXIT_INPUT, "RETAINED_OUTPUT_TEXT_ALIAS")
        if retained_path in paths:
            abort(EXIT_INPUT, "DUPLICATE_RETAINED_PATH")
        if (not isinstance(declared_digest, str) or len(declared_digest) != 64 or
                any(character not in "0123456789abcdef" for character in declared_digest)):
            abort(EXIT_SCHEMA, "DIGEST")
        if (type(declared_size) is not int or declared_size < 0 or
                declared_size > MAX_RETAINED_BYTES):
            abort(EXIT_SCHEMA, "SIZE")
        identifiers.add(artifact_id)
        paths.add(retained_path)
        profiles.add(profile_name)
        parsed.append({
            "artifact_id": artifact_id, "source_id": source, "profile": profile_name,
            "retained_path": retained_path, "sha256": declared_digest,
            "size_bytes": declared_size,
        })
    if len(profiles) != 1:
        abort(EXIT_INPUT, "MIXED_TRANSACTION_EVIDENCE")
    transaction_class = (
        "success-evidence" if next(iter(profiles)) == "hostname-lines-v1"
        else "provider-failure"
    )
    parsed.sort(key=lambda item: (
        item["artifact_id"], item["source_id"], item["profile"], item["retained_path"],
    ))
    return {"schema_version": 1, "artifacts": parsed,
            "transaction_class": transaction_class}


def validate_nonexistent_output(path, ops=os):
    parent_fd, name, parent, snapshot = open_parent(
        path, EXIT_PUBLICATION, "OUTPUT", require_euid_parent=True, ops=ops)
    try:
        try:
            ops.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError:
            abort(EXIT_PUBLICATION, "OUTPUT_INSPECT")
        else:
            abort(EXIT_USAGE, "OUTPUT_EXISTS_INITIAL")
        try:
            ops.fsync(parent_fd)
        except OSError:
            abort(EXIT_PUBLICATION, "OUTPUT_DIRECTORY_FSYNC_QUALIFICATION")
        return {"fd": parent_fd, "name": name, "path": path,
                "parent": parent, "parent_identity": snapshot}
    except BaseException:
        ops.close(parent_fd)
        raise


def revalidate_output_parent(context, ops=os):
    fresh = open_trusted_directory(context["parent"], EXIT_PUBLICATION, "OUTPUT_REWALK", ops)
    try:
        if directory_identity(ops.fstat(fresh)) != context["parent_identity"]:
            abort(EXIT_PUBLICATION, "OUTPUT_PARENT_REPLACED")
    finally:
        ops.close(fresh)
    if directory_identity(ops.fstat(context["fd"])) != context["parent_identity"]:
        abort(EXIT_PUBLICATION, "OUTPUT_PARENT_CHANGED")


def load_retained_manifest(path, output_context=None):
    context = open_absolute_regular(path, EXIT_INPUT, "MANIFEST")
    try:
        data, _digest, after = read_fd_stable(
            context["fd"], MAX_MANIFEST_BYTES, EXIT_INPUT, "MANIFEST")
        context["identity"] = file_identity(after)
        revalidate_open_file(context, EXIT_INPUT, "MANIFEST")
        if output_context is not None:
            try:
                appeared = os.stat(output_context["name"], dir_fd=output_context["fd"],
                                   follow_symlinks=False)
            except FileNotFoundError:
                appeared = None
            except OSError:
                abort(EXIT_PUBLICATION, "OUTPUT_RECHECK")
            if appeared is not None:
                if ((appeared.st_dev, appeared.st_ino) ==
                        (after.st_dev, after.st_ino)):
                    abort(EXIT_INPUT, "MANIFEST_OUTPUT_COLLISION")
                abort(EXIT_PUBLICATION, "OUTPUT_APPEARED")
        return data
    finally:
        close_context(context)


def validate_retained_artifacts(parsed, output_context):
    contexts = []
    inodes = set()
    total = 0
    try:
        for artifact in parsed["artifacts"]:
            context = open_absolute_regular(
                artifact["retained_path"], EXIT_INPUT, "RETAINED")
            contexts.append(context)
            before = os.fstat(context["fd"])
            validate_regular(before, EXIT_INPUT, "RETAINED")
            if before.st_size > MAX_RETAINED_BYTES:
                abort(EXIT_INPUT, "RETAINED_TOO_LARGE")
            inode = (before.st_dev, before.st_ino)
            if inode in inodes:
                abort(EXIT_INPUT, "DUPLICATE_RETAINED_INODE")
            if inode == (os.fstat(output_context["fd"]).st_dev,
                         os.fstat(output_context["fd"]).st_ino):
                abort(EXIT_INPUT, "RETAINED_OUTPUT_COLLISION")
            data, digest, after = read_fd_stable(
                context["fd"], MAX_RETAINED_BYTES, EXIT_INPUT, "RETAINED")
            del data
            context["identity"] = file_identity(after)
            if after.st_size != artifact["size_bytes"] or digest != artifact["sha256"]:
                abort(EXIT_INPUT, "RETAINED_DECLARATION_MISMATCH")
            total += after.st_size
            if total > MAX_TOTAL_RETAINED_BYTES:
                abort(EXIT_INPUT, "RETAINED_TOTAL")
            revalidate_open_file(context, EXIT_INPUT, "RETAINED")
            inodes.add(inode)
        try:
            appeared = os.stat(output_context["name"], dir_fd=output_context["fd"],
                               follow_symlinks=False)
        except FileNotFoundError:
            appeared = None
        except OSError:
            abort(EXIT_PUBLICATION, "OUTPUT_RECHECK")
        if appeared is not None:
            if (appeared.st_dev, appeared.st_ino) in inodes:
                abort(EXIT_INPUT, "RETAINED_OUTPUT_COLLISION")
            abort(EXIT_PUBLICATION, "OUTPUT_APPEARED")
        return contexts
    except BaseException:
        for context in contexts:
            close_context(context)
        raise


def validate_phase1(cfg):
    output_context = validate_nonexistent_output(cfg["output"])
    retained_contexts = []
    try:
        data = load_retained_manifest(cfg["manifest"], output_context)
        parsed = parse_manifest_document(data, cfg["output"])
        retained_contexts = validate_retained_artifacts(parsed, output_context)
        revalidate_output_parent(output_context)
        try:
            os.stat(output_context["name"], dir_fd=output_context["fd"],
                    follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError:
            abort(EXIT_PUBLICATION, "OUTPUT_FINAL_INSPECT")
        else:
            abort(EXIT_PUBLICATION, "OUTPUT_APPEARED")
        for context in retained_contexts:
            revalidate_open_file(context, EXIT_INPUT, "RETAINED")
        return parsed
    finally:
        for context in retained_contexts:
            close_context(context)
        close_context(output_context)




def help_text():
    return (
        "Usage: nullsec-wolt-stage2c.sh --help\n"
        "       nullsec-wolt-stage2c.sh --manifest ABSOLUTE_FILE "
        "--output ABSOLUTE_NONEXISTENT_PATH\n"
        "Phase 1 performs offline validation only; it does not orchestrate, "
        "classify, or publish.\n"
    )


def validate_launcher_result(status, stdout, stderr):
    """Return the only public result a fenced launcher may emit."""
    rejected = (EXIT_INTEGRITY, b"", b"STAGE2C_INTEGRITY_ERROR\n")
    if (type(status) is not int or type(stdout) is not bytes or
            type(stderr) is not bytes or
            len(stdout) > MAX_LAUNCH_RESULT_BYTES or
            len(stderr) > MAX_LAUNCH_RESULT_BYTES):
        return rejected
    if status == EXIT_OK and stderr == b"":
        if stdout == b"STAGE2C_PHASE1_VALIDATION_OK\n":
            return status, stdout, stderr
        expected_help = help_text().encode("ascii")
        if stdout == expected_help:
            return status, stdout, stderr
        return rejected
    expected_token = ERROR_TOKEN.get(status)
    if expected_token is not None and stdout == b"" and stderr == (
            expected_token + "\n").encode("ascii"):
        return status, stdout, stderr
    return rejected


def main(argv=None):
    try:
        verify_process_identity()
        qualify_platform()
        cfg = parse_cli(sys.argv[1:] if argv is None else argv)
        verify_integrity(cfg)
        if cfg["mode"] == "help":
            sys.stdout.write(help_text())
        else:
            transaction = validate_phase1(cfg)
            if transaction["transaction_class"] == "provider-failure":
                abort(EXIT_PROVIDER_FAILURE, "VALIDATED_PROVIDER_FAILURE")
            if transaction["transaction_class"] != "success-evidence":
                abort(EXIT_INTERNAL, "TRANSACTION_CLASS")
            sys.stdout.write("STAGE2C_PHASE1_VALIDATION_OK\n")
        return EXIT_OK
    except Failure as failure:
        token = ERROR_TOKEN.get(failure.code, ERROR_TOKEN[EXIT_INTERNAL])
        sys.stderr.write(token + "\n")
        return failure.code if failure.code in ERROR_TOKEN else EXIT_INTERNAL
    except BaseException:
        sys.stderr.write(ERROR_TOKEN[EXIT_INTERNAL] + "\n")
        return EXIT_INTERNAL


if __name__ == "__main__":
    raise SystemExit(main())
