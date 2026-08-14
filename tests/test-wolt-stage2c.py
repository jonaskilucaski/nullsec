#!/usr/bin/python3
"""Direct, bytecode-free unit and fault tests for Wolt Stage 2C Phase 2."""

import contextlib
import copy
import ctypes
import errno
import ast
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import socket
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock


sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "lib" / "wolt-stage2c.py"
LAUNCHER = ROOT / "nullsec-wolt-stage2c.sh"
INTEGRITY = ROOT / "config" / "wolt-stage2c-integrity.json"
EXTERNAL_TEMP_PARENT = Path("/tmp").resolve()
if EXTERNAL_TEMP_PARENT == ROOT or ROOT in EXTERNAL_TEMP_PARENT.parents:
    raise RuntimeError("external test root is inside repository")


def repository_inventory():
    inventory = []
    for base, directories, names in os.walk(ROOT, topdown=True, followlinks=False):
        if Path(base) == ROOT and ".git" in directories:
            directories.remove(".git")
        for name in sorted(directories + names):
            path = Path(base) / name
            relative = path.relative_to(ROOT).as_posix()
            value = path.lstat()
            digest = (hashlib.sha256(path.read_bytes()).hexdigest()
                      if stat.S_ISREG(value.st_mode) else None)
            inventory.append((relative, stat.S_IFMT(value.st_mode),
                              stat.S_IMODE(value.st_mode), digest))
    return tuple(sorted(inventory))


REPOSITORY_INVENTORY_BEFORE = repository_inventory()
TEMPORARY_ROOTS = set()

loader = importlib.machinery.SourceFileLoader("wolt_stage2c", str(CORE))
spec = importlib.util.spec_from_loader(loader.name, loader)
s2 = importlib.util.module_from_spec(spec)
loader.exec_module(s2)


def failure(testcase, code, function, *args, **kwargs):
    with testcase.assertRaises(s2.Failure) as caught:
        function(*args, **kwargs)
    testcase.assertEqual(caught.exception.code, code)
    return caught.exception


def internal_args(*public, repository=ROOT, launcher=LAUNCHER, identity=None,
                  aggregate=None):
    identity = s2.EXPECTED_INVENTORY_IDENTITY if identity is None else identity
    if aggregate is None:
        aggregate = json.loads(INTEGRITY.read_text(encoding="utf-8"))["aggregate_sha256"]
    return [
        "--repository", str(repository), "--launcher", str(launcher),
        "--integrity-schema", "1", "--inventory-identity", identity,
        "--inventory-aggregate", aggregate, *public,
    ]


def artifact(path, source="subfinder", profile="hostname-lines-v1", artifact_id="a-1",
             **changes):
    data = Path(path).read_bytes()
    value = {
        "artifact_id": artifact_id,
        "source_id": source,
        "profile": profile,
        "retained_path": str(path),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
    }
    value.update(changes)
    return value


def document(artifacts, **changes):
    value = {"schema_version": 1, "artifacts": artifacts}
    value.update(changes)
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def path_with_encoded_length(length):
    if length < 2:
        raise ValueError("absolute path length")
    components = []
    current = 1
    while length - current > 255:
        components.append("a" * 255)
        current += 256
    final = length - current
    if final == 0:
        components[-1] = components[-1][:-1]
        components.append("a")
    else:
        components.append("a" * final)
    return "/" + "/".join(components)


class TemporaryCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix=".stage2c-unit-", dir=str(EXTERNAL_TEMP_PARENT))
        self.directory = Path(self.temporary.name).resolve()
        TEMPORARY_ROOTS.add(self.directory)
        self.assertNotEqual(self.directory, ROOT)
        self.assertNotIn(ROOT, self.directory.parents)
        self.directory.chmod(0o700)

        # The production walk rejects /tmp because it is intentionally writable.
        # Filesystem-object tests retain all final-object checks while dedicated
        # ancestor tests below exercise the unpatched production traversal.
        def external_test_directory(path, code, reason, ops=os):
            flags = (ops.O_RDONLY | ops.O_DIRECTORY | ops.O_NOFOLLOW |
                     getattr(ops, "O_CLOEXEC", 0))
            try:
                descriptor = ops.open(path, flags)
                value = ops.fstat(descriptor)
                if (not stat.S_ISDIR(value.st_mode) or
                        value.st_uid not in (0, ops.geteuid()) or
                        s2.unsafe_mode(value.st_mode)):
                    ops.close(descriptor)
                    s2.abort(code, reason + "_TRUST")
                return descriptor
            except s2.Failure:
                raise
            except OSError:
                s2.abort(code, reason + "_OPEN")

        def external_test_chain(path, code, reason, ops=os):
            descriptor = external_test_directory(path, code, reason, ops)
            try:
                return [s2._ancestor_record(
                    descriptor, None, ops.fstat(descriptor))]
            except BaseException:
                ops.close(descriptor)
                raise

        self.trust_patch = mock.patch.object(
            s2, "open_trusted_directory", side_effect=external_test_directory)
        self.chain_patch = mock.patch.object(
            s2, "_open_trusted_directory_chain", side_effect=external_test_chain)
        self.trust_patch.start()
        self.chain_patch.start()

    def tearDown(self):
        try:
            self.chain_patch.stop()
            self.trust_patch.stop()
        finally:
            directory = self.directory
            self.temporary.cleanup()
            TEMPORARY_ROOTS.discard(directory)
            self.assertFalse(directory.exists())

    def write(self, name, data=b"data", mode=0o600):
        path = self.directory / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(data)
        path.chmod(mode)
        return path

    def output_context(self, name="output"):
        return s2.validate_nonexistent_output(str(self.directory / name))

    def run_main(self, manifest, output=None):
        output = self.directory / "output" if output is None else Path(output)
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (mock.patch.object(s2, "verify_process_identity"),
              mock.patch.object(s2, "qualify_platform"),
              mock.patch.object(s2, "verify_integrity"),
              mock.patch.object(s2, "orchestrate_phase2", return_value=[]),
              contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr)):
            code = s2.main(internal_args(
                "--manifest", str(manifest), "--output", str(output)))
        return code, stdout.getvalue(), stderr.getvalue(), output


class CliTests(unittest.TestCase):
    def test_help_is_the_only_help_form(self):
        cfg = s2.parse_cli(internal_args("--help"))
        self.assertEqual(cfg["mode"], "help")
        failure(self, 64, s2.parse_cli, internal_args("--help", "x"))

    def test_valid_parse(self):
        cfg = s2.parse_cli(internal_args("--manifest", "/a", "--output", "/b"))
        self.assertEqual((cfg["manifest"], cfg["output"]), ("/a", "/b"))

    def test_duplicate_unknown_missing_empty_positional_and_option_value(self):
        valid = ["--manifest", "/a", "--output", "/b"]
        cases = (
            valid + ["--output", "/c"], valid + ["--unknown", "x"],
            valid[:-2], ["--manifest", "", "--output", "/b"],
            valid + ["positional"],
            ["--manifest", "--output", "--output", "/b"],
            ["--manifest"], ["--config", "/x", *valid],
        )
        for case in cases:
            with self.subTest(case=case):
                failure(self, 64, s2.parse_cli, internal_args(*case))

    def test_absolute_length_and_alias_paths(self):
        failure(self, 64, s2.parse_cli,
                internal_args("--manifest", "relative", "--output", "/b"))
        failure(self, 64, s2.parse_cli,
                internal_args("--manifest", "/a", "--output", "relative"))
        failure(self, 64, s2.parse_cli,
                internal_args("--manifest", "/same", "--output", "/same"))
        self.assertEqual(len(os.fsencode(path_with_encoded_length(s2.MAX_PATH_BYTES))),
                         s2.MAX_PATH_BYTES)
        s2.validate_absolute_path(path_with_encoded_length(s2.MAX_PATH_BYTES), 64, "CLI")
        s2.validate_absolute_path(path_with_encoded_length(s2.MAX_PATH_BYTES - 1),
                                  64, "CLI")
        failure(self, 64, s2.validate_absolute_path,
                path_with_encoded_length(s2.MAX_PATH_BYTES + 1), 64, "CLI")

    def test_internal_context_is_fixed(self):
        failure(self, 2, s2.parse_cli, [])
        failure(self, 2, s2.parse_cli,
                internal_args("--help", aggregate="A" * 64))
        cfg = s2.parse_cli(internal_args("--help", identity="0" * 64))
        failure(self, 2, s2.verify_context, cfg)


class JsonAndSchemaTests(TemporaryCase):
    def parse(self, data, output=None):
        return s2.parse_manifest_document(
            data, str(self.directory / "output") if output is None else output)

    def test_strict_json_failures(self):
        cases = (
            b'{"schema_version":1,"schema_version":1,"artifacts":[]}',
            b'{"schema_version":1,"artifacts":[]}\xff',
            b'{"schema_version":1,"artifacts":[]} trailing',
            b'{"schema_version":1,"artifacts":[]}\0',
            b'{"schema_version":1,"artifacts":[{"x":1,"x":2}]}',
        )
        for data in cases:
            with self.subTest(data=data):
                failure(self, 4, self.parse, data)

    def test_surrogates_are_rejected_before_semantic_use(self):
        retained = self.write("retained")
        base = document([artifact(retained)])
        encoded_path = json.dumps(str(retained)).encode("utf-8")
        cases = (
            base.replace(b'"a-1"', b'"\\ud800"'),
            base.replace(encoded_path, b'"\\udc00"'),
            base.replace(b'"a-1"', b'"\\ud83d\\ude00"'),
            b'{"schema_version":1,"artifacts":[],"\\ud800":0}',
            b'"\\ud800"',
            b'{"schema_version":"\\udc00","artifacts":[]}',
        )
        for data in cases:
            with self.subTest(data=data):
                manifest = self.write("manifest.json", data)
                code, stdout, stderr, _output = self.run_main(manifest)
                self.assertEqual((code, stdout, stderr),
                                 (4, "", "STAGE2C_SCHEMA_ERROR\n"))

    def test_manifest_and_json_depth_boundaries(self):
        exact = b"{}" + b" " * (s2.MAX_MANIFEST_BYTES - 2)
        below = exact[:-1]
        self.assertEqual(s2.parse_strict_json(below), {})
        self.assertEqual(s2.parse_strict_json(exact), {})
        failure(self, 4, s2.parse_strict_json, exact + b" ")
        with mock.patch.object(s2, "MAX_MANIFEST_BYTES", 0):
            failure(self, 4, s2.parse_strict_json, b"0")
        self.assertEqual(s2.parse_strict_json(b"0"), 0)
        nested = b"[" * s2.MAX_JSON_DEPTH + b"0" + b"]" * s2.MAX_JSON_DEPTH
        s2.parse_strict_json(nested)
        s2.parse_strict_json(nested[1:-1])
        failure(self, 4, s2.parse_strict_json, b"[" + nested + b"]")
        with mock.patch.object(s2, "MAX_JSON_DEPTH", 0):
            self.assertEqual(s2.parse_strict_json(b"0"), 0)
        failure(self, 4, s2.reject_excessive_json_nesting,
                b"[0]", 0)

    def test_schema_types_fields_and_booleans(self):
        retained = self.write("retained")
        valid = artifact(retained)
        cases = (
            b"[]", b'{"schema_version":true,"artifacts":[]}',
            b'{"schema_version":1,"artifacts":[]}',
            document(True),
            document([{key: value for key, value in valid.items() if key != "sha256"}]),
            document([{**valid, "extra": 1}]),
            document([{**valid, "size_bytes": True}]),
        )
        for data in cases:
            failure(self, 4, self.parse, data)

    def test_identifier_boundaries(self):
        retained = self.write("retained")
        for identifier in ("", "-bad", "bad-", "Upper", "bad_name", "é"):
            failure(self, 4, self.parse,
                    document([artifact(retained, artifact_id=identifier)]))
        below = "a" * (s2.MAX_ARTIFACT_ID_BYTES - 1)
        exact = "a" * s2.MAX_ARTIFACT_ID_BYTES
        self.parse(document([artifact(retained, artifact_id=below)]))
        self.parse(document([artifact(retained, artifact_id=exact)]))
        failure(self, 4, self.parse,
                document([artifact(retained, artifact_id=exact + "a")]))

    def test_artifact_count_zero_below_exact_and_above(self):
        failure(self, 4, self.parse, document([]))
        artifacts = []
        for index in range(s2.MAX_ARTIFACTS + 1):
            retained = self.write("retained-" + str(index))
            artifacts.append(artifact(
                retained, source="subfinder",
                artifact_id="a-" + str(index)))
        self.assertEqual(len(self.parse(document(
            artifacts[:s2.MAX_ARTIFACTS - 1]))["artifacts"]), 31)
        self.assertEqual(len(self.parse(document(
            artifacts[:s2.MAX_ARTIFACTS]))["artifacts"]), 32)
        failure(self, 4, self.parse,
                document(artifacts[:s2.MAX_ARTIFACTS + 1]))

    def test_source_profile_matrix_mixed_and_duplicates(self):
        first = self.write("one")
        second = self.write("two")
        for source in sorted(s2.HOSTNAME_SOURCES):
            result = self.parse(document([artifact(first, source=source)]))
            self.assertEqual(result["transaction_class"], "success-evidence")
        for source in sorted(s2.SOURCE_IDS):
            result = self.parse(document([artifact(
                first, source=source, profile="retained-provider-failure-v1")]))
            self.assertEqual(result["transaction_class"], "provider-failure")
        mixed = [artifact(first), artifact(
            second, source="assetfinder", profile="retained-provider-failure-v1",
            artifact_id="a-2")]
        failure(self, 3, self.parse, document(mixed))
        failure(self, 4, self.parse, document([
            artifact(first), artifact(second, source="assetfinder", artifact_id="a-1")]))
        repeated = self.parse(document([
            artifact(first), artifact(second, source="subfinder", artifact_id="a-2")]))
        self.assertEqual(len(repeated["artifacts"]), 2)
        failure(self, 3, self.parse, document([
            artifact(first), artifact(first, source="assetfinder", artifact_id="a-2")]))
        failure(self, 4, self.parse, document([
            artifact(first, source="virustotal")]))

    def test_digest_size_and_path_schema_boundaries(self):
        retained = self.write("retained")
        for digest in ("0" * 63, "A" * 64, "g" * 64, 7):
            failure(self, 4, self.parse,
                    document([artifact(retained, sha256=digest)]))
        self.parse(document([artifact(
            retained, size_bytes=s2.MAX_RETAINED_BYTES - 1)]))
        self.parse(document([artifact(
            retained, size_bytes=s2.MAX_RETAINED_BYTES)]))
        for size in (-1, True, s2.MAX_RETAINED_BYTES + 1):
            failure(self, 4, self.parse,
                    document([artifact(retained, size_bytes=size)]))
        failure(self, 4, self.parse,
                document([artifact(retained, retained_path="relative")]))
        failure(self, 3, self.parse, document([artifact(
            retained, retained_path=str(self.directory / "output"))]))

    def test_deterministic_ordering(self):
        one = self.write("one")
        two = self.write("two")
        values = [artifact(two, source="assetfinder", artifact_id="z"),
                  artifact(one, source="subfinder", artifact_id="a")]
        first = self.parse(document(values))["artifacts"]
        second = self.parse(document(list(reversed(values))))["artifacts"]
        self.assertEqual(first, second)
        self.assertEqual([item["artifact_id"] for item in first], ["a", "z"])


class ManifestBoundaryTests(TemporaryCase):
    def assert_main_failure(self, manifest, code, token):
        result, stdout, stderr, _output = self.run_main(manifest)
        self.assertEqual((result, stdout, stderr), (code, "", token + "\n"))

    def test_manifest_filesystem_objects_are_input_errors(self):
        nonexistent = self.directory / "missing.json"
        self.assert_main_failure(nonexistent, 3, "STAGE2C_INPUT_ERROR")
        regular = self.write("regular.json", b"{}")
        symlink = self.directory / "manifest-symlink"
        symlink.symlink_to(regular)
        fifo = self.directory / "manifest-fifo"
        os.mkfifo(fifo, 0o600)
        directory = self.directory / "manifest-directory"
        directory.mkdir(mode=0o700)
        unsafe = self.write("manifest-unsafe.json", b"{}", 0o622)
        socket_path = self.directory / "manifest-socket"
        local_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        values = [symlink, fifo, directory, unsafe]
        try:
            try:
                local_socket.bind(str(socket_path))
                values.append(socket_path)
            except PermissionError:
                pass
            for value in values:
                with self.subTest(path=value):
                    self.assert_main_failure(value, 3, "STAGE2C_INPUT_ERROR")
        finally:
            local_socket.close()

    def test_manifest_replacement_and_stability_are_input_errors(self):
        retained = self.write("retained")
        manifest = self.write("manifest.json", document([artifact(retained)]))
        with mock.patch.object(
                s2, "revalidate_open_file", side_effect=s2.Failure(3, "secret-path")):
            self.assert_main_failure(manifest, 3, "STAGE2C_INPUT_ERROR")

    def test_manifest_oversize_is_input_but_documents_are_schema(self):
        oversized = self.write("oversized.json", b" " * (s2.MAX_MANIFEST_BYTES + 1))
        self.assert_main_failure(oversized, 3, "STAGE2C_INPUT_ERROR")
        malformed = self.write("malformed.json", b'{"schema_version":')
        self.assert_main_failure(malformed, 4, "STAGE2C_SCHEMA_ERROR")
        duplicate = self.write(
            "duplicate.json",
            b'{"schema_version":1,"schema_version":1,"artifacts":[]}')
        self.assert_main_failure(duplicate, 4, "STAGE2C_SCHEMA_ERROR")

    def test_manifest_output_descriptor_collision_is_input(self):
        manifest = self.write("manifest.json", b"{}")
        output = self.output_context()
        original_stat = os.stat
        manifest_stat = manifest.stat()

        def collision_stat(name, *args, **kwargs):
            if name == output["name"] and kwargs.get("dir_fd") == output["fd"]:
                return manifest_stat
            return original_stat(name, *args, **kwargs)

        try:
            with mock.patch.object(s2.os, "stat", side_effect=collision_stat):
                failure(self, 3, s2.load_retained_manifest,
                        str(manifest), output)
        finally:
            s2.close_context(output)


class FileValidationTests(TemporaryCase):
    def parsed(self, paths, profile="hostname-lines-v1"):
        sources = ["subfinder", "assetfinder", "amass"]
        values = [artifact(path, source=sources[index], profile=profile,
                           artifact_id="a-" + str(index))
                  for index, path in enumerate(paths)]
        return s2.parse_manifest_document(document(values), str(self.directory / "output"))

    def validate(self, parsed, output_name="output"):
        output = self.output_context(output_name)
        try:
            contexts = s2.validate_retained_artifacts(parsed, output)
            for context in contexts:
                s2.close_context(context)
        finally:
            s2.close_context(output)

    def test_individual_and_total_retained_boundaries(self):
        below = self.write("below", b"ab")
        exact = self.write("exact", b"abc")
        above = self.write("above", b"abcd")
        below_parsed = self.parsed([below])
        exact_parsed = self.parsed([exact])
        above_parsed = self.parsed([above])
        with mock.patch.object(s2, "MAX_RETAINED_BYTES", 3):
            self.validate(below_parsed, "below-output")
            self.validate(exact_parsed, "exact-output")
            output = self.output_context("above-output")
            try:
                failure(self, 3, s2.validate_retained_artifacts, above_parsed, output)
            finally:
                s2.close_context(output)
        one = self.write("total-one", b"a")
        two = self.write("total-two", b"bc")
        extra = self.write("total-extra", b"d")
        with mock.patch.object(s2, "MAX_TOTAL_RETAINED_BYTES", 3):
            self.validate(self.parsed([one]), "total-below")
            self.validate(self.parsed([one, two]), "total-exact")
            parsed = self.parsed([one, two, extra])
            output = self.output_context("total-above")
            try:
                failure(self, 3, s2.validate_retained_artifacts, parsed, output)
            finally:
                s2.close_context(output)
        empty = self.write("total-zero", b"")
        with mock.patch.object(s2, "MAX_TOTAL_RETAINED_BYTES", 0):
            self.validate(self.parsed([empty]), "total-zero-output")

    def test_real_object_rejection(self):
        regular = self.write("regular")
        symlink = self.directory / "symlink"
        symlink.symlink_to(regular)
        fifo = self.directory / "fifo"
        os.mkfifo(fifo, 0o600)
        hardlink = self.directory / "hardlink"
        os.link(regular, hardlink)
        directory = self.directory / "directory"
        directory.mkdir(mode=0o700)
        socket_path = self.directory / "socket"
        local_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        paths = [symlink, fifo, directory, regular, hardlink]
        try:
            try:
                local_socket.bind(str(socket_path))
                paths.append(socket_path)
            except PermissionError:
                pass
            for path in paths:
                with self.subTest(path=path):
                    failure(self, 3, s2.open_absolute_regular,
                            str(path), 3, "RETAINED")
        finally:
            local_socket.close()
        device = types.SimpleNamespace(
            st_mode=stat.S_IFCHR | 0o600, st_uid=os.geteuid(), st_gid=os.getegid(),
            st_nlink=1)
        failure(self, 3, s2.validate_regular, device, 3, "RETAINED")

    def test_duplicate_retained_inode_identity_remains_rejected(self):
        first = self.write("inode-one", b"one")
        second = self.write("inode-two", b"two")
        parsed = s2.parse_manifest_document(document([
            artifact(first, source="subfinder", artifact_id="inode-1"),
            artifact(second, source="subfinder", artifact_id="inode-2"),
        ]), str(self.directory / "inode-output"))
        output = self.output_context("inode-output")
        opened = []
        original_open = s2.open_absolute_regular
        original_fstat = os.fstat

        def capture_open(*args, **kwargs):
            context = original_open(*args, **kwargs)
            opened.append(context)
            return context

        def duplicate_inode_fstat(descriptor):
            value = original_fstat(descriptor)
            if len(opened) >= 2 and descriptor == opened[1]["fd"]:
                fields = list(value)
                first_value = original_fstat(opened[0]["fd"])
                fields[stat.ST_INO] = first_value.st_ino
                fields[stat.ST_DEV] = first_value.st_dev
                return os.stat_result(fields)
            return value

        try:
            with (mock.patch.object(
                    s2, "open_absolute_regular", side_effect=capture_open),
                  mock.patch.object(s2.os, "fstat", side_effect=duplicate_inode_fstat)):
                caught = failure(
                    self, 3, s2.validate_retained_artifacts, parsed, output)
            self.assertEqual(caught.reason, "DUPLICATE_RETAINED_INODE")
        finally:
            s2.close_context(output)

    def test_unsafe_mode_owner_replacement_and_short_read(self):
        unsafe = self.write("unsafe", mode=0o622)
        failure(self, 3, s2.open_absolute_regular, str(unsafe), 3, "RETAINED")
        owner = types.SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600, st_uid=os.geteuid() + 1000,
            st_gid=os.getegid(), st_nlink=1)
        failure(self, 3, s2.validate_regular, owner, 3, "RETAINED")
        retained = self.write("retained", b"one")
        context = s2.open_absolute_regular(str(retained), 3, "RETAINED")
        try:
            _data, _digest, value = s2.read_fd_stable(context["fd"], 100, 3, "RETAINED")
            context["identity"] = s2.file_identity(value)
            replacement = self.write("replacement", b"two")
            os.replace(replacement, retained)
            failure(self, 3, s2.revalidate_open_file, context, 3, "RETAINED")
        finally:
            s2.close_context(context)
        value = types.SimpleNamespace(
            st_dev=1, st_ino=2, st_size=3, st_mode=stat.S_IFREG | 0o600,
            st_uid=os.geteuid(), st_gid=os.getegid(), st_nlink=1,
            st_mtime_ns=1, st_ctime_ns=1)
        ops = types.SimpleNamespace(
            geteuid=os.geteuid, fstat=lambda _fd: value,
            read=mock.Mock(side_effect=[b"ab", b""]))
        failure(self, 3, s2.read_fd_stable, 5, 10, 3, "RETAINED", ops=ops)

    def test_protected_read_limit_boundaries(self):
        below = self.write("protected-below", b"ab")
        value = self.write("protected", b"abc")
        below_descriptor = os.open(below, os.O_RDONLY)
        descriptor = os.open(value, os.O_RDONLY)
        try:
            with mock.patch.object(s2, "MAX_PROTECTED_BYTES", 3):
                s2.read_fd_stable(
                    below_descriptor, s2.MAX_PROTECTED_BYTES, 2, "PROTECTED")
                s2.read_fd_stable(descriptor, s2.MAX_PROTECTED_BYTES, 2, "PROTECTED")
                os.lseek(descriptor, 0, os.SEEK_SET)
                failure(self, 2, s2.read_fd_stable, descriptor,
                        s2.MAX_PROTECTED_BYTES - 1, 2, "PROTECTED")
        finally:
            os.close(below_descriptor)
            os.close(descriptor)


class TrustedAncestorTests(unittest.TestCase):
    def test_real_safe_nested_walk_and_real_unsafe_ancestor(self):
        root_owner = os.stat("/").st_uid
        ops = types.SimpleNamespace(
            O_RDONLY=os.O_RDONLY, O_DIRECTORY=os.O_DIRECTORY,
            O_NOFOLLOW=os.O_NOFOLLOW, O_CLOEXEC=getattr(os, "O_CLOEXEC", 0),
            open=os.open, fstat=os.fstat, close=os.close,
            geteuid=lambda: root_owner)
        descriptor = s2.open_trusted_directory("/", 3, "REAL", ops)
        os.close(descriptor)
        failure(self, 3, s2.open_trusted_directory, "/tmp", 3, "REAL", ops)

    def test_symlinked_intermediate_and_replacement_during_walk(self):
        safe = types.SimpleNamespace(
            st_dev=1, st_ino=1, st_mode=stat.S_IFDIR | 0o755,
            st_uid=os.geteuid(), st_gid=os.getegid())
        unsafe = types.SimpleNamespace(
            st_dev=1, st_ino=3, st_mode=stat.S_IFDIR | 0o777,
            st_uid=os.geteuid(), st_gid=os.getegid())

        opened_safe = iter((20, 21, 22))
        safe_ops = types.SimpleNamespace(
            O_RDONLY=os.O_RDONLY, O_DIRECTORY=os.O_DIRECTORY,
            O_NOFOLLOW=os.O_NOFOLLOW, O_CLOEXEC=getattr(os, "O_CLOEXEC", 0),
            open=lambda *_args, **_kwargs: next(opened_safe),
            fstat=lambda _fd: safe, close=lambda _fd: None,
            geteuid=os.geteuid)
        descriptor = s2.open_trusted_directory(
            "/safe/nested", 3, "WALK", safe_ops)
        self.assertEqual(descriptor, 22)

        def symlink_open(name, _flags, dir_fd=None):
            if name == "/":
                return 10
            if name == "safe" and dir_fd == 10:
                return 11
            raise OSError(errno.ELOOP, "symlink")

        symlink_ops = types.SimpleNamespace(
            O_RDONLY=os.O_RDONLY, O_DIRECTORY=os.O_DIRECTORY,
            O_NOFOLLOW=os.O_NOFOLLOW, O_CLOEXEC=getattr(os, "O_CLOEXEC", 0),
            open=symlink_open, fstat=lambda _fd: safe, close=lambda _fd: None,
            geteuid=os.geteuid)
        failure(self, 3, s2.open_trusted_directory,
                "/safe/link/child", 3, "WALK", symlink_ops)

        opened = iter((10, 11, 12))
        replacement_ops = types.SimpleNamespace(
            O_RDONLY=os.O_RDONLY, O_DIRECTORY=os.O_DIRECTORY,
            O_NOFOLLOW=os.O_NOFOLLOW, O_CLOEXEC=getattr(os, "O_CLOEXEC", 0),
            open=lambda *_args, **_kwargs: next(opened),
            fstat=lambda fd: unsafe if fd == 12 else safe,
            close=lambda _fd: None, geteuid=os.geteuid)
        failure(self, 3, s2.open_trusted_directory,
                "/safe/replaced", 3, "WALK", replacement_ops)


class AncestorChainBindingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix=".stage2c-ancestor-", dir=str(EXTERNAL_TEMP_PARENT))
        self.directory = Path(self.temporary.name).resolve()
        TEMPORARY_ROOTS.add(self.directory)
        self.directory.chmod(0o700)

    def tearDown(self):
        directory = self.directory
        self.temporary.cleanup()
        TEMPORARY_ROOTS.discard(directory)
        self.assertFalse(directory.exists())

    def nested_file(self, name="retained", data=b"data"):
        safe = self.directory / "safe"
        nested = safe / "nested"
        safe.mkdir(exist_ok=True, mode=0o700)
        safe.chmod(0o700)
        nested.mkdir(exist_ok=True, mode=0o700)
        nested.chmod(0o700)
        path = nested / name
        path.write_bytes(data)
        path.chmod(0o600)
        return path

    def output_directory(self, path, code, reason, ops=os):
        flags = (ops.O_RDONLY | ops.O_DIRECTORY | ops.O_NOFOLLOW |
                 getattr(ops, "O_CLOEXEC", 0))
        try:
            return ops.open(path, flags)
        except OSError:
            s2.abort(code, reason + "_OPEN")

    def run_main(self, manifest, output, *extra_patches):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(s2, "verify_process_identity"))
            stack.enter_context(mock.patch.object(s2, "qualify_platform"))
            stack.enter_context(mock.patch.object(s2, "verify_integrity"))
            stack.enter_context(mock.patch.object(
                s2, "orchestrate_phase2", return_value=[]))
            stack.enter_context(mock.patch.object(
                s2, "_validate_trusted_ancestor",
                side_effect=self.sandbox_ancestor_validator))
            stack.enter_context(mock.patch.object(
                s2, "open_trusted_directory", side_effect=self.output_directory))
            for patch in extra_patches:
                stack.enter_context(patch)
            stack.enter_context(contextlib.redirect_stdout(stdout))
            stack.enter_context(contextlib.redirect_stderr(stderr))
            code = s2.main(internal_args(
                "--manifest", str(manifest), "--output", str(output)))
        return code, stdout.getvalue(), stderr.getvalue()

    def sandbox_ancestor_validator(self, value, code, reason, ops=os):
        root_owner = os.stat("/").st_uid
        tmp_identity = (os.stat("/tmp").st_dev, os.stat("/tmp").st_ino)
        if (not stat.S_ISDIR(value.st_mode) or
                value.st_uid not in (0, ops.geteuid(), root_owner) or
                (s2.unsafe_mode(value.st_mode) and
                 (value.st_dev, value.st_ino) != tmp_identity)):
            s2.abort(code, reason + "_TRUST")

    def sandbox_trust_patch(self):
        return mock.patch.object(
            s2, "_validate_trusted_ancestor",
            side_effect=self.sandbox_ancestor_validator)

    def assert_descriptors_closed(self, descriptors):
        self.assertTrue(descriptors)
        for descriptor in descriptors:
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_real_safe_nested_chain_succeeds_and_all_descriptors_close(self):
        with self.sandbox_trust_patch():
            context = s2.open_absolute_regular(str(CORE), 3, "REAL_SAFE")
        descriptors = [record["fd"] for record in context["ancestors"]]
        try:
            _data, _digest, value = s2.read_fd_stable(
                context["fd"], s2.MAX_PROTECTED_BYTES, 3, "REAL_SAFE")
            context["identity"] = s2.file_identity(value)
            with self.sandbox_trust_patch():
                s2.revalidate_open_file(context, 3, "REAL_SAFE")
            self.assertGreater(len(descriptors), 2)
        finally:
            s2.close_context(context)
        self.assert_descriptors_closed(descriptors)

    def test_unsafe_and_symlinked_intermediate_ancestors_are_rejected(self):
        unsafe_parent = self.directory / "unsafe"
        unsafe_parent.mkdir(mode=0o700)
        unsafe_parent.chmod(0o777)
        unsafe_file = unsafe_parent / "value"
        unsafe_file.write_bytes(b"data")
        unsafe_file.chmod(0o600)
        with self.sandbox_trust_patch():
            failure(self, 3, s2.open_absolute_regular,
                    str(unsafe_file), 3, "UNSAFE_INTERMEDIATE")
        target = self.directory / "target"
        target.mkdir(mode=0o700)
        target_file = target / "value"
        target_file.write_bytes(b"data")
        target_file.chmod(0o600)
        link = self.directory / "link"
        link.symlink_to(target, target_is_directory=True)
        with self.sandbox_trust_patch():
            failure(self, 3, s2.open_absolute_regular,
                    str(link / "value"), 3, "SYMLINK_INTERMEDIATE")

    def open_nested_context(self):
        retained = self.nested_file()
        trust = self.sandbox_trust_patch()
        trust.start()
        try:
            context = s2.open_absolute_regular(str(retained), 3, "RETAINED")
            _data, _digest, value = s2.read_fd_stable(
                context["fd"], s2.MAX_RETAINED_BYTES, 3, "RETAINED")
            context["identity"] = s2.file_identity(value)
            return retained, context, trust
        except BaseException:
            trust.stop()
            raise

    def test_safe_looking_replacement_and_detached_ancestor_are_rejected(self):
        for replacement in (True, False):
            with self.subTest(replacement=replacement):
                retained, context, trust = self.open_nested_context()
                ancestor = self.directory / "safe"
                detached = self.directory / ("detached-" + str(int(replacement)))
                descriptors = [record["fd"] for record in context["ancestors"]]
                try:
                    ancestor.rename(detached)
                    if replacement:
                        ancestor.mkdir(mode=0o700)
                    failure(self, 3, s2.revalidate_open_file,
                            context, 3, "RETAINED")
                finally:
                    s2.close_context(context)
                    trust.stop()
                self.assertTrue(retained.parent.parent == ancestor)
                self.assert_descriptors_closed(descriptors)

    def test_authenticated_ancestor_mode_change_is_rejected(self):
        _retained, context, trust = self.open_nested_context()
        ancestor = self.directory / "safe"
        try:
            ancestor.chmod(0o750)
            failure(self, 3, s2.revalidate_open_file,
                    context, 3, "RETAINED")
        finally:
            s2.close_context(context)
            trust.stop()

    def test_manifest_ancestor_replacement_is_exact_input_failure_and_closes(self):
        retained = self.directory / "retained"
        retained.write_bytes(b"hostname\n")
        retained.chmod(0o600)
        manifest = self.nested_file(
            "manifest.json", document([artifact(retained)]))
        ancestor = self.directory / "safe"
        detached = self.directory / "manifest-detached"
        captured = []
        original_chain = s2._open_trusted_directory_chain
        original_read = s2.read_fd_stable
        changed = False

        def capture_chain(*args, **kwargs):
            chain = original_chain(*args, **kwargs)
            captured.extend(record["fd"] for record in chain)
            return chain

        def replace_after_read(*args, **kwargs):
            nonlocal changed
            result = original_read(*args, **kwargs)
            reason = args[3] if len(args) > 3 else kwargs.get("reason")
            if reason == "MANIFEST" and not changed:
                ancestor.rename(detached)
                ancestor.mkdir(mode=0o700)
                changed = True
            return result

        result = self.run_main(
            manifest, self.directory / "manifest-output",
            mock.patch.object(s2, "_open_trusted_directory_chain",
                              side_effect=capture_chain),
            mock.patch.object(s2, "read_fd_stable", side_effect=replace_after_read))
        self.assertEqual(result, (3, "", "STAGE2C_INPUT_ERROR\n"))
        self.assertNotIn("manifest.json", result[2])
        self.assertNotIn("manifest-detached", result[2])
        self.assertTrue(changed)
        self.assert_descriptors_closed(captured)

    def test_retained_ancestor_detachment_is_exact_input_failure_and_closes(self):
        retained = self.nested_file(data=b"hostname\n")
        manifest = self.directory / "manifest.json"
        manifest.write_bytes(document([artifact(retained)]))
        manifest.chmod(0o600)
        ancestor = self.directory / "safe"
        detached = self.directory / "retained-detached"
        captured = []
        original_chain = s2._open_trusted_directory_chain
        original_read = s2.read_fd_stable
        changed = False

        def capture_chain(*args, **kwargs):
            chain = original_chain(*args, **kwargs)
            captured.extend(record["fd"] for record in chain)
            return chain

        def detach_after_read(*args, **kwargs):
            nonlocal changed
            result = original_read(*args, **kwargs)
            reason = args[3] if len(args) > 3 else kwargs.get("reason")
            if reason == "RETAINED" and not changed:
                ancestor.rename(detached)
                changed = True
            return result

        result = self.run_main(
            manifest, self.directory / "retained-output",
            mock.patch.object(s2, "_open_trusted_directory_chain",
                              side_effect=capture_chain),
            mock.patch.object(s2, "read_fd_stable", side_effect=detach_after_read))
        self.assertEqual(result, (3, "", "STAGE2C_INPUT_ERROR\n"))
        self.assertNotIn(str(retained), result[2])
        self.assertNotIn("retained-detached", result[2])
        self.assertTrue(changed)
        self.assert_descriptors_closed(captured)


class PlatformQualificationTests(TemporaryCase):
    class Function:
        argtypes = None
        restype = None

        def __init__(self, number, result=-1):
            self.number = number
            self.result = result

        def __call__(self, *_args):
            ctypes.set_errno(self.number)
            return self.result

    def library(self, number, result=-1):
        return types.SimpleNamespace(renameat2=self.Function(number, result))

    def test_missing_blocked_unsupported_and_unexpected_probe_results(self):
        failure(self, 2, s2.qualify_platform, object())
        for number in (errno.ENOSYS, errno.EPERM, errno.EACCES, errno.EINVAL):
            with self.subTest(number=number):
                failure(self, 2, s2.qualify_platform, self.library(number))
        failure(self, 2, s2.qualify_platform, self.library(0, result=0))

    def test_expected_probe_errno_and_actual_runtime_probe(self):
        s2.qualify_platform(self.library(errno.EFAULT))
        before = repository_inventory()
        s2.probe_rename_noreplace()
        self.assertEqual(repository_inventory(), before)

    def test_platform_probe_remains_qualification_only(self):
        self.assertTrue(callable(s2.probe_rename_noreplace))
        self.assertFalse(hasattr(s2, "rename_noreplace"))


class PhaseResultTests(TemporaryCase):
    def test_repeated_sources_succeed_and_provider_fail_after_validation(self):
        first = self.write("repeat-one", b"one\n")
        second = self.write("repeat-two", b"two\n")
        success_manifest = self.write("repeat-success.json", document([
            artifact(first, source="subfinder", artifact_id="repeat-1"),
            artifact(second, source="subfinder", artifact_id="repeat-2"),
        ]))
        code, stdout, stderr, output = self.run_main(
            success_manifest, self.directory / "repeat-success-output")
        self.assertEqual((code, stdout, stderr),
                         (0, "STAGE2C_PHASE2_ORCHESTRATION_OK\n", ""))
        self.assertFalse(output.exists())

        provider_manifest = self.write("repeat-provider.json", document([
            artifact(first, source="shodan",
                     profile="retained-provider-failure-v1", artifact_id="failure-1"),
            artifact(second, source="shodan",
                     profile="retained-provider-failure-v1", artifact_id="failure-2"),
        ]))
        code, stdout, stderr, output = self.run_main(
            provider_manifest, self.directory / "repeat-provider-output")
        self.assertEqual((code, stdout, stderr),
                         (7, "", "STAGE2C_PROVIDER_FAILURE\n"))
        self.assertFalse(output.exists())

    def test_real_artifact_count_boundary_through_main(self):
        values = []
        for index in range(s2.MAX_ARTIFACTS + 1):
            retained = self.write("boundary-" + str(index), b"value\n")
            values.append(artifact(
                retained, source="subfinder", artifact_id="boundary-" + str(index)))
        for count in (s2.MAX_ARTIFACTS - 1, s2.MAX_ARTIFACTS):
            with self.subTest(count=count):
                manifest = self.write(
                    "boundary-manifest-" + str(count), document(values[:count]))
                code, stdout, stderr, output = self.run_main(
                    manifest, self.directory / ("boundary-output-" + str(count)))
                self.assertEqual((code, stdout, stderr),
                                 (0, "STAGE2C_PHASE2_ORCHESTRATION_OK\n", ""))
                self.assertFalse(output.exists())
        manifest = self.write("boundary-manifest-above", document(values))
        code, stdout, stderr, output = self.run_main(
            manifest, self.directory / "boundary-output-above")
        self.assertEqual((code, stdout, stderr),
                         (4, "", "STAGE2C_SCHEMA_ERROR\n"))
        self.assertFalse(output.exists())

    def test_phase1_ignores_inserted_registries_authority_and_rename_dispatch(self):
        retained = self.write("retained", b"hostname\n")
        output_success = self.directory / "success-output"
        success_manifest = self.write(
            "success.json", document([artifact(retained)]))
        attacker = mock.Mock()
        with (mock.patch.object(s2, "workspace_records", {"forged": object()},
                               create=True),
              mock.patch.object(s2, "sealed_records", {"forged": object()},
                                create=True),
              mock.patch.object(s2, "seal_workspace_file", attacker, create=True),
              mock.patch.object(s2, "publish_workspace_entry", attacker, create=True),
              mock.patch.object(s2, "rename_noreplace", attacker, create=True),
              mock.patch.object(s2.os, "rename", attacker),
              mock.patch.object(s2.os, "replace", attacker)):
            code, stdout, stderr, _output = self.run_main(
                success_manifest, output_success)
        self.assertEqual((code, stdout, stderr),
                         (0, "STAGE2C_PHASE2_ORCHESTRATION_OK\n", ""))
        self.assertFalse(output_success.exists())
        attacker.assert_not_called()

        diagnostic = b"provider secret retained/path attacker.example\n"
        failure_artifact = self.write("provider-failure", diagnostic)
        failure_manifest = self.write("provider.json", document([artifact(
            failure_artifact, source="shodan",
            profile="retained-provider-failure-v1")]))
        output_failure = self.directory / "failure-output"
        attacker.reset_mock()
        with (mock.patch.object(s2, "workspace_records", {"forged": object()},
                               create=True),
              mock.patch.object(s2, "sealed_records", {"forged": object()},
                                create=True),
              mock.patch.object(s2, "seal_workspace_file", attacker, create=True),
              mock.patch.object(s2, "publish_workspace_entry", attacker, create=True),
              mock.patch.object(s2, "rename_noreplace", attacker, create=True),
              mock.patch.object(s2.os, "rename", attacker),
              mock.patch.object(s2.os, "replace", attacker)):
            code, stdout, stderr, _output = self.run_main(
                failure_manifest, output_failure)
        self.assertEqual((code, stdout, stderr),
                         (7, "", "STAGE2C_PROVIDER_FAILURE\n"))
        self.assertFalse(output_failure.exists())
        self.assertNotIn(str(failure_artifact), stderr)
        self.assertNotIn("shodan", stderr)
        self.assertNotIn("a-1", stderr)
        self.assertNotIn("attacker.example", stderr)
        attacker.assert_not_called()

    def test_mixed_profiles_cannot_reach_success_or_provider_result(self):
        first = self.write("mixed-one")
        second = self.write("mixed-two")
        manifest = self.write("mixed.json", document([
            artifact(first), artifact(
                second, source="assetfinder",
                profile="retained-provider-failure-v1", artifact_id="a-2")]))
        code, stdout, stderr, output = self.run_main(manifest)
        self.assertEqual((code, stdout, stderr),
                         (3, "", "STAGE2C_INPUT_ERROR\n"))
        self.assertNotIn(code, (0, 7))
        self.assertFalse(output.exists())


class Phase2OrchestrationTests(TemporaryCase):
    def cfg_and_transaction(self, artifacts, name="phase2"):
        manifest = self.write(name + "-manifest.json", document(artifacts))
        output = self.directory / (name + "-output")
        cfg = s2.parse_cli(internal_args(
            "--manifest", str(manifest), "--output", str(output)))
        transaction = s2.open_validated_transaction(cfg)
        return cfg, transaction, output

    def normalized_bytes(self, source, retained):
        records = s2.retained_records(Path(retained).read_bytes())
        value = {
            "schema_version": 1, "source_id": source,
            "collection_status": "success", "record_count": len(records),
            "records": records,
        }
        return (json.dumps(value, sort_keys=True, ensure_ascii=True,
                           allow_nan=False, separators=(",", ":")) + "\n").encode("ascii")

    def successful_runner(self, calls):
        def runner(argv):
            calls.append(tuple(argv))
            output = Path(argv[8])
            output.write_bytes(self.normalized_bytes(argv[2], argv[6]))
            output.chmod(0o400)
            return 0, b"STAGE2B_COMPLETE\n", b""
        return runner

    def invoke(self, artifacts, runner=None, name="phase2"):
        cfg, transaction, output = self.cfg_and_transaction(artifacts, name)
        calls = []
        runner = self.successful_runner(calls) if runner is None else runner
        try:
            with mock.patch.object(s2, "verify_integrity"):
                results = s2.orchestrate_phase2(cfg, transaction, runner)
        finally:
            s2.close_validated_transaction(transaction)
        residue = [path for path in self.directory.iterdir()
                   if path.name.startswith(".nullsec-wolt-stage2c-phase2-")]
        return results, calls, output, residue

    def test_one_multiple_repeated_and_deterministic_order(self):
        one = self.write("one-lines", b"b.wolt.com\na.wolt.com\n")
        two = self.write("two-lines", b"c.wolt.com\n")
        values = [
            artifact(two, source="subfinder", artifact_id="z-last"),
            artifact(one, source="subfinder", artifact_id="a-first"),
        ]
        results, calls, output, residue = self.invoke(values)
        self.assertEqual([value["artifact_id"] for value in results],
                         ["a-first", "z-last"])
        self.assertEqual([value["ordinal"] for value in results], [0, 1])
        self.assertEqual(len(calls), 2)
        self.assertEqual([call[2] for call in calls], ["subfinder", "subfinder"])
        self.assertEqual([call[6] for call in calls], [str(one), str(two)])
        self.assertFalse(output.exists())
        self.assertEqual(residue, [])

    def test_fixed_executable_exact_argv_and_injection_is_data_only(self):
        retained = self.write("--command-provider-lines", b"a.wolt.com\n")
        values = [artifact(retained, artifact_id="command-provider-shell")]
        _results, calls, _output, _residue = self.invoke(values, name="argv")
        call = calls[0]
        self.assertEqual(call[0], str(ROOT / "nullsec-wolt-stage2b.sh"))
        self.assertEqual(call[1:5], (
            "--source", "subfinder", "--profile", "hostname-lines-v1"))
        self.assertEqual(call[5:7], ("--input", str(retained)))
        self.assertEqual(call[7], "--output")
        self.assertTrue(Path(call[8]).name == "normalized-0000.json")
        self.assertNotIn("command-provider-shell", call)
        self.assertEqual(len(call), 9)

    def test_provider_failure_and_mixed_never_orchestrate(self):
        retained = self.write("failure-receipt", b"failure\n")
        provider = self.write("provider.json", document([artifact(
            retained, source="shodan", profile="retained-provider-failure-v1")]))
        child = mock.Mock()
        workspace = mock.Mock()
        stdout, stderr = io.StringIO(), io.StringIO()
        with (mock.patch.object(s2, "verify_process_identity"),
              mock.patch.object(s2, "qualify_platform"),
              mock.patch.object(s2, "verify_integrity"),
              mock.patch.object(s2, "orchestrate_phase2", child),
              mock.patch.object(s2, "create_transient_workspace", workspace),
              contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr)):
            code = s2.main(internal_args(
                "--manifest", str(provider), "--output",
                str(self.directory / "provider-output")))
        self.assertEqual((code, stdout.getvalue(), stderr.getvalue()),
                         (7, "", "STAGE2C_PROVIDER_FAILURE\n"))
        child.assert_not_called()
        workspace.assert_not_called()

        other = self.write("mixed-lines", b"a.wolt.com\n")
        mixed = self.write("mixed-phase2.json", document([
            artifact(other), artifact(retained, source="shodan",
                profile="retained-provider-failure-v1", artifact_id="z-failure")]))
        stdout, stderr = io.StringIO(), io.StringIO()
        with (mock.patch.object(s2, "verify_process_identity"),
              mock.patch.object(s2, "qualify_platform"),
              mock.patch.object(s2, "verify_integrity"),
              mock.patch.object(s2, "orchestrate_phase2", child),
              contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr)):
            code = s2.main(internal_args(
                "--manifest", str(mixed), "--output",
                str(self.directory / "mixed-phase2-output")))
        self.assertEqual((code, stdout.getvalue(), stderr.getvalue()),
                         (3, "", "STAGE2C_INPUT_ERROR\n"))
        child.assert_not_called()

    def test_missing_output_child_failure_and_output_target_appearance(self):
        retained = self.write("missing-lines", b"a.wolt.com\n")
        values = [artifact(retained)]
        for result in ((9, b"", b""), (-9, b"", b""),
                       (0, b"STAGE2B_COMPLETE\n", b""),
                       (0, b"wrong\n", b""),
                       (0, b"STAGE2B_COMPLETE\n", b"warning\n")):
            with self.subTest(result=result):
                cfg, transaction, output = self.cfg_and_transaction(
                    values, "child-" + str(abs(result[0])))
                try:
                    with mock.patch.object(s2, "verify_integrity"):
                        failure(self, 5, s2.orchestrate_phase2,
                                cfg, transaction, lambda _argv, value=result: value)
                finally:
                    s2.close_validated_transaction(transaction)
                self.assertFalse(output.exists())

        cfg, transaction, output = self.cfg_and_transaction(values, "appeared")
        def appearing(argv):
            output.write_bytes(b"do-not-delete")
            output.chmod(0o600)
            Path(argv[8]).write_bytes(self.normalized_bytes(argv[2], argv[6]))
            Path(argv[8]).chmod(0o400)
            return 0, b"STAGE2B_COMPLETE\n", b""
        try:
            with mock.patch.object(s2, "verify_integrity"):
                failure(self, 6, s2.orchestrate_phase2,
                        cfg, transaction, appearing)
        finally:
            s2.close_validated_transaction(transaction)
        self.assertEqual(output.read_bytes(), b"do-not-delete")
        output.unlink()

    def test_retained_replacement_before_and_after_child(self):
        for when in ("before", "after"):
            retained = self.write(when + "-retained", b"a.wolt.com\n")
            cfg, transaction, output = self.cfg_and_transaction(
                [artifact(retained)], "replace-" + when)
            replacement = self.write(when + "-replacement", b"b.wolt.com\n")
            def runner(argv):
                if when == "after":
                    Path(argv[8]).write_bytes(self.normalized_bytes(argv[2], argv[6]))
                    Path(argv[8]).chmod(0o400)
                os.replace(replacement, retained)
                return 0, b"STAGE2B_COMPLETE\n", b""
            if when == "before":
                os.replace(replacement, retained)
            try:
                with mock.patch.object(s2, "verify_integrity"):
                    failure(self, 3, s2.orchestrate_phase2,
                            cfg, transaction, runner)
            finally:
                s2.close_validated_transaction(transaction)
            self.assertFalse(output.exists())

    def test_workspace_replacement_and_cleanup_failure(self):
        output_context = self.output_context("workspace-output")
        workspace = s2.create_transient_workspace(output_context)
        original = self.directory / (workspace["name"] + "-detached")
        named = self.directory / workspace["name"]
        named.rename(original)
        named.mkdir(mode=0o700)
        try:
            failure(self, 5, s2.revalidate_workspace, workspace, ())
        finally:
            named.rmdir()
            original.rename(named)
            s2.cleanup_transient_workspace(workspace)
            s2.close_context(output_context)

        output_context = self.output_context("cleanup-output")
        workspace = s2.create_transient_workspace(output_context)
        original_rmdir = s2.os.rmdir
        def failed_rmdir(path, *args, **kwargs):
            if path == workspace["name"]:
                raise OSError(errno.EIO, "fault")
            return original_rmdir(path, *args, **kwargs)
        try:
            with mock.patch.object(s2.os, "rmdir", side_effect=failed_rmdir):
                failure(self, 8, s2.cleanup_transient_workspace, workspace)
        finally:
            if (self.directory / workspace["name"]).exists():
                (self.directory / workspace["name"]).rmdir()
            s2.close_context(output_context)

    def test_normalized_file_and_schema_fault_matrix(self):
        retained = self.write("schema-retained", b"a.wolt.com\n")
        artifact_value = artifact(retained)
        expected = json.loads(self.normalized_bytes("subfinder", retained))
        cases = []
        cases.append(("malformed", b"not-json\n"))
        cases.append(("duplicate", b'{"schema_version":1,"schema_version":1}\n'))
        for label, changes in (
                ("source", {"source_id": "amass"}),
                ("status", {"collection_status": "failed"}),
                ("count", {"record_count": 2}),
                ("records-type", {"records": [7]}),
                ("records-control", {"records": ["a\\nb"]})):
            value = dict(expected)
            value.update(changes)
            cases.append((label, (json.dumps(
                value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")))
        for label, payload in cases:
            with self.subTest(label=label):
                output_context = self.output_context("schema-output-" + label)
                workspace = s2.create_transient_workspace(output_context)
                name = "normalized.json"
                path = self.directory / workspace["name"] / name
                path.write_bytes(payload)
                path.chmod(0o400)
                try:
                    failure(self, 5, s2.validate_normalized_envelope,
                            workspace, name, artifact_value,
                            retained.read_bytes())
                finally:
                    s2.cleanup_transient_workspace(workspace)
                    s2.close_context(output_context)

    def test_normalized_object_mode_symlink_hardlink_and_oversize(self):
        retained = self.write("object-retained", b"a.wolt.com\n")
        artifact_value = artifact(retained)
        payload = self.normalized_bytes("subfinder", retained)
        for label in ("mode", "symlink", "hardlink", "oversize"):
            with self.subTest(label=label):
                output_context = self.output_context("object-output-" + label)
                workspace = s2.create_transient_workspace(output_context)
                path = self.directory / workspace["name"] / "normalized.json"
                external = None
                if label == "symlink":
                    external = self.write("symlink-target", payload, 0o400)
                    path.symlink_to(external)
                elif label == "hardlink":
                    external = self.write("hardlink-target", payload, 0o400)
                    os.link(external, path)
                elif label == "oversize":
                    path.write_bytes(b"x" * (s2.MAX_NORMALIZED_ENVELOPE_BYTES + 1))
                    path.chmod(0o400)
                else:
                    path.write_bytes(payload)
                    path.chmod(0o600)
                try:
                    failure(self, 5, s2.validate_normalized_envelope,
                            workspace, "normalized.json", artifact_value,
                            retained.read_bytes())
                finally:
                    s2.cleanup_transient_workspace(workspace)
                    s2.close_context(output_context)

    def test_normalized_owner_and_named_replacement_are_rejected(self):
        retained = self.write("identity-retained", b"a.wolt.com\n")
        artifact_value = artifact(retained)
        payload = self.normalized_bytes("subfinder", retained)

        output_context = self.output_context("owner-output")
        workspace = s2.create_transient_workspace(output_context)
        path = self.directory / workspace["name"] / "normalized.json"
        path.write_bytes(payload)
        path.chmod(0o400)
        opened = []
        original_open = s2.open_regular_at
        original_fstat = s2.os.fstat
        def capture_open(*args, **kwargs):
            descriptor = original_open(*args, **kwargs)
            opened.append(descriptor)
            return descriptor
        def wrong_owner(descriptor):
            value = original_fstat(descriptor)
            if opened and descriptor == opened[-1]:
                fields = list(value)
                fields[stat.ST_UID] = os.geteuid() + 1000
                return os.stat_result(fields)
            return value
        try:
            with (mock.patch.object(s2, "open_regular_at", side_effect=capture_open),
                  mock.patch.object(s2.os, "fstat", side_effect=wrong_owner)):
                failure(self, 5, s2.validate_normalized_envelope,
                        workspace, "normalized.json", artifact_value,
                        retained.read_bytes())
        finally:
            s2.cleanup_transient_workspace(workspace)
            s2.close_context(output_context)

        output_context = self.output_context("replacement-output")
        workspace = s2.create_transient_workspace(output_context)
        path = self.directory / workspace["name"] / "normalized.json"
        path.write_bytes(payload)
        path.chmod(0o400)
        replacement = self.write("normalized-replacement", payload, 0o400)
        original_read = s2.read_fd_stable
        changed = False
        def replace_after_read(*args, **kwargs):
            nonlocal changed
            result = original_read(*args, **kwargs)
            if not changed:
                os.replace(replacement, path)
                changed = True
            return result
        try:
            with mock.patch.object(s2, "read_fd_stable", side_effect=replace_after_read):
                failure(self, 5, s2.validate_normalized_envelope,
                        workspace, "normalized.json", artifact_value,
                        retained.read_bytes())
        finally:
            s2.cleanup_transient_workspace(workspace)
            s2.close_context(output_context)
        self.assertTrue(changed)

    def test_child_runner_sanitizes_environment_and_bounds_transcript(self):
        captured = {}
        def popen(argv, **kwargs):
            captured["argv"] = argv
            captured.update(kwargs)
            out_read, out_write = os.pipe()
            err_read, err_write = os.pipe()
            os.write(out_write, b"STAGE2B_COMPLETE\n")
            os.close(out_write)
            os.close(err_write)
            return types.SimpleNamespace(
                stdout=os.fdopen(out_read, "rb", buffering=0),
                stderr=os.fdopen(err_read, "rb", buffering=0), pid=999999,
                wait=lambda timeout=None: 0, kill=lambda: None)
        argv = [str(ROOT / "nullsec-wolt-stage2b.sh")]
        self.assertEqual(s2.run_fixed_stage2b(argv, popen),
                         (0, b"STAGE2B_COMPLETE\n", b""))
        self.assertEqual(captured["env"], {"LC_ALL": "C"})
        self.assertIs(captured["shell"], False)
        self.assertIs(captured["close_fds"], True)
        self.assertIs(captured["start_new_session"], True)
        self.assertEqual(captured["argv"], argv)
        for result in (
                (0, b"x" * (s2.MAX_CHILD_STDOUT_BYTES + 1), b""),
                (0, b"STAGE2B_COMPLETE\n", b"x" * (s2.MAX_CHILD_STDERR_BYTES + 1)),
                (-signal.SIGKILL, b"", b""), (0, b"one\ntwo\n", b"")):
            failure(self, 5, s2.validate_stage2b_transcript, *result)

    def test_child_timeout_is_killed_and_reaped(self):
        out_read, out_write = os.pipe()
        err_read, err_write = os.pipe()
        killed = []
        waited = []
        process = types.SimpleNamespace(
            stdout=os.fdopen(out_read, "rb", buffering=0),
            stderr=os.fdopen(err_read, "rb", buffering=0), pid=999999,
            kill=lambda: killed.append(True),
            wait=lambda timeout=None: waited.append(timeout) or 0)
        try:
            with (mock.patch.object(s2.time, "monotonic", side_effect=(0, 31)),
                  mock.patch.object(s2.os, "killpg", side_effect=OSError())):
                failure(self, 5, s2.run_fixed_stage2b,
                        [str(ROOT / "nullsec-wolt-stage2b.sh")],
                        lambda _argv, **_kwargs: process)
        finally:
            os.close(out_write)
            os.close(err_write)
        self.assertTrue(killed)
        self.assertTrue(waited)

    def test_same_uid_limitation_is_explicit(self):
        core = CORE.read_text(encoding="utf-8")
        self.assertIn("malicious same-UID process is outside", core)
        self.assertIn("same-UID replacement", LAUNCHER.read_text(encoding="utf-8"))


class IntegrityAndResultTests(unittest.TestCase):
    def run_controlled_main(self, *, parse=None, validate=None, process=None):
        stdout = io.StringIO()
        stderr = io.StringIO()
        cfg = {"mode": "validate"}
        parse = cfg if parse is None else parse
        validate = {"transaction_class": "success-evidence"} if validate is None else validate
        process = mock.DEFAULT if process is None else process
        process_patch = (mock.patch.object(s2, "verify_process_identity") if
                         process is mock.DEFAULT else
                         mock.patch.object(s2, "verify_process_identity", side_effect=process))
        parse_patch = (mock.patch.object(s2, "parse_cli", return_value=parse) if
                       not isinstance(parse, BaseException) else
                       mock.patch.object(s2, "parse_cli", side_effect=parse))
        transaction = {"parsed": validate, "retained": [], "output": None}
        validate_patch = (mock.patch.object(
            s2, "open_validated_transaction", return_value=transaction) if
            not isinstance(validate, BaseException) else mock.patch.object(
                s2, "open_validated_transaction", side_effect=validate))
        with (process_patch, mock.patch.object(s2, "qualify_platform"), parse_patch,
              mock.patch.object(s2, "verify_integrity"), validate_patch,
              mock.patch.object(s2, "orchestrate_phase2", return_value=[]),
              contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr)):
            code = s2.main([])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_every_fixed_failure_exit_and_token_through_main(self):
        for code, token in s2.ERROR_TOKEN.items():
            with self.subTest(code=code):
                if code == 1:
                    result = self.run_controlled_main(process=RuntimeError("attacker-secret"))
                elif code in (6, 7, 8):
                    result = self.run_controlled_main(
                        validate=s2.Failure(code, "attacker-secret"))
                else:
                    result = self.run_controlled_main(
                        parse=s2.Failure(code, "attacker-secret"))
                self.assertEqual(result, (code, "", token + "\n"))
                self.assertNotIn("attacker-secret", result[2])

    def test_help_exit_zero_exact_output(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (mock.patch.object(s2, "verify_process_identity"),
              mock.patch.object(s2, "qualify_platform"),
              mock.patch.object(s2, "verify_integrity"),
              contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr)):
            code = s2.main(internal_args("--help"))
        self.assertEqual((code, stdout.getvalue(), stderr.getvalue()),
                         (0, s2.help_text(), ""))

    def test_protected_integrity_failure_remains_exit_two(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (mock.patch.object(s2, "verify_process_identity"),
              mock.patch.object(s2, "qualify_platform"),
              mock.patch.object(s2, "parse_cli", return_value={"mode": "help"}),
              mock.patch.object(s2, "verify_integrity",
                                side_effect=s2.Failure(2, "protected-secret")),
              contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr)):
            code = s2.main([])
        self.assertEqual((code, stdout.getvalue(), stderr.getvalue()),
                         (2, "", "STAGE2C_INTEGRITY_ERROR\n"))

    def test_integrity_inventory_aggregate_and_nonrecursive_assumption(self):
        value = json.loads(INTEGRITY.read_text(encoding="utf-8"))
        self.assertEqual(value["schema_version"], 1)
        self.assertEqual(set(value["protected_files"]), s2.PROTECTED_PATHS)
        self.assertEqual(len(value["protected_files"]), 36)
        self.assertNotIn("config/wolt-stage2c-integrity.json", value["protected_files"])
        self.assertNotIn("nullsec-wolt-stage2c.sh", value["protected_files"])
        self.assertEqual(value["inventory_identity"],
                         s2.inventory_identity(value["protected_files"]))
        self.assertEqual(value["aggregate_sha256"],
                         s2.aggregate_digest(value["protected_files"]))
        self.assertIn(value["aggregate_sha256"], LAUNCHER.read_text(encoding="utf-8"))
        for relative, digest in value["protected_files"].items():
            self.assertEqual(
                hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(), digest)

    def test_static_offline_phase2_capability_boundary(self):
        core = CORE.read_text(encoding="utf-8")
        launcher = LAUNCHER.read_text(encoding="utf-8")
        forbidden_core = (
            "import socket", "import urllib", "import http", "requests",
            "os.system", "os.popen", "shell=True", "check_call",
            "check_output", "execv", "spawn", "eval(", "classification_package",
        )
        for token in forbidden_core:
            self.assertNotIn(token, core)
        self.assertIn("subprocess.Popen", core)
        self.assertIn('STAGE2B_LAUNCHER_RELATIVE = "nullsec-wolt-stage2b.sh"', core)
        self.assertNotIn('STAGE2B_LAUNCHER_RELATIVE = os.environ', core)
        self.assertNotIn("source ", launcher)
        self.assertNotIn("eval ", launcher)
        self.assertNotIn("/usr/bin/env python", launcher)
        self.assertIn("/usr/bin/python3 -I -S -B", launcher)

    def test_phase2_has_transient_staging_but_no_final_publication_authority(self):
        tree = ast.parse(CORE.read_text(encoding="utf-8"))
        forbidden = (
            "_build_workspace_boundary", "TransactionWorkspace", "WorkspaceEntry",
            "SealedEntry", "require_qualified_workspace", "create_private_workspace",
            "create_workspace_file", "seal_workspace_file", "cleanup_workspace",
            "rollback_workspace", "revalidate_sealed_entry", "publish_workspace_entry",
            "rename_noreplace", "write_complete", "fsync_file", "fsync_directory",
            "_seal_checkpoint", "workspace_records", "sealed_records",
        )
        declared = {
            node.name for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        }
        core = CORE.read_text(encoding="utf-8")
        for name in forbidden:
            with self.subTest(name=name):
                self.assertNotIn(name, declared)
                self.assertNotIn(name, vars(s2))
                if name != "rename_noreplace":
                    self.assertNotIn(name, core)
        self.assertNotIn("authority = object()", core)
        self.assertNotIn("__new__", core)
        self.assertNotIn("os.rename", core)
        self.assertNotIn("os.replace", core)
        self.assertIn("cleanup_transient_workspace", declared)

    def test_introspection_copy_reconstruction_and_registry_insertion_have_no_authority(self):
        capability_types = ("TransactionWorkspace", "WorkspaceEntry", "SealedEntry")
        for name in capability_types:
            with self.subTest(name=name):
                with self.assertRaises(AttributeError):
                    getattr(s2, name)
        forged = types.SimpleNamespace(
            workspace=object(), workspace_fd=7, name="payload", size=3,
            digest="0" * 64, state="issued")
        copied = (copy.copy(forged), copy.deepcopy(forged))
        self.assertEqual(copied[0].__dict__, forged.__dict__)
        self.assertEqual(copied[1].workspace_fd, forged.workspace_fd)
        self.assertEqual(copied[1].name, forged.name)
        self.assertEqual(copied[1].digest, forged.digest)
        self.assertEqual(copied[1].state, forged.state)
        self.assertIsNot(copied[1].workspace, forged.workspace)
        consumers = (
            "require_qualified_workspace", "seal_workspace_file",
            "publish_workspace_entry", "cleanup_workspace")
        for name in consumers:
            self.assertFalse(hasattr(s2, name))

        for name, value in vars(s2).items():
            if isinstance(value, types.FunctionType):
                with self.subTest(function=name):
                    self.assertIsNone(value.__closure__)
                    defaults = (value.__defaults__ or ()) + tuple(
                        (value.__kwdefaults__ or {}).values())
                    self.assertFalse(any(isinstance(item, (dict, list, set, bytearray))
                                         for item in defaults))
                    code_values = [constant for constant in value.__code__.co_consts
                                   if isinstance(constant, str)]
                    self.assertFalse(any("opaque workspace" in constant.lower()
                                         for constant in code_values))

    def test_launcher_result_contract_accepts_every_exact_fixed_result(self):
        success = (0, b"STAGE2C_PHASE2_ORCHESTRATION_OK\n", b"")
        help_result = (0, s2.help_text().encode("ascii"), b"")
        self.assertEqual(s2.validate_launcher_result(*success), success)
        self.assertEqual(s2.validate_launcher_result(*help_result), help_result)
        for code, token in s2.ERROR_TOKEN.items():
            result = (code, b"", (token + "\n").encode("ascii"))
            with self.subTest(code=code):
                self.assertEqual(s2.validate_launcher_result(*result), result)

    def test_launcher_result_contract_fails_closed_on_all_diagnostics(self):
        rejected = (2, b"", b"STAGE2C_INTEGRITY_ERROR\n")
        secret = str(ROOT).encode("utf-8") + b" jonaski ImportError traceback\n"
        cases = (
            (126, b"", b"/usr/bin/python3: Permission denied\n"),
            (127, b"", b"/usr/bin/python3: No such file\n"),
            (0, b"STAGE2C_PHASE2_ORCHESTRATION_OK", b""),
            (0, b"STAGE2C_PHASE2_ORCHESTRATION_OK\n", b"warning\n"),
            (1, b"", b"STAGE2C_INTERNAL_ERROR\npartial"),
            (1, secret, b""), (2, b"", secret), (255, b"", b""),
            (0, b"x" * (s2.MAX_LAUNCH_RESULT_BYTES + 1), b""),
            (1, b"", b"x" * (s2.MAX_LAUNCH_RESULT_BYTES + 1)),
            (True, b"", b""), (0, "text", b""),
        )
        for case in cases:
            with self.subTest(status=case[0], stdout_size=len(case[1])):
                self.assertEqual(s2.validate_launcher_result(*case), rejected)

    def test_launcher_statically_fences_cd_exec_startup_and_child_streams(self):
        launcher = LAUNCHER.read_text(encoding="utf-8")
        self.assertIn('builtin cd -P -- "$launcher_dir" 2>/dev/null || startup_fail',
                      launcher)
        self.assertNotIn("exec /usr/bin/python3", launcher)
        self.assertIn('/usr/bin/python3 -I -S -B "$PYTHON_CORE"', launcher)
        self.assertIn('>"$stdout_path" 2>"$stderr_path"', launcher)
        self.assertIn(") 2>/dev/null; then", launcher)
        self.assertIn("ulimit -S -f 4", launcher)
        self.assertNotIn("ulimit -f 4", launcher)
        self.assertIn("/usr/bin/mktemp -d -p /tmp", launcher)
        self.assertIn("/proc/$$/fd/$result_fd/stdout", launcher)
        self.assertIn("$stdout_size -le 4096", launcher)
        self.assertIn("cleanup_private || startup_fail", launcher)
        self.assertIn("/usr/bin/rmdir -- \"$result_dir\" 2>/dev/null", launcher)
        self.assertLess(launcher.index("trap 'cleanup_private"),
                        launcher.index("/usr/bin/mktemp -d -p /tmp"))
        self.assertNotIn("cat \"$stdout_path\"", launcher)
        self.assertNotIn("cat \"$stderr_path\"", launcher)
        for token in tuple(s2.ERROR_TOKEN.values()) + (
                "STAGE2C_PHASE2_ORCHESTRATION_OK",):
            self.assertIn(token, launcher)
        exact_results = [
            (0, b"STAGE2C_PHASE2_ORCHESTRATION_OK\n", b""),
            (0, s2.help_text().encode("ascii"), b""),
        ]
        exact_results.extend(
            (code, b"", (token + "\n").encode("ascii"))
            for code, token in s2.ERROR_TOKEN.items())
        expanded_launcher = launcher.replace(
            "$empty_hash", hashlib.sha256(b"").hexdigest())
        for code, stdout, stderr in exact_results:
            key = "{}:{}:{}:{}:{}".format(
                code, len(stdout), hashlib.sha256(stdout).hexdigest(),
                len(stderr), hashlib.sha256(stderr).hexdigest())
            with self.subTest(code=code, stdout_size=len(stdout)):
                self.assertIn(key, expanded_launcher)

    def test_launcher_capture_metadata_gate_remains_complete(self):
        launcher = LAUNCHER.read_text(encoding="utf-8")
        self.assertNotIn("stat -c '%F", launcher)
        self.assertIn(
            "stat -c '%f|%u|%a|%h' -- \"$result_dir\"", launcher)
        self.assertIn(
            "stat -c '%f|%u|%a|%h' -- \"$stdout_path\" \"$stderr_path\"",
            launcher)
        self.assertIn(
            "stat -c '%f|%u|%a|%h|%s' -- \"$stdout_path\" \"$stderr_path\"",
            launcher)
        self.assertIn(
            '[[ $result_meta == "41c0|$UID|700|2" ]]', launcher)
        self.assertIn(
            "$stdout_mode_hex == 8180 && $stderr_mode_hex == 8180",
            launcher)
        for check in (
                '$stdout_uid == "$UID" && $stderr_uid == "$UID"',
                "$stdout_mode == 600 && $stderr_mode == 600",
                "$stdout_links == 1 && $stderr_links == 1",
                "$stdout_size =~ ^[0-9]+$ && $stderr_size =~ ^[0-9]+$",
                "$stdout_size -le 4096 && $stderr_size -le 4096",
                'result_identity=$(/usr/bin/stat -Lc \'%d:%i\' -- '
                '"/proc/$$/fd/$result_fd"',
                'current_identity=$(/usr/bin/stat -c \'%d:%i\' -- '
                '"$result_dir"',
                '[[ ! -L $result_dir && '
                '$current_identity == "$result_identity" ]]',
        ):
            with self.subTest(check=check):
                self.assertIn(check, launcher)

    def test_stat_raw_mode_gate_accepts_regular_captures_and_rejects_substitution(self):
        def run_stat(path, format_string):
            read_fd, write_fd = os.pipe()
            try:
                try:
                    process = os.posix_spawn(
                        "/usr/bin/stat",
                        ("/usr/bin/stat", "-c", format_string, "--",
                         os.fspath(path)),
                        os.environ,
                        file_actions=(
                            (os.POSIX_SPAWN_DUP2, write_fd, 1),
                            (os.POSIX_SPAWN_CLOSE, read_fd),
                            (os.POSIX_SPAWN_CLOSE, write_fd),
                        ),
                    )
                finally:
                    os.close(write_fd)
                chunks = []
                while True:
                    chunk = os.read(read_fd, 4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
            finally:
                os.close(read_fd)
            _process, status = os.waitpid(process, 0)
            self.assertTrue(os.WIFEXITED(status))
            self.assertEqual(os.WEXITSTATUS(status), 0)
            return b"".join(chunks).decode("ascii").rstrip("\n")

        def passes_capture_gate(path):
            fields = run_stat(path, "%f|%u|%a|%h|%s").split("|")
            if len(fields) != 5:
                return False
            mode_hex, owner, mode, links, size = fields
            return (
                mode_hex == "8180" and
                owner == str(os.geteuid()) and
                mode == "600" and
                links == "1" and
                size.isdecimal() and
                int(size) <= 4096
            )

        temporary_path = None
        with tempfile.TemporaryDirectory(
                prefix=".stage2c-capture-mode-",
                dir=str(EXTERNAL_TEMP_PARENT)) as temporary:
            temporary_path = Path(temporary)
            empty = temporary_path / "empty"
            nonempty = temporary_path / "nonempty"
            link = temporary_path / "link"
            directory = temporary_path / "directory"
            wrong_mode = temporary_path / "wrong-mode"
            linked = temporary_path / "linked"
            linked_alias = temporary_path / "linked-alias"
            oversized = temporary_path / "oversized"

            empty.write_bytes(b"")
            nonempty.write_bytes(b"capture\n")
            wrong_mode.write_bytes(b"capture\n")
            linked.write_bytes(b"capture\n")
            oversized.write_bytes(b"x" * 4097)
            for path in (empty, nonempty, linked, oversized):
                path.chmod(0o600)
            wrong_mode.chmod(0o640)
            directory.mkdir(mode=0o700)
            link.symlink_to(empty)
            os.link(linked, linked_alias)

            owner = os.geteuid()
            self.assertEqual(
                run_stat(empty, "%f|%u|%a|%h"),
                f"8180|{owner}|600|1")
            self.assertEqual(
                run_stat(nonempty, "%f|%u|%a|%h"),
                f"8180|{owner}|600|1")
            self.assertEqual(
                run_stat(directory, "%f|%u|%a|%h"),
                f"41c0|{owner}|700|2")
            self.assertTrue(passes_capture_gate(empty))
            self.assertTrue(passes_capture_gate(nonempty))

            link_mode = int(run_stat(link, "%f"), 16)
            self.assertTrue(stat.S_ISLNK(link_mode))
            self.assertEqual(run_stat(wrong_mode, "%a"), "640")
            self.assertEqual(run_stat(linked, "%h"), "2")
            self.assertEqual(run_stat(linked_alias, "%h"), "2")
            self.assertEqual(run_stat(oversized, "%s"), "4097")

            for rejected in (
                    link, directory, wrong_mode, linked, linked_alias, oversized):
                with self.subTest(rejected=rejected.name):
                    self.assertFalse(passes_capture_gate(rejected))
        self.assertIsNotNone(temporary_path)
        self.assertFalse(temporary_path.exists())

    def test_all_frozen_resource_limits_are_positive_and_not_cli_options(self):
        names = (
            "MAX_MANIFEST_BYTES", "MAX_JSON_DEPTH", "MAX_ARTIFACTS",
            "MAX_ARTIFACT_ID_BYTES", "MAX_PATH_BYTES", "MAX_RETAINED_BYTES",
            "MAX_TOTAL_RETAINED_BYTES", "MAX_PROTECTED_BYTES",
            "MAX_LAUNCH_RESULT_BYTES", "MAX_STAGE2B_INPUT_BYTES",
            "MAX_NORMALIZED_ENVELOPE_BYTES", "MAX_TOTAL_NORMALIZED_BYTES",
            "MAX_TRANSIENT_ARTIFACTS", "MAX_CHILD_STDOUT_BYTES",
            "MAX_CHILD_STDERR_BYTES", "CHILD_TIMEOUT_SECONDS",
            "CHILD_CPU_SECONDS", "CHILD_ADDRESS_SPACE_BYTES",
            "CHILD_OPEN_FILES", "WORKSPACE_ATTEMPTS",
        )
        usage = s2.help_text()
        for name in names:
            self.assertGreater(getattr(s2, name), 0)
            self.assertNotIn(name.lower().replace("_", "-"), usage)

    def test_external_temporary_root_ignores_environment_and_cleans_on_exception(self):
        path = None
        with mock.patch.dict(os.environ, {"TMPDIR": str(ROOT)}):
            temporary = tempfile.TemporaryDirectory(
                prefix=".stage2c-abnormal-", dir=str(EXTERNAL_TEMP_PARENT))
            try:
                path = Path(temporary.name).resolve()
                self.assertNotEqual(path, ROOT)
                self.assertNotIn(ROOT, path.parents)
                raise RuntimeError("intentional helper exception")
            except RuntimeError:
                pass
            finally:
                temporary.cleanup()
        self.assertIsNotNone(path)
        self.assertFalse(path.exists())

    def test_same_uid_limitation_is_documented(self):
        launcher = LAUNCHER.read_text(encoding="utf-8")
        self.assertIn("same-UID replacement of both this launcher and the integrity manifest",
                      launcher)


def tearDownModule():
    if TEMPORARY_ROOTS:
        raise AssertionError("external temporary roots remain")
    after = repository_inventory()
    if after != REPOSITORY_INVENTORY_BEFORE:
        raise AssertionError("repository inventory changed during tests")
    residue = []
    for relative, kind, _mode, _digest in after:
        name = Path(relative).name
        if (name == "__pycache__" or name.endswith((".pyc", ".pyo", ".log", ".out")) or
                kind in (stat.S_IFIFO, stat.S_IFSOCK)):
            residue.append(relative)
    if residue:
        raise AssertionError("repository test residue: " + repr(residue))


if __name__ == "__main__":
    unittest.main(verbosity=2)
