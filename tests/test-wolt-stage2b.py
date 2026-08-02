#!/usr/bin/python3
"""Deterministic offline unit and fault-injection tests for Wolt Stage 2B."""

import contextlib
import errno
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import types
import unittest
from unittest import mock


os.environ.pop("BASH_ENV", None)
os.environ.pop("ENV", None)
ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "wolt-stage2b"
CORE = ROOT / "lib" / "wolt-stage2b.py"
loader = importlib.machinery.SourceFileLoader("wolt_stage2b", str(CORE))
spec = importlib.util.spec_from_loader(loader.name, loader)
s2 = importlib.util.module_from_spec(spec)
loader.exec_module(s2)


def failure(testcase, code, function, *args, **kwargs):
    with testcase.assertRaises(s2.Failure) as caught:
        function(*args, **kwargs)
    testcase.assertEqual(caught.exception.code, code)
    return caught.exception


def internal_args(*public, repository=ROOT, launcher=None):
    launcher = ROOT / "nullsec-wolt-stage2b.sh" if launcher is None else launcher
    return ["--repository", str(repository), "--launcher", str(launcher), *public]


def conversion_args(source, profile, source_path, output_path):
    return internal_args("--source", source, "--profile", profile,
                         "--input", str(source_path), "--output", str(output_path))


def receipt(source="shodan", error="POLICY_BLOCKED", **changes):
    value = {"schema_version": 1, "profile": "retained-provider-failure-v1",
             "source_id": source, "error_code": error}
    value.update(changes)
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def stat_value(**changes):
    values = dict(st_dev=1, st_ino=2, st_size=3, st_mode=stat.S_IFREG | 0o600,
                  st_uid=os.geteuid(), st_gid=os.getegid(), st_mtime_ns=4,
                  st_ctime_ns=5)
    values.update(changes)
    return types.SimpleNamespace(**values)


def assert_stage2a_envelope(testcase, payload):
    testcase.assertLessEqual(len(payload), 8 * 1024 * 1024)
    testcase.assertTrue(payload.endswith(b"\n"))
    testcase.assertFalse(payload.endswith(b"\n\n"))
    value = json.loads(payload[:-1].decode("utf-8"))
    common = {"schema_version", "source_id", "collection_status", "record_count", "records"}
    expected = common if value["collection_status"] == "success" else common | {"error_code"}
    testcase.assertEqual(set(value), expected)
    testcase.assertEqual(value["schema_version"], 1)
    testcase.assertIn(value["source_id"], s2.SOURCE_IDS)
    testcase.assertIs(type(value["record_count"]), int)
    testcase.assertLessEqual(value["record_count"], 100000)
    testcase.assertEqual(value["record_count"], len(value["records"]))
    for record in value["records"]:
        testcase.assertIs(type(record), str)
        encoded = record.encode("ascii")
        testcase.assertLessEqual(len(encoded), 4096)
        testcase.assertFalse(any(byte in encoded for byte in (0, 10, 13)))
    if value["collection_status"] == "failed":
        testcase.assertIn(value["error_code"], s2.ERROR_CODES)
        testcase.assertEqual(value["record_count"], 0)
        testcase.assertEqual(value["records"], [])
    return value


class TemporaryCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="unit-", dir=FIXTURES)
        self.directory = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, name, data, mode=0o600):
        path = self.directory / name
        path.write_bytes(data)
        path.chmod(mode)
        return path


class IdentityAndCliTests(unittest.TestCase):
    def fake_ids(self, uid=1, euid=1, gid=2, egid=2):
        return types.SimpleNamespace(getuid=lambda: uid, geteuid=lambda: euid,
                                     getgid=lambda: gid, getegid=lambda: egid)

    def test_uid_and_gid_mismatch(self):
        failure(self, 2, s2.verify_identity, self.fake_ids(uid=1, euid=3))
        failure(self, 2, s2.verify_identity, self.fake_ids(gid=2, egid=4))

    def test_help_only(self):
        cfg = s2.parse_cli(internal_args("--help"))
        self.assertEqual(cfg["mode"], "help")
        for extra in ("--source", "x"):
            failure(self, 64, s2.parse_cli, internal_args("--help", extra))

    def test_missing_duplicate_unknown_empty_and_positional(self):
        valid = ["--source", "amass", "--profile", "hostname-lines-v1",
                 "--input", "/a", "--output", "/b"]
        cases = [valid[:-2], valid + ["--source", "amass"],
                 valid + ["--bogus", "x"], valid + ["positional"],
                 ["--source", "", *valid[2:]]]
        for case in cases:
            with self.subTest(case=case):
                failure(self, 64, s2.parse_cli, internal_args(*case))

    def test_option_looking_required_values_are_usage(self):
        cases = {
            "--source": ["--source", "--profile", "--profile", "hostname-lines-v1",
                         "--input", "/a", "--output", "/b"],
            "--profile": ["--source", "amass", "--profile", "--input",
                          "--input", "/a", "--output", "/b"],
            "--input": ["--source", "amass", "--profile", "hostname-lines-v1",
                        "--input", "--output", "--output", "/b"],
            "--output": ["--source", "amass", "--profile", "hostname-lines-v1",
                         "--input", "/a", "--output", "--source"],
        }
        for option, arguments in cases.items():
            with self.subTest(option=option):
                failure(self, 64, s2.parse_cli, internal_args(*arguments))
        option_like = ["--source", "-amass", "--profile", "hostname-lines-v1",
                       "--input", "/a", "--output", "/b"]
        failure(self, 64, s2.parse_cli, internal_args(*option_like))

    def test_relative_paths(self):
        for option in ("--input", "--output"):
            args = ["--source", "amass", "--profile", "hostname-lines-v1",
                    "--input", "/a", "--output", "/b"]
            args[args.index(option) + 1] = "relative"
            with self.subTest(option=option):
                failure(self, 64, s2.parse_cli, internal_args(*args))

    def test_source_profile_support(self):
        base = ["--source", "subfinder", "--profile", "hostname-lines-v1",
                "--input", "/a", "--output", "/b"]
        for source in ("unknown", "Subfinder", ""):
            args = list(base); args[1] = source
            expected = 64 if source == "" else 4
            with self.subTest(source=source):
                failure(self, expected, s2.parse_cli, internal_args(*args))
        args = list(base); args[3] = "native-json-v1"
        failure(self, 4, s2.parse_cli, internal_args(*args))
        for source in ("virustotal", "shodan"):
            args = list(base); args[1] = source
            failure(self, 4, s2.parse_cli, internal_args(*args))

    def test_incorrect_internal_context(self):
        failure(self, 2, s2.parse_cli, [])
        cfg = {"repository": "/wrong", "launcher": "/wrong/l"}
        failure(self, 2, s2.verify_context, cfg)


class HostnameLineTests(unittest.TestCase):
    def test_valid_sources_and_preservation(self):
        data = (FIXTURES / "hostname-lines.txt").read_bytes()
        expected = data[:-1].decode("ascii").split("\n")
        for source in sorted(s2.LINE_SOURCES):
            with self.subTest(source=source):
                payload = s2.envelope_bytes(source, "hostname-lines-v1", data)
                value = assert_stage2a_envelope(self, payload)
                self.assertEqual(value["records"], expected)
                self.assertEqual(value["source_id"], source)
        self.assertEqual(expected[0], "api.wolt.com")
        self.assertEqual(expected[1], "MixedCase.WOLT.COM.")
        self.assertEqual(expected[2], "api.wolt.com")
        self.assertIn("https://example.invalid/path", expected)
        self.assertIn("192.0.2.1", expected)
        self.assertIn("2001:db8::1", expected)
        self.assertIn("192.0.2.0/24", expected)
        self.assertIn("*.wolt.com", expected)
        self.assertIn("com.wolt.android", expected)
        self.assertIn("printable data !@#$%^&*()", expected)

    def test_empty_and_final_lf(self):
        empty = json.loads(s2.envelope_bytes("amass", "hostname-lines-v1", b""))
        self.assertEqual(empty["records"], [])
        for data in (b"a.wolt.com", b"a.wolt.com\n"):
            with self.subTest(data=data):
                self.assertEqual(s2.parse_hostname_lines(data), ["a.wolt.com"])

    def test_blank_cr_nul_nonascii_and_controls(self):
        cases = (b"a\n\nb", b"\n", b"a\r", b"a\r\n", b"a\0b", b"\xff",
                 b"a\tb", b"a\x01b", b"a\x7fb")
        for data in cases:
            with self.subTest(data=data):
                failure(self, 3, s2.parse_hostname_lines, data)

    def test_oversized_line_and_record_count(self):
        failure(self, 3, s2.parse_hostname_lines, b"a" * 4097)
        failure(self, 3, s2.parse_hostname_lines, b"a\n" * 100001)

    def test_envelope_over_eight_mib_rejected(self):
        records = (b"\\\n" * 100000)
        with mock.patch.object(s2, "MAX_INPUT", len(records) + 1024):
            failure(self, 3, s2.envelope_bytes, "amass", "hostname-lines-v1", records)

    def test_exact_deterministic_compact_encoding(self):
        data = b"B.WOLT.COM.\na.wolt.com\na.wolt.com\n"
        first = s2.envelope_bytes("subfinder", "hostname-lines-v1", data)
        second = s2.envelope_bytes("subfinder", "hostname-lines-v1", data)
        expected = (b'{"collection_status":"success","record_count":3,"records":'
                    b'["B.WOLT.COM.","a.wolt.com","a.wolt.com"],"schema_version":1,'
                    b'"source_id":"subfinder"}\n')
        self.assertEqual(first, expected)
        self.assertEqual(first, second)
        self.assertNotIn(b"timestamp", first)
        self.assertNotIn(b"/", first)


class FailureReceiptTests(unittest.TestCase):
    def test_every_source_and_error_code(self):
        for source in sorted(s2.SOURCE_IDS):
            for error in sorted(s2.ERROR_CODES):
                with self.subTest(source=source, error=error):
                    payload = s2.envelope_bytes(
                        source, "retained-provider-failure-v1", receipt(source, error))
                    value = assert_stage2a_envelope(self, payload)
                    self.assertEqual(value["source_id"], source)
                    self.assertEqual(value["error_code"], error)

    def test_exact_failed_keys_and_encoding(self):
        payload = s2.envelope_bytes("shodan", "retained-provider-failure-v1",
                                    receipt("shodan", "TIMEOUT"))
        self.assertEqual(
            payload,
            b'{"collection_status":"failed","error_code":"TIMEOUT","record_count":0,'
            b'"records":[],"schema_version":1,"source_id":"shodan"}\n')

    def test_mismatch_profile_keys_and_types(self):
        values = [receipt("shodan", source_id="amass"),
                  receipt("shodan", profile="native-provider-error"),
                  receipt("shodan", unknown=True),
                  b'{"schema_version":1,"profile":"retained-provider-failure-v1",'
                  b'"source_id":"shodan"}',
                  receipt("shodan", schema_version=True),
                  receipt("shodan", error_code=7),
                  receipt("shodan", source_id=7)]
        for data in values:
            with self.subTest(data=data):
                failure(self, 4, s2.parse_failure_receipt, data, "shodan")

    def test_duplicate_invalid_encoding_nul_constants_and_depth(self):
        cases = [
            b'{"schema_version":1,"schema_version":1,"profile":"retained-provider-failure-v1",'
            b'"source_id":"shodan","error_code":"TIMEOUT"}',
            b"\xff", b'{"x":"\0"}', b'{"x":NaN}', b'{"x":Infinity}',
            b"[" * 17 + b"]" * 17,
        ]
        for data in cases:
            with self.subTest(data=data[:30]):
                failure(self, 4, s2.parse_failure_receipt, data, "shodan")

    def test_unknown_error_native_text_and_empty(self):
        for data in (receipt("shodan", "RAW_PROVIDER_ERROR"),
                     b"provider timed out while querying API", b""):
            with self.subTest(data=data):
                failure(self, 4, s2.parse_failure_receipt, data, "shodan")


class DescriptorInputTests(TemporaryCase):
    def run_launcher(self, input_path, output_path):
        return subprocess.run(
            [str(ROOT / "nullsec-wolt-stage2b.sh"), "--source", "amass",
             "--profile", "hostname-lines-v1", "--input", str(input_path),
             "--output", str(output_path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=3)

    def test_read_detects_every_metadata_change(self):
        before = stat_value()
        changes = {"st_dev": 9, "st_ino": 9, "st_size": 4,
                   "st_mode": stat.S_IFREG | 0o400, "st_uid": os.geteuid() + 1,
                   "st_gid": os.getegid() + 1, "st_mtime_ns": 9, "st_ctime_ns": 9}
        for field, value in changes.items():
            stats = iter((before, stat_value(**{field: value})))
            reads = iter((b"abc", b""))
            ops = types.SimpleNamespace(fstat=lambda _fd: next(stats),
                                        read=lambda _fd, _size: next(reads),
                                        geteuid=os.geteuid)
            with self.subTest(field=field):
                failure(self, 3, s2.read_fd_stable, 5, 10, 3, "INPUT", ops)

    def test_reject_type_owner_and_unsafe_mode(self):
        for st in (stat_value(st_mode=stat.S_IFDIR | 0o700),
                   stat_value(st_uid=os.geteuid() + 1),
                   stat_value(st_mode=stat.S_IFREG | 0o620),
                   stat_value(st_mode=stat.S_IFREG | 0o602)):
            with self.subTest(mode=st.st_mode, uid=st.st_uid):
                failure(self, 3, s2.validate_regular, st, 3, "INPUT")

    def test_oversized_input_and_receipt(self):
        lines = self.write("large-lines", b"a" * (s2.MAX_INPUT + 1))
        failure(self, 3, s2.open_input, str(lines), "hostname-lines-v1")
        receipt_path = self.write("large-receipt", b" " * (s2.MAX_RECEIPT + 1))
        failure(self, 3, s2.open_input, str(receipt_path), "retained-provider-failure-v1")

    def test_symlink_wrong_type_and_unsafe_input(self):
        target = self.write("target", b"a\n")
        link = self.directory / "link"; link.symlink_to(target)
        failure(self, 3, s2.open_input, str(link), "hostname-lines-v1")
        failure(self, 3, s2.open_input, str(self.directory), "hostname-lines-v1")
        target.chmod(0o660)
        failure(self, 3, s2.open_input, str(target), "hostname-lines-v1")

    def test_real_launcher_promptly_rejects_fifo_and_directory(self):
        fifo = self.directory / "input-fifo"
        os.mkfifo(fifo, 0o600)
        for label, candidate in (("fifo", fifo), ("directory", self.directory)):
            output = self.directory / (label + "-output")
            with self.subTest(label=label):
                completed = self.run_launcher(candidate, output)
                self.assertEqual(
                    (completed.returncode, completed.stdout, completed.stderr),
                    (3, b"", b"STAGE2B_INPUT_ERROR\n"))
                self.assertFalse(output.exists())
                self.assertFalse(any(path.name.startswith(".stage2b-")
                                     for path in self.directory.iterdir()))

    def test_unsafe_ancestor(self):
        unsafe = self.directory / "unsafe"; unsafe.mkdir(mode=0o700); unsafe.chmod(0o770)
        path = unsafe / "input"; path.write_bytes(b"a\n"); path.chmod(0o600)
        failure(self, 3, s2.open_input, str(path), "hostname-lines-v1")

    def test_changing_and_replaced_input(self):
        path = self.write("input", b"a\n")
        context = s2.open_input(str(path), "hostname-lines-v1")
        try:
            path.write_bytes(b"b\n")
            failure(self, 3, s2.revalidate_open_file, context)
        finally:
            s2.close_context(context)
        path.write_bytes(b"a\n"); path.chmod(0o600)
        context = s2.open_input(str(path), "hostname-lines-v1")
        moved = self.directory / "moved"
        try:
            path.rename(moved)
            path.write_bytes(b"a\n"); path.chmod(0o600)
            failure(self, 3, s2.revalidate_open_file, context)
        finally:
            s2.close_context(context)


class IntegrityTests(unittest.TestCase):
    def manifest(self, files=None, **changes):
        files = {path: "0" * 64 for path in s2.PROTECTED_PATHS} if files is None else files
        value = {"schema_version": 1, "aggregate_algorithm": s2.AGGREGATE_ALGORITHM,
                 "aggregate_sha256": s2.aggregate_digest(files), "protected_files": files}
        value.update(changes)
        return json.dumps(value, separators=(",", ":")).encode()

    def load_bytes(self, data):
        with mock.patch.object(s2, "read_absolute_stable", return_value=(data, stat_value())):
            return s2.load_manifest(str(ROOT))

    def test_manifest_malformed_duplicate_unknown_and_missing_keys(self):
        valid = json.loads(self.manifest())
        cases = [b"not-json", b'{"schema_version":1,"schema_version":1}',
                 json.dumps(dict(valid, unknown=True)).encode(),
                 json.dumps({key: value for key, value in valid.items()
                             if key != "aggregate_sha256"}).encode()]
        for data in cases:
            with self.subTest(data=data[:30]):
                with mock.patch.object(s2, "read_absolute_stable",
                                       return_value=(data, stat_value())):
                    failure(self, 2, s2.load_manifest, str(ROOT))

    def test_manifest_inventory_and_digest_guards(self):
        base = {path: "0" * 64 for path in s2.PROTECTED_PATHS}
        variants = []
        unknown = dict(base); unknown["unknown"] = "0" * 64; variants.append(unknown)
        missing = dict(base); missing.pop(next(iter(missing))); variants.append(missing)
        bad = dict(base); bad[next(iter(bad))] = "x" * 64; variants.append(bad)
        for files in variants:
            with self.subTest(count=len(files)):
                failure(self, 2, self.load_bytes, self.manifest(files))

    def test_manifest_aggregate_mismatch_and_values(self):
        failure(self, 2, self.load_bytes, self.manifest(aggregate_sha256="0" * 64))
        failure(self, 2, self.load_bytes, self.manifest(schema_version=True))
        failure(self, 2, self.load_bytes,
                self.manifest(aggregate_algorithm="unnamed"))

    def verify_digest_mismatch(self, relative):
        contents = {path: path.encode() for path in s2.PROTECTED_PATHS}
        files = {path: hashlib.sha256(data).hexdigest() for path, data in contents.items()}
        manifest = {"protected_files": files, "aggregate_sha256": s2.aggregate_digest(files)}
        contents[relative] += b"changed"
        executable = stat_value(st_size=1, st_mode=stat.S_IFREG | 0o700)
        regular = stat_value(st_size=1)

        def read(path, _limit, _code, _reason):
            rel = os.path.relpath(path, "/repo")
            return contents[rel], executable if rel == "nullsec-wolt-stage2b.sh" else regular

        cfg = {"repository": "/repo", "launcher": "/repo/nullsec-wolt-stage2b.sh"}
        with mock.patch.object(s2, "verify_context", return_value=("/repo", cfg["launcher"], "/repo/lib/wolt-stage2b.py")), \
             mock.patch.object(s2, "load_manifest", return_value=manifest), \
             mock.patch.object(s2, "read_absolute_stable", side_effect=read):
            failure(self, 2, s2.verify_integrity, cfg)

    def test_protected_launcher_and_core_digest_mismatch(self):
        self.verify_digest_mismatch(".gitignore")
        self.verify_digest_mismatch("nullsec-wolt-stage2b.sh")
        self.verify_digest_mismatch("lib/wolt-stage2b.py")

    def test_ancestor_foreign_owner_and_modes(self):
        directory = lambda uid=0, mode=0o755: types.SimpleNamespace(
            st_mode=stat.S_IFDIR | mode, st_uid=uid, st_gid=uid,
            st_dev=1, st_ino=1)
        for bad in (directory(uid=77), directory(mode=0o775), directory(mode=0o777)):
            descriptors = iter((10, 11))
            table = {10: directory(), 11: bad}
            ops = types.SimpleNamespace(
                O_RDONLY=os.O_RDONLY, O_DIRECTORY=os.O_DIRECTORY,
                O_CLOEXEC=getattr(os, "O_CLOEXEC", 0),
                O_NOFOLLOW=getattr(os, "O_NOFOLLOW", 0), geteuid=lambda: 1001,
                open=lambda *_args, **_kwargs: next(descriptors),
                fstat=lambda fd: table[fd], close=lambda _fd: None)
            with self.subTest(bad=bad):
                failure(self, 2, s2.open_trusted_directory, "/bad", 2, "ANCESTOR", ops)


class PublicationTests(TemporaryCase):
    def context(self, name="output.json"):
        return s2.open_output_parent(str(self.directory / name))

    def publish(self, context, payload=b"payload\n", **kwargs):
        return s2.publish_atomic(context, payload, lambda: None, **kwargs)

    def test_short_writes_and_exact_mode(self):
        context = self.context()
        original = os.write
        try:
            with mock.patch.object(s2.os, "write",
                                   side_effect=lambda fd, data: original(fd, data[:2])):
                self.publish(context)
            output = self.directory / "output.json"
            self.assertEqual(output.read_bytes(), b"payload\n")
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o400)
        finally:
            s2.close_context(context)

    def test_zero_write_fsync_chmod_atomic_and_precheck_failures(self):
        scenarios = []
        scenarios.append(("zero", {"write": mock.patch.object(s2.os, "write", return_value=0)}))
        original_fsync = os.fsync; calls = [0]
        def fail_first(fd):
            calls[0] += 1
            if calls[0] == 1: raise OSError(errno.EIO, "fsync")
            return original_fsync(fd)
        scenarios.append(("fsync", {"fsync": mock.patch.object(s2.os, "fsync", side_effect=fail_first)}))
        scenarios.append(("chmod", {"chmod": mock.patch.object(s2.os, "fchmod", side_effect=OSError(errno.EIO, "chmod"))}))
        for label, patches in scenarios:
            context = self.context(label + ".json")
            try:
                patcher = next(iter(patches.values())); patcher.start()
                try: failure(self, 6, self.publish, context)
                finally: patcher.stop()
                self.assertFalse((self.directory / (label + ".json")).exists())
                self.assertFalse(any(p.name.startswith(".stage2b-") for p in self.directory.iterdir()))
            finally:
                s2.close_context(context)
        context = self.context("atomic.json")
        try:
            def atomic_failure(*_args):
                s2.abort(6, "ATOMIC_TEST")
            failure(self, 6, self.publish, context, rename_function=atomic_failure)
            self.assertFalse((self.directory / "atomic.json").exists())
        finally:
            s2.close_context(context)
        context = self.context("precheck.json")
        try:
            failure(self, 6, s2.publish_atomic, context, b"x\n",
                    lambda: s2.abort(6, "PRECHECK"))
            self.assertFalse((self.directory / "precheck.json").exists())
        finally:
            s2.close_context(context)

    def test_directory_fsync_and_verification_rollback(self):
        context = self.context("dir-fsync.json")
        original = os.fsync; calls = [0]
        def fail_third(fd):
            calls[0] += 1
            if calls[0] == 3: raise OSError(errno.EIO, "directory")
            return original(fd)
        try:
            with mock.patch.object(s2.os, "fsync", side_effect=fail_third):
                failure(self, 6, self.publish, context)
            self.assertFalse((self.directory / "dir-fsync.json").exists())
        finally:
            s2.close_context(context)
        context = self.context("verify.json")
        original_open = s2.open_regular_at
        def fail_verify(parent, name, code, reason, ops=os):
            if reason == "PUBLISHED": s2.abort(6, "VERIFY_TEST")
            return original_open(parent, name, code, reason, ops)
        try:
            with mock.patch.object(s2, "open_regular_at", side_effect=fail_verify):
                failure(self, 6, self.publish, context)
            self.assertFalse((self.directory / "verify.json").exists())
        finally:
            s2.close_context(context)

    def test_temporary_collision_and_cleanup_failure(self):
        collision = self.directory / ".stage2b-fixed"; collision.write_bytes(b"sentinel")
        context = self.context("collision.json")
        try:
            with mock.patch.object(s2.secrets, "token_hex", return_value="fixed"):
                failure(self, 6, self.publish, context)
            self.assertEqual(collision.read_bytes(), b"sentinel")
        finally:
            s2.close_context(context)
            collision.unlink()
        context = self.context("cleanup.json")
        try:
            with mock.patch.object(s2.os, "write", return_value=0), \
                 mock.patch.object(s2, "cleanup_name", side_effect=s2.Failure(6, "CLEANUP_TEST")):
                exc = failure(self, 6, self.publish, context)
                self.assertEqual(exc.reason, "CLEANUP_TEST")
        finally:
            s2.close_context(context)
            for path in self.directory.glob(".stage2b-*"):
                path.unlink()

    def test_atomic_unavailable(self):
        library = types.SimpleNamespace()
        failure(self, 6, s2.rename_noreplace, 3, "a", "b", library)


class ProductionConversionTests(TemporaryCase):
    def cfg(self, source, profile, input_path, output_path):
        return s2.parse_cli(conversion_args(source, profile, input_path, output_path))

    def test_production_success_failure_zero_and_repeat(self):
        source = self.write("lines", b"B.WOLT.COM.\na.wolt.com\na.wolt.com\n")
        outputs = []
        for index in range(2):
            output = self.directory / ("success-%d.json" % index)
            s2.convert(self.cfg("subfinder", "hostname-lines-v1", source, output))
            outputs.append(output.read_bytes())
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o400)
        self.assertEqual(outputs[0], outputs[1])
        assert_stage2a_envelope(self, outputs[0])
        empty = self.write("empty", b"")
        empty_output = self.directory / "empty.json"
        s2.convert(self.cfg("amass", "hostname-lines-v1", empty, empty_output))
        self.assertEqual(json.loads(empty_output.read_bytes())["records"], [])
        failed = self.write("failed", receipt("virustotal", "CREDENTIAL_ERROR"))
        failed_output = self.directory / "failed.json"
        s2.convert(self.cfg("virustotal", "retained-provider-failure-v1", failed, failed_output))
        assert_stage2a_envelope(self, failed_output.read_bytes())

    def test_existing_symlink_alias_and_malformed_publication(self):
        source = self.write("input", b"a.wolt.com\n")
        existing = self.write("existing", b"unchanged")
        before = existing.read_bytes()
        failure(self, 6, s2.convert,
                self.cfg("amass", "hostname-lines-v1", source, existing))
        self.assertEqual(existing.read_bytes(), before)
        symlink = self.directory / "output-link"; symlink.symlink_to(existing)
        failure(self, 6, s2.convert,
                self.cfg("amass", "hostname-lines-v1", source, symlink))
        hardlink = self.directory / "hardlink"; os.link(source, hardlink)
        failure(self, 6, s2.convert,
                self.cfg("amass", "hostname-lines-v1", source, hardlink))
        malformed = self.write("malformed", b"a\n\nb")
        output = self.directory / "not-created"
        failure(self, 3, s2.convert,
                self.cfg("amass", "hostname-lines-v1", malformed, output))
        self.assertFalse(output.exists())

    def test_public_main_exact_success_and_failure(self):
        source = self.write("public-input", b"a.wolt.com\n")
        output = self.directory / "public-output"
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            rc = s2.main(conversion_args("assetfinder", "hostname-lines-v1", source, output))
        self.assertEqual((rc, stdout.getvalue(), stderr.getvalue()),
                         (0, "STAGE2B_COMPLETE\n", ""))
        bad = self.write("bad", b"a\r\n")
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            rc = s2.main(conversion_args("assetfinder", "hostname-lines-v1", bad,
                                         self.directory / "bad-output"))
        self.assertEqual((rc, stdout.getvalue(), stderr.getvalue()),
                         (3, "", "STAGE2B_INPUT_ERROR\n"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
