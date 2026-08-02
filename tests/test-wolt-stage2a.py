#!/usr/bin/python3
"""Deterministic offline unit and fault-injection tests for Stage 2A."""

import copy
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
import shutil
import tempfile
import types
import unittest
from unittest import mock
import sys

sys.dont_write_bytecode = True
os.environ.pop("BASH_ENV", None)
os.environ.pop("ENV", None)
sys_path = Path(__file__).resolve().parents[1] / "lib" / "wolt-stage2a.py"
loader = importlib.machinery.SourceFileLoader("wolt_stage2a", str(sys_path))
spec = importlib.util.spec_from_loader(loader.name, loader)
s2 = importlib.util.module_from_spec(spec)
loader.exec_module(s2)


def envelope(source="subfinder", status="success", records=None, **extra):
    records = [] if records is None else records
    value = {"schema_version": 1, "source_id": source,
             "collection_status": status, "record_count": len(records),
             "records": records}
    if status == "failed": value["error_code"] = "COLLECTION_FAILED"
    value.update(extra)
    return json.dumps(value, separators=(",", ":")).encode()


def expect_failure(testcase, code, function, *args, **kwargs):
    with testcase.assertRaises(s2.Failure) as caught:
        function(*args, **kwargs)
    testcase.assertEqual(caught.exception.code, code)
    return caught.exception


class IdentityTests(unittest.TestCase):
    def fake(self, uid=1, euid=1, gid=2, egid=2):
        return types.SimpleNamespace(getuid=lambda: uid, geteuid=lambda: euid,
                                     getgid=lambda: gid, getegid=lambda: egid)

    def test_identity_accepts_equal_ids(self):
        s2.verify_identity(self.fake())

    def test_uid_mismatch_precedes_gid(self):
        exc = expect_failure(self, 2, s2.verify_identity, self.fake(uid=1, euid=3, gid=2, egid=4))
        self.assertEqual(exc.reason, "UID_MISMATCH")

    def test_gid_mismatch(self):
        exc = expect_failure(self, 2, s2.verify_identity, self.fake(gid=2, egid=4))
        self.assertEqual(exc.reason, "GID_MISMATCH")

    def test_main_identity_failure_accesses_no_files(self):
        with mock.patch.object(s2, "verify_identity", side_effect=s2.Failure(2, "UID_MISMATCH")), \
             mock.patch.object(s2, "parse_cli") as parse:
            self.assertEqual(s2.main([]), 2)
            parse.assert_not_called()


class EnvelopeTests(unittest.TestCase):
    def test_every_source_id(self):
        for source in s2.SOURCE_IDS:
            with self.subTest(source=source):
                self.assertEqual(s2.validate_envelope(source, envelope(source)), [])

    def test_zero_success(self):
        self.assertEqual(s2.validate_envelope("amass", envelope("amass")), [])

    def test_failure_codes(self):
        for code in s2.SOURCE_ERRORS:
            data = envelope("shodan", "failed", error_code=code)
            with self.subTest(code=code):
                exc = expect_failure(self, 4, s2.validate_envelope, "shodan", data)
                self.assertEqual(exc.reason, code)

    def test_unknown_failure_code(self):
        expect_failure(self, 4, s2.validate_envelope, "shodan",
                       envelope("shodan", "failed", error_code="RAW_ERROR"))

    def test_error_on_success(self):
        expect_failure(self, 4, s2.validate_envelope, "subfinder",
                       envelope(error_code="TOOL_ERROR"))

    def test_missing_error_on_failure(self):
        value = json.loads(envelope("shodan", "failed")); del value["error_code"]
        expect_failure(self, 4, s2.validate_envelope, "shodan", json.dumps(value).encode())

    def test_failed_records_and_count(self):
        for value in ({"records": ["a.wolt.com"], "record_count": 1}, {"record_count": 1}):
            with self.subTest(value=value):
                expect_failure(self, 4, s2.validate_envelope, "shodan",
                               envelope("shodan", "failed", **value))

    def test_source_mismatch(self):
        expect_failure(self, 4, s2.validate_envelope, "amass", envelope("subfinder"))

    def test_unknown_and_missing_keys(self):
        base = json.loads(envelope())
        variants = [dict(base, extra=True), {k: v for k, v in base.items() if k != "records"}]
        for value in variants:
            with self.subTest(keys=value.keys()):
                expect_failure(self, 4, s2.validate_envelope, "subfinder", json.dumps(value).encode())

    def test_duplicate_json_key(self):
        data = b'{"schema_version":1,"schema_version":1,"source_id":"subfinder","collection_status":"success","record_count":0,"records":[]}'
        expect_failure(self, 4, s2.validate_envelope, "subfinder", data)

    def test_count_types_and_values(self):
        for count in (True, -1, 1):
            value = json.loads(envelope()); value["record_count"] = count
            with self.subTest(count=count):
                expect_failure(self, 4, s2.validate_envelope, "subfinder", json.dumps(value).encode())

    def test_record_limit(self):
        value = json.loads(envelope()); value["record_count"] = s2.MAX_RECORDS + 1
        expect_failure(self, 4, s2.validate_envelope, "subfinder", json.dumps(value).encode())
        records = [""] * (s2.MAX_RECORDS + 1)
        value = {"schema_version": 1, "source_id": "subfinder", "collection_status": "success",
                 "record_count": len(records), "records": records}
        expect_failure(self, 4, s2.validate_envelope, "subfinder", json.dumps(value).encode())

    def test_record_types(self):
        for record in (1, True, {}, [], None):
            with self.subTest(record=record):
                expect_failure(self, 4, s2.validate_envelope, "subfinder", envelope(records=[record]))

    def test_record_encoding_and_controls(self):
        for record in ("wölt.com", "a\nb", "a\rb", "a\0b"):
            with self.subTest(record=repr(record)):
                expect_failure(self, 4, s2.validate_envelope, "subfinder", envelope(records=[record]))

    def test_nul_and_invalid_utf8(self):
        expect_failure(self, 4, s2.validate_envelope, "subfinder", b"{\0}")
        expect_failure(self, 4, s2.validate_envelope, "subfinder", b"\xff")

    def test_cli_unknown_duplicate_and_seed_options(self):
        internal = ["--repository", "/r", "--launcher", "/r/l"]
        expect_failure(self, 4, s2.parse_cli, internal + ["--evidence-root", "/e", "--import-source", "bad", "/x"])
        expect_failure(self, 4, s2.parse_cli, internal + ["--evidence-root", "/e", "--import-source", "amass", "/x", "--import-source", "amass", "/y"])
        for option in ("--seed", "--domain", "--run", "--scan", "--enumerate", "--live"):
            with self.subTest(option=option): expect_failure(self, 64, s2.parse_cli, internal + [option])


class DescriptorTests(unittest.TestCase):
    def metadata(self, **changes):
        base = dict(st_dev=1, st_ino=2, st_size=3,
                    st_mode=stat.S_IFREG | 0o600, st_uid=os.getuid(),
                    st_gid=os.getgid(), st_mtime_ns=4, st_ctime_ns=5)
        base.update(changes); return types.SimpleNamespace(**base)

    def fake_ops(self, before, after, chunks=(b"abc", b"")):
        stats = iter((before, after)); reads = iter(chunks)
        return types.SimpleNamespace(fstat=lambda _fd: next(stats), read=lambda _fd, _size: next(reads))

    def test_unchanged_read(self):
        st = self.metadata(); data, _ = s2.read_fd_verified(3, 10, 3, "X", self.fake_ops(st, st))
        self.assertEqual(data, b"abc")

    def test_every_metadata_change(self):
        changes = {"st_dev": 9, "st_ino": 9, "st_size": 4,
                   "st_mode": stat.S_IFREG | 0o400, "st_uid": os.getuid() + 1,
                   "st_mtime_ns": 9, "st_ctime_ns": 9}
        before = self.metadata()
        for field, value in changes.items():
            with self.subTest(field=field):
                after = self.metadata(**{field: value})
                expect_failure(self, 3, s2.read_fd_verified, 3, 10, 3, "X", self.fake_ops(before, after))

    def test_type_and_permissions_change(self):
        for mode in (stat.S_IFDIR | 0o700, stat.S_IFREG | 0o620, stat.S_IFREG | 0o602):
            with self.subTest(mode=oct(mode)):
                expect_failure(self, 3, s2.read_fd_verified, 3, 10, 3, "X",
                               self.fake_ops(self.metadata(), self.metadata(st_mode=mode)))

    def test_short_truncate_growth_and_stream_limit(self):
        cases = [
            (self.metadata(st_size=4), self.metadata(st_size=4), (b"abc", b""), 10),
            (self.metadata(), self.metadata(st_size=4), (b"abc", b"d", b""), 10),
            (self.metadata(st_size=6), self.metadata(st_size=6), (b"abc", b"def", b""), 5),
        ]
        for before, after, chunks, limit in cases:
            with self.subTest(chunks=chunks):
                expect_failure(self, 3, s2.read_fd_verified, 3, limit, 3, "X",
                               self.fake_ops(before, after, chunks))


class H1AncestorTests(unittest.TestCase):
    def fake_ops(self, entries):
        table = {index + 10: entry for index, entry in enumerate(entries)}
        names = iter(range(10, 10 + len(entries)))
        return types.SimpleNamespace(
            O_RDONLY=os.O_RDONLY, O_DIRECTORY=os.O_DIRECTORY, O_CLOEXEC=getattr(os, "O_CLOEXEC", 0),
            O_NOFOLLOW=getattr(os, "O_NOFOLLOW", 0), geteuid=lambda: 1001,
            open=lambda _name, _flags, **_kwargs: next(names), fstat=lambda fd: table[fd], close=lambda _fd: None)

    def directory(self, uid=0, mode=0o755):
        return types.SimpleNamespace(st_mode=stat.S_IFDIR | mode, st_uid=uid)

    def check(self, entries, accepted):
        ops = self.fake_ops(entries)
        if accepted:
            fd = s2.open_trusted_ancestor_chain("/home/user/evidence", ops=ops); self.assertEqual(fd, 13)
        else: expect_failure(self, 2, s2.open_trusted_ancestor_chain, "/home/user/evidence", 2, "ANCESTOR", ops)

    def test_h1_trusted_root_and_current_uid_ancestors_accepted(self):
        self.check([self.directory(), self.directory(), self.directory(1001, 0o700),
                    self.directory(1001, 0o755)], True)

    def test_h1_foreign_owner_ancestor_rejected(self):
        self.check([self.directory(), self.directory(uid=77), self.directory(1001), self.directory(1001)], False)

    def test_h1_group_writable_ancestor_rejected(self):
        self.check([self.directory(), self.directory(mode=0o775), self.directory(1001), self.directory(1001)], False)

    def test_h1_world_writable_ancestor_rejected(self):
        self.check([self.directory(), self.directory(mode=0o1777), self.directory(1001), self.directory(1001)], False)

    def test_h1_symlink_ancestor_rejected(self):
        ops = self.fake_ops([self.directory(), self.directory(), self.directory(1001), self.directory(1001)])
        original = ops.open; calls = [0]
        def fail_symlink(name, flags, **kwargs):
            calls[0] += 1
            if calls[0] == 2: raise OSError(errno.ELOOP, "loop")
            return original(name, flags, **kwargs)
        ops.open = fail_symlink
        expect_failure(self, 2, s2.open_trusted_ancestor_chain, "/home/user/evidence", 2, "ANCESTOR", ops)


class H1RewalkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name) / "evidence"
        self.run_name = "INCOMPLETE-20260101T000000.000000000Z-0123456789abcdef"
        self.run_path = self.root / self.run_name; self.runtime = self.run_path / ".stage1-runtime"
        self.runtime.mkdir(parents=True, mode=0o700)
        self.wrapper = self.runtime / "nullsec-wolt.sh"; self.wrapper.write_bytes(b"#!/bin/bash\n")
        self.input = self.runtime / "classifier-input.txt"; self.input.write_bytes(b"wolt.com\n")
        self.wrapper.chmod(0o500); self.input.chmod(0o400); self.runtime.chmod(0o500)
        self.root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.run_fd = os.open(self.run_path, os.O_RDONLY | os.O_DIRECTORY)
        self.runtime_fd = os.open(self.runtime, os.O_RDONLY | os.O_DIRECTORY)
        self.root_parent_fd = os.open(self.root.parent, os.O_RDONLY | os.O_DIRECTORY)
        self.run = {"name": self.run_name, "root_identity": s2.descriptor_identity(os.fstat(self.root_fd)),
                    "identity": s2.descriptor_identity(os.fstat(self.run_fd)),
                    "root_parent_fd": self.root_parent_fd, "root_name": self.root.name}
        self.snap = {"s_identity": s2.descriptor_identity(os.fstat(self.runtime_fd)),
                     "wrapper_identity": s2.snapshot_entry_identity(self.runtime_fd, "nullsec-wolt.sh"),
                     "input_identity": s2.snapshot_entry_identity(self.runtime_fd, "classifier-input.txt")}
        self.canary = False

    def tearDown(self):
        os.close(self.runtime_fd); os.close(self.run_fd); os.close(self.root_fd); os.close(self.root_parent_fd)
        self.temp.cleanup()

    def attempt(self):
        try: s2.final_classifier_rewalk(self.root_fd, self.run, self.snap)
        except s2.Failure: pass
        else: self.canary = True

    def rejected(self):
        self.attempt(); self.assertFalse(self.canary)
        self.assertFalse(any(p.is_dir() and not p.name.startswith("INCOMPLETE-") for p in self.root.iterdir()))

    def replace_file(self, path, data=b"replacement\n", mode=0o500):
        self.runtime.chmod(0o700)
        path.rename(path.with_name(path.name + ".old")); path.write_bytes(data); path.chmod(mode)
        self.runtime.chmod(0o500)

    def test_h1_evidence_root_identity_replacement_rejected(self):
        self.root.rename(self.root.with_name("evidence.old")); self.root.mkdir(mode=0o700); self.rejected()

    def test_h1_incomplete_identity_replacement_rejected(self):
        self.run_path.rename(self.root / (self.run_name + ".old")); (self.root / self.run_name).mkdir(mode=0o700); self.rejected()

    def test_h1_runtime_identity_replacement_rejected(self):
        self.runtime.rename(self.run_path / ".stage1-runtime.old"); self.runtime.mkdir(mode=0o500); self.rejected()

    def test_h1_wrapper_identity_replacement_rejected(self):
        self.replace_file(self.wrapper); self.rejected()

    def test_h1_classifier_input_identity_replacement_rejected(self):
        self.replace_file(self.input, mode=0o400); self.rejected()

    def test_h1_file_type_change_rejected(self):
        self.runtime.chmod(0o700); self.wrapper.rename(self.runtime / "wrapper.old")
        self.wrapper.mkdir(mode=0o500); self.runtime.chmod(0o500); self.rejected()

    def test_h1_ownership_change_rejected(self):
        self.snap["wrapper_identity"] = (*self.snap["wrapper_identity"][:3], os.getuid() + 1,
                                         self.snap["wrapper_identity"][4]); self.rejected()

    def test_h1_mode_change_rejected(self):
        self.wrapper.chmod(0o400); self.rejected()

    def test_h1_stable_descriptor_relative_control_succeeds(self):
        self.attempt(); self.assertTrue(self.canary)


class H1IntegratedProcessTests(unittest.TestCase):
    """H1 tests through main -> process using real descendants and classifier path."""

    PROTECTED = ("nullsec.sh", "nullsec-wolt.sh", "config/wolt-approved-exact.txt",
                 "config/wolt-excluded.txt", "config/wolt-mobile-assets.txt",
                 "config/wolt-policy.json", "tests/test-wolt-wrapper.sh")

    @classmethod
    def setUpClass(cls):
        cls.real_repo = Path(__file__).resolve().parents[1]
        cls.protected_before = cls.protected_hashes()

    @classmethod
    def protected_hashes(cls, reader=None):
        reader = reader or (lambda path: path.read_bytes())
        return {name: hashlib.sha256(reader(cls.real_repo / name)).hexdigest()
                for name in cls.PROTECTED}

    @classmethod
    def assert_protected_preserved(cls, reader=None):
        if cls.protected_hashes(reader) != cls.protected_before:
            raise AssertionError("protected-file content changed during integrated H1 suite")

    @classmethod
    def tearDownClass(cls):
        cls.assert_protected_preserved()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix=".stage2a-h1-", dir=str(self.real_repo))
        self.base = Path(self.temp.name); self.repo = self.base / "repo"; self.root = self.base / "evidence"
        (self.repo / "lib").mkdir(parents=True); (self.repo / "config").mkdir(); self.root.mkdir(mode=0o700)
        self.marker = self.base / "CLASSIFIER-EXECUTED"; self.sentinel = self.base / "PROVIDER-NETWORK-SENTINEL"
        self.sentinel.write_bytes(b"unchanged\n"); self.sentinel_hash = hashlib.sha256(self.sentinel.read_bytes()).digest()
        launcher = self.repo / "nullsec-wolt-stage2a.sh"
        launcher.write_bytes(b"#!/bin/bash -p\nexit 99\n"); launcher.chmod(0o700)
        shutil.copyfile(sys_path, self.repo / "lib/wolt-stage2a.py"); (self.repo / "lib/wolt-stage2a.py").chmod(0o600)
        wrapper = self.repo / "nullsec-wolt.sh"
        wrapper.write_text("#!/bin/bash\n/bin/touch -- " + self._quote(self.marker) + "\n"
                           "while IFS= read -r line; do printf 'APPROVED_EXACT\\n'; done < \"$2\"\n")
        wrapper.chmod(0o700)
        for name in s2.STAGE1_FILES[1:]:
            path = self.repo / name; path.write_bytes((name + "\n").encode()); path.chmod(0o600)
        digests = {name: hashlib.sha256((self.repo / name).read_bytes()).hexdigest() for name in s2.STAGE1_FILES}
        manifest = {"schema_version": 1, "aggregate_algorithm": "named-sha256-v1", "stage1_files": digests}
        mp = self.repo / "config/wolt-stage2a-integrity.json"; mp.write_text(json.dumps(manifest)); mp.chmod(0o600)
        self.input = self.base / "input.json"; self.input.write_bytes(envelope(records=["wolt.com"])); self.input.chmod(0o600)
        self.argv = ["--repository", str(self.repo), "--launcher", str(launcher),
                     "--evidence-root", str(self.root), "--import-source", "subfinder", str(self.input)]
        self.real_rewalk = s2.final_classifier_rewalk
        self.real_bounded = s2.bounded_process
        self.real_ancestor = s2.open_trusted_ancestor_chain
        self.ancestor_effect = None

    @staticmethod
    def _quote(path):
        return "'" + str(path).replace("'", "'\\''") + "'"

    def tearDown(self):
        self.temp.cleanup()

    def ancestor_ops(self, effect=None):
        """Delegate all syscalls; model only sandbox-remapped absolute ancestor metadata."""
        real = os
        root_key = (real.stat("/").st_dev, real.stat("/").st_ino)
        home_key = (real.stat("/home").st_dev, real.stat("/home").st_ino)
        base_key = (real.stat(self.base).st_dev, real.stat(self.base).st_ino)
        def fstat(fd):
            st = real.fstat(fd); key = (st.st_dev, st.st_ino); values = {}
            if key in (root_key, home_key) and st.st_uid == 65534: values["st_uid"] = 0
            if effect and key == base_key:
                if effect == "foreign": values["st_uid"] = real.geteuid() + 100
                elif effect == "group": values["st_mode"] = st.st_mode | stat.S_IWGRP
                elif effect == "world": values["st_mode"] = st.st_mode | stat.S_IWOTH
            return types.SimpleNamespace(**{name: values.get(name, getattr(st, name)) for name in dir(st)
                                           if name.startswith("st_")})
        return types.SimpleNamespace(O_RDONLY=real.O_RDONLY, O_DIRECTORY=real.O_DIRECTORY,
            O_CLOEXEC=getattr(real, "O_CLOEXEC", 0), O_NOFOLLOW=getattr(real, "O_NOFOLLOW", 0),
            geteuid=real.geteuid, open=real.open, fstat=fstat, close=real.close)

    def trusted_open(self, path, code=s2.EXIT_INTEGRITY, reason="ANCESTOR", ops=os, retain_parent=False):
        return self.real_ancestor(path, code, reason,
            self.ancestor_ops(self.ancestor_effect), retain_parent)

    def invoke(self, mutation=None, rewalk=None, bounded=None):
        out, err = io.StringIO(), io.StringIO()
        patches = [mock.patch.object(s2, "open_trusted_ancestor_chain", side_effect=self.trusted_open)]
        if rewalk is not None: patches.append(mock.patch.object(s2, "final_classifier_rewalk", side_effect=rewalk))
        if bounded is not None: patches.append(mock.patch.object(s2, "bounded_process", side_effect=bounded))
        with contextlib.ExitStack() as stack:
            for patch in patches: stack.enter_context(patch)
            if mutation:
                def mutate_then_rewalk(root_fd, run, snap):
                    mutation(root_fd, run, snap)
                    return self.real_rewalk(root_fd, run, snap)
                stack.enter_context(mock.patch.object(s2, "final_classifier_rewalk", side_effect=mutate_then_rewalk))
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err): rc = s2.main(self.argv)
        return rc, out.getvalue(), err.getvalue()

    def assert_integrity_rejection(self, mutation=None, **invoke_kwargs):
        rc, out, err = self.invoke(mutation, **invoke_kwargs)
        self.assertEqual((rc, out, err), (s2.EXIT_INTEGRITY, "", "STAGE2A_INTEGRITY_ERROR\n"))
        self.assertFalse(self.marker.exists(), "real classifier canary executed")
        self.assertEqual(hashlib.sha256(self.sentinel.read_bytes()).digest(), self.sentinel_hash)
        entries = list(self.root.iterdir()) if self.root.exists() else []
        self.assertFalse(any(p.is_dir() and not p.name.startswith("INCOMPLETE-") for p in entries))
        self.assertTrue(all(not p.is_dir() or p.name.startswith("INCOMPLETE-") for p in entries))

    def runtime_paths(self, run):
        runtime = self.root / run["name"] / ".stage1-runtime"
        return runtime, runtime / "nullsec-wolt.sh", runtime / "classifier-input.txt"

    def replace(self, path, kind="file", mode=None):
        parent = path.parent; parent.chmod(0o700); path.rename(path.with_name(path.name + ".old"))
        if kind == "dir": path.mkdir(mode=mode or 0o500)
        elif kind == "symlink": path.symlink_to(path.with_name(path.name + ".old").name)
        else: path.write_bytes(b"ATTACKER_CONTROLLED_BYTES\n"); path.chmod(mode or 0o500)
        parent.chmod(0o500)

    def test_h1_process_rejects_unsafe_ancestors_and_symlink(self):
        for effect in ("foreign", "group", "world"):
            with self.subTest(effect=effect):
                self.ancestor_effect = effect; self.assert_integrity_rejection(); self.ancestor_effect = None
        real_root = self.root; moved = self.base / "evidence-real"; real_root.rename(moved); real_root.symlink_to(moved.name)
        self.assert_integrity_rejection()

    def test_h1_process_rejects_all_rewalk_mutations_with_real_canary(self):
        def root(_fd, run, _snap):
            self.root.rename(self.base / "evidence.old"); self.root.mkdir(mode=0o700)
        def run_dir(_fd, run, _snap):
            p = self.root / run["name"]; p.rename(self.root / (run["name"] + ".old")); p.mkdir(mode=0o700)
        def runtime(_fd, run, _snap): self.replace(self.runtime_paths(run)[0], "dir", 0o500)
        def wrapper(_fd, run, _snap): self.replace(self.runtime_paths(run)[1], "file", 0o500)
        def inp(_fd, run, _snap): self.replace(self.runtime_paths(run)[2], "file", 0o400)
        def file_type(_fd, run, _snap): self.replace(self.runtime_paths(run)[1], "dir", 0o500)
        def mode(_fd, run, _snap): self.runtime_paths(run)[1].chmod(0o400)
        def symlink(_fd, run, _snap): self.replace(self.runtime_paths(run)[1], "symlink")
        for name, mutation in (("root", root), ("incomplete", run_dir), ("runtime", runtime),
                               ("wrapper", wrapper), ("input", inp), ("type", file_type),
                               ("mode", mode), ("symlink", symlink)):
            with self.subTest(name=name): self.assert_integrity_rejection(mutation)
            self.tearDown(); self.setUp()

    def test_h1_rewalk_call_contract_order_and_forced_failure(self):
        events = []; real = self.real_rewalk
        def rewalk(root_fd, run, snap):
            self.assertIn("snapshot", events); self.assertNotIn("classifier", events)
            events.append("rewalk"); return real(root_fd, run, snap)
        def boundary(argv, *args, **kwargs):
            events.append("classifier"); self.assertEqual(events.count("rewalk"), 1)
            return self.real_bounded(argv, *args, **kwargs)
        original_snapshot = s2.snapshot_stage1
        def snapshot(*args, **kwargs):
            result = original_snapshot(*args, **kwargs); events.append("snapshot"); return result
        with mock.patch.object(s2, "snapshot_stage1", side_effect=snapshot):
            rc, out, err = self.invoke(rewalk=rewalk, bounded=boundary)
        self.assertEqual((rc, out, err), (0, "", "")); self.assertEqual(events, ["snapshot", "rewalk", "classifier"])
        self.assertTrue(self.marker.exists())

        self.marker.unlink(); events.clear()
        def fail_rewalk(*_args): events.append("rewalk"); raise s2.Failure(2, "FORCED_REWALK_FAILURE")
        rc, out, err = self.invoke(rewalk=fail_rewalk, bounded=boundary)
        self.assertEqual((rc, out, err), (2, "", "STAGE2A_INTEGRITY_ERROR\n")); self.assertFalse(self.marker.exists())
        self.assertEqual(events, ["rewalk"])

    def test_h1_real_dirfd_flags_and_identity_comparisons(self):
        calls = []; real_open, real_fstat, real_stat = os.open, os.fstat, os.stat
        def open_spy(path, flags, *args, **kwargs):
            calls.append(("open", str(path), flags, kwargs.get("dir_fd"))); return real_open(path, flags, *args, **kwargs)
        def fstat_spy(fd): calls.append(("fstat", fd)); return real_fstat(fd)
        def stat_spy(path, *args, **kwargs): calls.append(("stat", str(path), kwargs.get("dir_fd"), kwargs.get("follow_symlinks"))); return real_stat(path, *args, **kwargs)
        with mock.patch.object(s2.os, "open", side_effect=open_spy), mock.patch.object(s2.os, "fstat", side_effect=fstat_spy), \
             mock.patch.object(s2.os, "stat", side_effect=stat_spy):
            rc, out, err = self.invoke()
        self.assertEqual((rc, out, err), (0, "", ""))
        relative = [c for c in calls if c[0] == "open" and c[1] in
                    (self.root.name, next(p.name for p in self.root.iterdir()), ".stage1-runtime", "nullsec-wolt.sh", "classifier-input.txt")]
        self.assertTrue(relative); self.assertTrue(all(c[3] is not None for c in relative))
        if getattr(os, "O_NOFOLLOW", 0): self.assertTrue(all(c[2] & os.O_NOFOLLOW for c in relative))
        dirs = [c for c in relative if c[1] not in ("nullsec-wolt.sh", "classifier-input.txt")]
        if getattr(os, "O_DIRECTORY", 0): self.assertTrue(all(c[2] & os.O_DIRECTORY for c in dirs))
        self.assertTrue(any(c[0] == "stat" and c[2] is not None and c[3] is False for c in calls))
        self.assertGreaterEqual(sum(c[0] == "fstat" for c in calls), 5)

    def test_h1_expected_failure_mutation_guards(self):
        original_wrapper = (self.repo / "nullsec-wolt.sh").read_bytes()

        def replace_wrapper_with_same_bytes(_fd, run, _snap):
            wrapper = self.runtime_paths(run)[1]
            wrapper.parent.chmod(0o700)
            wrapper.rename(wrapper.with_name(wrapper.name + ".old"))
            wrapper.write_bytes(original_wrapper); wrapper.chmod(0o500)
            wrapper.parent.chmod(0o500)

        def bypass_rewalk(root_fd, run, snap):
            replace_wrapper_with_same_bytes(root_fd, run, snap)

        with self.subTest(mutant="final rewalk bypass"), self.assertRaises(AssertionError):
            self.assert_integrity_rejection(rewalk=bypass_rewalk)
        self.tearDown(); self.setUp()

        events = []
        def classifier_boundary(argv, *args, **kwargs):
            events.append("classifier")
            return self.real_bounded(argv, *args, **kwargs)
        def classifier_before_rewalk(root_fd, run, snap):
            base = os.path.join(self.root, run["name"], ".stage1-runtime")
            classifier_boundary(["/bin/bash", os.path.join(base, "nullsec-wolt.sh"),
                                 "--classify-file", os.path.join(base, "classifier-input.txt")])
            events.append("rewalk")
            return self.real_rewalk(root_fd, run, snap)
        rc, out, err = self.invoke(rewalk=classifier_before_rewalk, bounded=classifier_boundary)
        self.assertEqual((rc, out, err), (0, "", "")); self.assertTrue(self.marker.exists())
        with self.subTest(mutant="rewalk after classifier"), self.assertRaises(AssertionError):
            self.assertEqual(events, ["rewalk", "classifier"])
        self.tearDown(); self.setUp()

        def suppress_rewalk_failure(root_fd, run, snap):
            replace_wrapper_with_same_bytes(root_fd, run, snap)
            try: self.real_rewalk(root_fd, run, snap)
            except s2.Failure: return None
        with self.subTest(mutant="continue after rewalk failure"), self.assertRaises(AssertionError):
            self.assert_integrity_rejection(rewalk=suppress_rewalk_failure)
        self.tearDown(); self.setUp()

        reflected = "SYNTHETIC_SECRET_EXCEPTION_TEXT_DO_NOT_REFLECT"
        def forced_failure(*_args):
            raise s2.Failure(s2.EXIT_INTEGRITY, reflected)
        with mock.patch.dict(s2.ERROR_TOKEN, {s2.EXIT_INTEGRITY: reflected}):
            with self.subTest(mutant="exception text reflection"), self.assertRaises(AssertionError):
                self.assert_integrity_rejection(rewalk=forced_failure)
        self.tearDown(); self.setUp()

        real_read = s2.read_path_verified
        real_sha256 = hashlib.sha256
        protected_marker = b"\n# IN_MEMORY_PROTECTED_CHANGE\n"
        injected = []
        def changed_production_read(path, limit, code, reason):
            data, st = real_read(path, limit, code, reason)
            if Path(path) == self.repo / "nullsec-wolt.sh":
                data += protected_marker; injected.append(data)
            return data, st
        def broken_production_sha256(data=b""):
            if protected_marker in data:
                data = data.replace(protected_marker, b"")
            return real_sha256(data)
        def changed_reader(path):
            data = path.read_bytes()
            return data + (protected_marker if path.name == "nullsec-wolt.sh" else b"")
        self.assertNotEqual(real_sha256(original_wrapper).digest(),
                            real_sha256(original_wrapper + protected_marker).digest())
        self.assertEqual(broken_production_sha256(original_wrapper).digest(),
                         broken_production_sha256(original_wrapper + protected_marker).digest())
        with mock.patch.object(s2, "read_path_verified", side_effect=changed_production_read), \
             mock.patch.object(s2.hashlib, "sha256", side_effect=broken_production_sha256):
            rc, out, err = self.invoke()
        self.assertEqual((rc, out, err), (0, "", "")); self.assertTrue(self.marker.exists())
        self.assertEqual(len(injected), 1); self.assertIn(protected_marker, injected[0])
        self.assertIs(s2.hashlib.sha256, real_sha256)
        with self.subTest(mutant="protected-file guard failure"), \
             self.assertRaisesRegex(AssertionError, "protected-file content changed"):
            self.assert_protected_preserved(changed_reader)

    def test_h1_genuine_owner_change_when_capable(self):
        path = self.base / "ownership-target"; path.write_bytes(b"x"); before = path.stat().st_uid
        candidate = before + 1
        try: os.chown(path, candidate, -1)
        except OSError:
            self.skipTest("real st_uid mutation unavailable; run host shell: /usr/bin/python3 -I -S tests/test-wolt-stage2a.py H1IntegratedProcessTests.test_h1_genuine_owner_change_when_capable")
        after = path.stat().st_uid
        self.assertNotEqual(before, after)
        def ownership_mutation(_fd, run, _snap):
            wrapper = self.runtime_paths(run)[1]; wrapper.parent.chmod(0o700)
            os.chown(wrapper, candidate, -1); self.assertEqual(wrapper.stat().st_uid, candidate)
            wrapper.parent.chmod(0o500)
        self.assert_integrity_rejection(ownership_mutation)


class ClassificationTests(unittest.TestCase):
    def positions(self):
        return [("subfinder", 1, "wolt.com"), ("subfinder", 2, "api.wolt.com"),
                ("subfinder", 3, "press.wolt.com"), ("subfinder", 4, "example.com"),
                ("subfinder", 5, "com.wolt.android"), ("subfinder", 6, "https://wolt.com")]

    def test_all_tokens_and_separation(self):
        tokens = ["APPROVED_EXACT", "PENDING_WILDCARD_REVIEW", "APPROVED_EXACT",
                  "NON_WOLT", "MOBILE_ASSET", "MALFORMED"]
        out, counts = s2.aggregate(self.positions(), tokens)
        self.assertEqual(out["approved-exact.txt"], b"wolt.com\n")
        self.assertEqual(out["wildcard-candidates-unreviewed.txt"], b"api.wolt.com\n")
        self.assertEqual(out["explicitly-excluded.txt"], b"press.wolt.com\n")
        self.assertNotIn(b"approved", out["wildcard-candidates-unreviewed.txt"].lower())
        self.assertEqual(counts["EXCLUDED"], 1)

    def test_duplicate_provenance(self):
        positions = [("subfinder", 1, "api.wolt.com"), ("subfinder", 2, "API.WOLT.COM."),
                     ("assetfinder", 1, "api.wolt.com")]
        out, _ = s2.aggregate(positions, ["PENDING_WILDCARD_REVIEW"] * 3)
        self.assertEqual(out["wildcard-candidates-unreviewed.txt"], b"api.wolt.com\n")
        rows = out["provenance.tsv"].splitlines()
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[1:], sorted(rows[1:]))

    def test_malformed_not_reflected(self):
        out, _ = s2.aggregate([("subfinder", 7, "secret$(value)")], ["MALFORMED"])
        self.assertNotIn(b"secret", out["rejected-malformed.txt"])

    def test_classifier_validation_failures(self):
        self.assertEqual(s2.validate_classifier_result(0, b"APPROVED_EXACT\n", b"", 1), ["APPROVED_EXACT"])
        variants = [(20, b"", b"", 1), (20, b"MALFORMED\nMALFORMED\n", b"", 1),
                    (20, b"UNKNOWN\n", b"", 1), (20, b"MALFORMED\n", b"error", 1),
                    (-9, b"", b"", 0), (7, b"", b"", 0),
                    (20, b"\xff\n", b"", 1), (20, b"MALFORMED", b"", 1)]
        for args in variants:
            with self.subTest(args=args): expect_failure(self, 5, s2.validate_classifier_result, *args)

    def test_bounded_process_missing_timeout_and_output_limit(self):
        expect_failure(self, 5, s2.bounded_process, ["/definitely/missing/stage2a"])
        expect_failure(self, 5, s2.bounded_process,
                       ["/usr/bin/python3", "-I", "-S", "-c", "while True: pass"], 0.05, 1024)
        expect_failure(self, 5, s2.bounded_process,
                       ["/usr/bin/python3", "-I", "-S", "-c", "import sys;sys.stdout.write('x'*4096)"], 5, 100)

    def test_bounded_process_signal_and_valid(self):
        rc, out, err = s2.bounded_process(
            ["/usr/bin/python3", "-I", "-S", "-c", "print('APPROVED_EXACT')"], 5, 1024)
        self.assertEqual((rc, out, err), (0, b"APPROVED_EXACT\n", b""))
        rc, _out, _err = s2.bounded_process(
            ["/usr/bin/python3", "-I", "-S", "-c", "import os,signal;os.kill(os.getpid(),signal.SIGTERM)"], 5, 1024)
        self.assertLess(rc, 0)


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.repo = self.root / "repo"; self.run = self.root / "run"
        (self.repo / "config").mkdir(parents=True); self.run.mkdir(mode=0o700)
        self.manifest = {}
        for name in s2.STAGE1_FILES:
            path = self.repo.joinpath(*name.split("/")); path.parent.mkdir(parents=True, exist_ok=True)
            data = ("data:" + name + "\n").encode(); path.write_bytes(data); path.chmod(0o600)
            self.manifest[name] = s2.hashlib.sha256(data).hexdigest()
        self.runfd = os.open(self.run, os.O_RDONLY | os.O_DIRECTORY)

    def tearDown(self):
        os.close(self.runfd); self.temp.cleanup()

    def test_population_sealing_verification_cleanup(self):
        snap = s2.snapshot_stage1(str(self.repo), self.runfd, self.manifest, {"amass": ["wolt.com"]})
        self.assertEqual(stat.S_IMODE(os.fstat(snap["sfd"]).st_mode), 0o500)
        self.assertEqual(stat.S_IMODE(os.fstat(snap["cfd"]).st_mode), 0o500)
        self.assertEqual(stat.S_IMODE(os.stat(self.run / ".stage1-runtime/nullsec-wolt.sh").st_mode), 0o500)
        self.assertEqual(stat.S_IMODE(os.stat(self.run / ".stage1-runtime/classifier-input.txt").st_mode), 0o400)
        s2.cleanup_snapshot(self.runfd, snap)
        self.assertEqual(os.listdir(self.runfd), [])

    def test_repository_replacement_does_not_change_snapshot(self):
        snap = s2.snapshot_stage1(str(self.repo), self.runfd, self.manifest, {"amass": ["wolt.com"]})
        original = (self.run / ".stage1-runtime/nullsec-wolt.sh").read_bytes()
        (self.repo / "nullsec-wolt.sh").write_bytes(b"replacement")
        self.assertEqual((self.run / ".stage1-runtime/nullsec-wolt.sh").read_bytes(), original)
        s2.cleanup_snapshot(self.runfd, snap)

    def test_policy_replacement_does_not_change_snapshot(self):
        snap = s2.snapshot_stage1(str(self.repo), self.runfd, self.manifest, {"amass": []})
        target = self.run / ".stage1-runtime/config/wolt-policy.json"
        original = target.read_bytes(); (self.repo / "config/wolt-policy.json").write_bytes(b"replacement")
        self.assertEqual(target.read_bytes(), original); s2.cleanup_snapshot(self.runfd, snap)

    def test_source_digest_mismatch_prevents_snapshot(self):
        self.manifest["nullsec-wolt.sh"] = "0" * 64
        expect_failure(self, 2, s2.snapshot_stage1, str(self.repo), self.runfd, self.manifest, {"amass": []})

    def test_postseal_inventory_mode_digest_and_symlink(self):
        for mutation in ("extra", "mode", "digest", "symlink"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as td:
                repo = Path(td) / "repo"; run = Path(td) / "run"
                (repo / "config").mkdir(parents=True); run.mkdir(mode=0o700)
                manifest = {}
                for name in s2.STAGE1_FILES:
                    path = repo.joinpath(*name.split("/")); path.parent.mkdir(parents=True, exist_ok=True)
                    data = ("data:" + name + "\n").encode(); path.write_bytes(data); path.chmod(0o600)
                    manifest[name] = s2.hashlib.sha256(data).hexdigest()
                runfd = os.open(run, os.O_RDONLY | os.O_DIRECTORY)
                snap = s2.snapshot_stage1(str(repo), runfd, manifest, {"amass": []})
                os.fchmod(snap["sfd"], 0o700); base = run / ".stage1-runtime"
                if mutation == "extra": (base / "extra").write_text("x")
                elif mutation == "mode": (base / "classifier-input.txt").chmod(0o600)
                elif mutation == "digest":
                    (base / "nullsec-wolt.sh").chmod(0o700); (base / "nullsec-wolt.sh").write_text("x"); (base / "nullsec-wolt.sh").chmod(0o500)
                else:
                    (base / "classifier-input.txt").unlink(); (base / "classifier-input.txt").symlink_to("nullsec-wolt.sh")
                os.fchmod(snap["sfd"], 0o500)
                expect_failure(self, 2, s2.verify_snapshot, snap["sfd"], snap["cfd"], snap["digests"], 0)
                os.close(snap["cfd"]); os.close(snap["sfd"]); os.close(runfd)

    def test_cleanup_failure_is_publication_failure(self):
        snap = s2.snapshot_stage1(str(self.repo), self.runfd, self.manifest, {"amass": []})
        with mock.patch.object(s2.os, "unlink", side_effect=OSError()):
            expect_failure(self, 6, s2.cleanup_snapshot, self.runfd, snap)
        self.assertTrue((self.run / ".stage1-runtime").exists())


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.repo = Path(self.temp.name)
        (self.repo / "config").mkdir()
        self.digests = {}
        for name in s2.STAGE1_FILES:
            path = self.repo.joinpath(*name.split("/")); path.parent.mkdir(parents=True, exist_ok=True)
            data = (name + "\n").encode(); path.write_bytes(data); path.chmod(0o600)
            self.digests[name] = s2.hashlib.sha256(data).hexdigest()
        self.write_manifest()

    def tearDown(self): self.temp.cleanup()

    def write_manifest(self, value=None):
        value = value or {"schema_version": 1, "aggregate_algorithm": "named-sha256-v1", "stage1_files": self.digests}
        path = self.repo / "config/wolt-stage2a-integrity.json"
        path.write_text(json.dumps(value)); path.chmod(0o600)

    def test_valid_manifest(self): self.assertEqual(s2.load_integrity(str(self.repo)), self.digests)

    def test_manifest_malformed_duplicate_missing_extra(self):
        path = self.repo / "config/wolt-stage2a-integrity.json"
        cases = [b"{", b'{"schema_version":1,"schema_version":1}',
                 json.dumps({"schema_version": 1}).encode(),
                 json.dumps({"schema_version": 1, "aggregate_algorithm": "named-sha256-v1",
                             "stage1_files": self.digests, "extra": 1}).encode()]
        for data in cases:
            with self.subTest(data=data[:20]):
                path.write_bytes(data); path.chmod(0o600)
                expect_failure(self, 2, s2.load_integrity, str(self.repo))

    def test_each_stage1_digest_mismatch(self):
        for name in s2.STAGE1_FILES:
            with self.subTest(name=name):
                manifest = dict(self.digests); manifest[name] = "0" * 64
                self.write_manifest({"schema_version": 1, "aggregate_algorithm": "named-sha256-v1", "stage1_files": manifest})
                # Snapshot creation is the point that validates source bytes.
                with tempfile.TemporaryDirectory() as rd:
                    fd = os.open(rd, os.O_RDONLY | os.O_DIRECTORY)
                    expect_failure(self, 2, s2.snapshot_stage1, str(self.repo), fd, manifest, {"amass": []})
                    os.close(fd)

    def test_symlink_missing_and_modes(self):
        target = self.repo / "nullsec-wolt.sh"; real = self.repo / "wrapper-real"
        target.rename(real); target.symlink_to(real.name)
        with tempfile.TemporaryDirectory() as rd:
            fd = os.open(rd, os.O_RDONLY | os.O_DIRECTORY)
            expect_failure(self, 2, s2.snapshot_stage1, str(self.repo), fd, self.digests, {"amass": []}); os.close(fd)
        target.unlink(); real.rename(target)
        for mode in (0o620, 0o602):
            target.chmod(mode)
            with tempfile.TemporaryDirectory() as rd:
                fd = os.open(rd, os.O_RDONLY | os.O_DIRECTORY)
                expect_failure(self, 2, s2.snapshot_stage1, str(self.repo), fd, self.digests, {"amass": []}); os.close(fd)
        target.chmod(0o600); target.unlink()
        with tempfile.TemporaryDirectory() as rd:
            fd = os.open(rd, os.O_RDONLY | os.O_DIRECTORY)
            expect_failure(self, 2, s2.snapshot_stage1, str(self.repo), fd, self.digests, {"amass": []}); os.close(fd)

    def test_wrong_owner_boundary(self):
        st = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=os.getuid() + 1)
        expect_failure(self, 2, s2.validate_regular, st, 2, "OWNER")


class PublicationTests(unittest.TestCase):
    def outputs(self): return {name: b"" for name in s2.DATA_FILES}

    def test_rename_unavailable_cross_device_and_existing(self):
        expect_failure(self, 6, s2.rename_noreplace, 1, "a", "b", types.SimpleNamespace())
        for number in (errno.EXDEV, errno.EEXIST, errno.EIO):
            class Callable:
                restype = None
                def __call__(self, *_args): ctypes_set_errno(number); return -1
            with self.subTest(number=number):
                expect_failure(self, 6, s2.rename_noreplace, 1, "a", "b", types.SimpleNamespace(renameat2=Callable()))

    def test_each_write_fault_prevents_rename(self):
        run = {"fd": 10, "name": "INCOMPLETE-x", "id": "x"}
        for failure_index in range(10):
            calls = []
            def fake_create(_fd, name, _data, _mode):
                calls.append(name)
                if len(calls) - 1 == failure_index: s2.abort(6, "FAULT")
            inventory = [[], list(s2.DATA_FILES)]
            with self.subTest(index=failure_index), mock.patch.object(s2, "create_file", side_effect=fake_create), \
                 mock.patch.object(s2.os, "listdir", side_effect=inventory), \
                 mock.patch.object(s2.os, "fsync"), mock.patch.object(s2, "rename_noreplace") as rename:
                expect_failure(self, 6, s2.publish, 9, run, self.outputs(), {})
                rename.assert_not_called()

    def test_after_rename_root_fsync_failure_no_rollback(self):
        run = {"fd": 10, "name": "INCOMPLETE-x", "id": "x"}; mutation = []
        with mock.patch.object(s2, "create_file"), \
             mock.patch.object(s2.os, "listdir", side_effect=[[], list(s2.DATA_FILES)]), \
             mock.patch.object(s2, "rename_noreplace", side_effect=lambda *_: mutation.append("rename")), \
             mock.patch.object(s2.os, "fsync", side_effect=[None, OSError()]):
            expect_failure(self, 6, s2.publish, 9, run, self.outputs(), {})
        self.assertEqual(mutation, ["rename"])

    def test_create_file_open_write_and_fsync_faults(self):
        with mock.patch.object(s2.os, "open", side_effect=OSError()):
            expect_failure(self, 6, s2.create_file, 1, "x", b"x", 0o600)
        with mock.patch.object(s2.os, "open", return_value=4), mock.patch.object(s2.os, "write", side_effect=OSError()), mock.patch.object(s2.os, "close"):
            expect_failure(self, 6, s2.create_file, 1, "x", b"x", 0o600)
        with mock.patch.object(s2.os, "open", return_value=4), mock.patch.object(s2.os, "write", return_value=1), mock.patch.object(s2.os, "fsync", side_effect=OSError()), mock.patch.object(s2.os, "close"):
            expect_failure(self, 6, s2.create_file, 1, "x", b"x", 0o600)


def ctypes_set_errno(number):
    import ctypes
    ctypes.set_errno(number)


class MetadataTests(unittest.TestCase):
    def valid(self):
        return {"schema_version": 1, "run_id": "20260101T000000.000000000Z-0123456789abcdef",
                "started_at_utc": "x", "completed_at_utc": "x", "completion_state": "COMPLETE",
                "approved_source_ids": [], "per_source_status": {}, "per_source_record_counts": {},
                "classification_counts": {t: 0 for t in s2.TOKENS},
                "launcher_sha256": "0" * 64, "python_core_sha256": "0" * 64,
                "aggregate_program_sha256": "0" * 64, "stage1_policy_sha256": "0" * 64,
                "output_files": {n: {"byte_size": 0, "sha256": "0" * 64} for n in s2.DATA_FILES}}

    def test_exact_metadata_accepts(self):
        value = self.valid(); self.assertTrue(s2.metadata_schema(value, value["run_id"]))

    def test_self_and_complete_hashes_rejected(self):
        for name in ("run-metadata.json", "COMPLETE"):
            value = self.valid(); value["output_files"][name] = {"byte_size": 0, "sha256": "0" * 64}
            self.assertFalse(s2.metadata_schema(value, value["run_id"]))

    def test_missing_extra_and_completion_rejected(self):
        variants = []
        v = self.valid(); v["extra"] = 1; variants.append(v)
        v = self.valid(); del v["run_id"]; variants.append(v)
        v = self.valid(); v["completion_state"] = "INCOMPLETE"; variants.append(v)
        v = self.valid(); del v["output_files"][s2.DATA_FILES[0]]; variants.append(v)
        for value in variants: self.assertFalse(s2.metadata_schema(value, self.valid()["run_id"]))


class ConsumerTests(unittest.TestCase):
    def make_run(self, parent):
        run_id = "20260101T000000.000000000Z-0123456789abcdef"; run = Path(parent) / run_id; run.mkdir(mode=0o700)
        outputs = {name: (b"hostname\tclassification\tsource_id\n" if name == "provenance.tsv" else b"") for name in s2.DATA_FILES}
        for name, data in outputs.items(): (run / name).write_bytes(data); (run / name).chmod(0o600)
        meta = MetadataTests().valid(); meta["run_id"] = run_id
        meta["output_files"] = {n: {"byte_size": len(d), "sha256": s2.hashlib.sha256(d).hexdigest()} for n, d in outputs.items()}
        (run / "run-metadata.json").write_bytes(s2.json_bytes(meta)); (run / "run-metadata.json").chmod(0o600)
        (run / "COMPLETE").write_bytes(b""); (run / "COMPLETE").chmod(0o600)
        return run

    def test_accepts_one_valid_run(self):
        with tempfile.TemporaryDirectory() as td: s2.validate_run(str(self.make_run(td)))

    def test_rejects_inventory_marker_metadata_and_output_mutations(self):
        mutations = ("missing_complete", "nonzero_complete", "symlink_complete", "bad_metadata",
                     "extra_metadata", "wrong_state", "missing_output", "extra_file", "extra_dir",
                     "symlink_output", "size_mismatch", "digest_mismatch", "snapshot")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as td:
                run = self.make_run(td); meta_path = run / "run-metadata.json"
                if mutation == "missing_complete": (run / "COMPLETE").unlink()
                elif mutation == "nonzero_complete": (run / "COMPLETE").write_bytes(b"x")
                elif mutation == "symlink_complete": (run / "COMPLETE").unlink(); (run / "COMPLETE").symlink_to("approved-exact.txt")
                elif mutation == "bad_metadata": meta_path.write_bytes(b"{")
                elif mutation in ("extra_metadata", "wrong_state", "size_mismatch", "digest_mismatch"):
                    value = json.loads(meta_path.read_text())
                    if mutation == "extra_metadata": value["extra"] = 1
                    elif mutation == "wrong_state": value["completion_state"] = "INCOMPLETE"
                    elif mutation == "size_mismatch": value["output_files"][s2.DATA_FILES[0]]["byte_size"] = 1
                    else: value["output_files"][s2.DATA_FILES[0]]["sha256"] = "0" * 64
                    meta_path.write_bytes(s2.json_bytes(value))
                elif mutation == "missing_output": (run / s2.DATA_FILES[0]).unlink()
                elif mutation == "extra_file": (run / "extra").write_bytes(b"")
                elif mutation == "extra_dir": (run / "extra").mkdir()
                elif mutation == "symlink_output": (run / s2.DATA_FILES[0]).unlink(); (run / s2.DATA_FILES[0]).symlink_to(s2.DATA_FILES[1])
                else: (run / ".stage1-runtime").mkdir()
                expect_failure(self, 6, s2.validate_run, str(run))

    def test_incomplete_and_invalid_run_ids(self):
        for name in ("INCOMPLETE-20260101T000000.000000000Z-0123456789abcdef", "bad"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as td:
                path = Path(td) / name; path.mkdir(); expect_failure(self, 6, s2.validate_run, str(path))


if __name__ == "__main__":
    unittest.main(verbosity=2)
