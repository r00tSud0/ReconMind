"""
Offline tests for evaluation/scripts/prepare_run3_data.py on tiny fake
sources. Nothing is downloaded and every file lives in a temp folder:

    python3 -m unittest evaluation.tests.test_prepare_run3_data -v
"""

import builtins
import contextlib
import csv
import importlib.util
import io
import json
import os
import tempfile
import unittest
import urllib.error
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(os.path.dirname(HERE), "scripts", "prepare_run3_data.py")


def load_script():
    spec = importlib.util.spec_from_file_location("prepare_run3_data", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


p3 = load_script()


def tech(name, revoked=False, deprecated=False):
    return {"name": name, "revoked": revoked, "deprecated": deprecated}


TECHNIQUES = {
    "T1190": tech("Exploit Public-Facing Application"),
    "T1059": tech("Command and Scripting Interpreter"),
    "T1068": tech("Exploitation for Privilege Escalation"),
    "T1005": tech("Data from Local System"),
    "T1499.004": tech("Endpoint Denial of Service: Application or System Exploitation"),
    "T1001": tech("Data Obfuscation", revoked=True),
    "T1002": tech("Data Compressed", deprecated=True),
}

CVE_HEADER = ["CVE ID", "Primary Impact", "Secondary Impact",
              "Exploitation Technique", "Uncategorized", "Phase"]
EDB_HEADER = ["id", "file", "description", "date_published", "author", "type",
              "platform", "port", "date_added", "date_updated", "verified", "codes",
              "tags", "aliases", "screenshot_url", "application_url", "source_url"]


def csv_text(header, rows):
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(header)
    writer.writerows(rows)
    return out.getvalue()


def cve_csv(rows):
    """rows: (cve, primary, secondary, exploitation)"""
    return csv_text(CVE_HEADER, [[c, p, s, e, "", ""] for c, p, s, e in rows])


def edb_csv(rows):
    """rows: (id, description, codes)"""
    blank = [""] * len(EDB_HEADER)
    out = []
    for edb_id, desc, codes in rows:
        row = list(blank)
        row[0], row[2], row[11] = edb_id, desc, codes
        out.append(row)
    return csv_text(EDB_HEADER, out)


def pattern(stix_id, tid, **extra):
    return dict({"type": "attack-pattern", "id": stix_id, "external_references": [
        {"source_name": "mitre-attack", "external_id": tid}]}, **extra)


def uses(rel_id, target, description, **extra):
    return dict({"type": "relationship", "id": rel_id, "relationship_type": "uses",
                 "source_ref": "intrusion-set--x", "target_ref": target,
                 "description": description}, **extra)


def kev_obj(cve, mapping_type, tid, desc="", comments=""):
    return {"capability_id": cve, "mapping_type": mapping_type, "attack_object_id": tid,
            "capability_description": desc, "comments": comments}


def tram_row(row_id, sentence, labels, doc):
    return {"id": row_id, "sentence": sentence, "labels": labels, "doc_title": doc}


def base_inputs():
    bundle = {"type": "bundle", "objects": [
        pattern("attack-pattern--a", "T1190"),
        pattern("attack-pattern--b", "T1059"),
        uses("relationship--1", "attack-pattern--a",
             "APT1 exploited [Struts](https://example.com/s) servers.(Citation: Report 2020)"),
        uses("relationship--2", "attack-pattern--b", "APT1 ran commands."),
    ]}
    kev = {"mapping_objects": [
        kev_obj("CVE-2020-0001", "exploitation_technique", "T1190",
                "Struts lets attackers run code.", "Exploited in the wild."),
        kev_obj("CVE-2020-0001", "secondary_impact", "T1005",
                "Struts lets attackers run code.", "Exploited in the wild."),
    ]}
    cve_map = p3.cve_csv_labels(cve_csv([
        ("CVE-2020-0001", "T1059", "", ""),
        ("CVE-2020-0002", "", "T1005", "T1068"),
    ]))
    cve_texts = {"CVE-2020-0001": "Struts before 2.3 allows remote code execution.",
                 "CVE-2020-0002": "A kernel bug lets local users gain root."}
    edb = p3.exploitdb_entries(edb_csv([
        ("100", "Struts 2.3 - Remote Code Execution", "CVE-2020-0001"),
        ("200", "Linux Kernel 2.6 - Local Root", "CVE-2020-0002;OSVDB-1"),
        ("300", "Some Tool 1.0 - Denial of Service", ""),
    ]))
    tram = {"train": [tram_row("tram-00001", "Adversary used PowerShell.", ["T1059"], "doc a"),
                      tram_row("tram-00002", "Nothing here.", [], "doc a")],
            "val": [tram_row("tram-00003", "They exploited a web server.", ["T1190"], "doc b")]}
    return dict(attack_bundle=bundle, kev_data=kev, cve_map=cve_map, cve_texts=cve_texts,
                edb_entries=edb, tram_splits=tram, holdout=set(), exam_edb_ids=set(),
                exam_titles=set(), techniques=TECHNIQUES, min_rows=1)


def all_rows(result):
    return result["splits"]["train"] + result["splits"]["val"]


class CleanTextTests(unittest.TestCase):

    def test_citations_links_and_whitespace(self):
        text = ("APT1 used [PsExec](https://attack.mitre.org/software/S0029) to move "
                "(Citation: Foo (2019)) laterally.(Citation: A)(Citation: B)\n  Done.")
        self.assertEqual(p3.clean_text(text), "APT1 used PsExec to move laterally. Done.")

    def test_no_space_left_before_full_stop_and_dotted_words_kept(self):
        self.assertEqual(p3.clean_text("It ran .NET code (Citation: X)."),
                         "It ran .NET code.")

    def test_link_with_parentheses_in_url(self):
        self.assertEqual(p3.clean_text("see [Wiki](https://w.org/a_(b)) now"), "see Wiki now")

    def test_attack_rows_skip_revoked_deprecated_and_non_uses(self):
        bundle = {"objects": [
            pattern("attack-pattern--a", "T1190"),
            pattern("attack-pattern--old", "T1068", revoked=True),
            pattern("attack-pattern--dep", "T1005", x_mitre_deprecated=True),
            uses("relationship--1", "attack-pattern--a", "Kept [X](http://x) (Citation: C)."),
            uses("relationship--2", "attack-pattern--a", "Revoked.", revoked=True),
            uses("relationship--3", "attack-pattern--a", "Deprecated.", x_mitre_deprecated=True),
            uses("relationship--4", "attack-pattern--old", "Target revoked."),
            uses("relationship--5", "attack-pattern--dep", "Target deprecated."),
            uses("relationship--6", "attack-pattern--a", ""),
            dict(uses("relationship--7", "attack-pattern--a", "Mitigates."),
                 relationship_type="mitigates"),
        ]}
        rows = p3.attack_rows(bundle)
        self.assertEqual([(r["sentence"], r["labels"], r["group"]) for r in rows],
                         [("Kept X.", ["T1190"], "relationship--1")])


class CtidTests(unittest.TestCase):

    def test_kev_labels_use_only_exploitation_and_primary_impact(self):
        data = {"mapping_objects": [
            kev_obj("CVE-2021-1234", "exploitation_technique", "T1190", "Desc.", "Note."),
            kev_obj("CVE-2021-1234", "primary_impact", "T1059", "Desc.", "Note."),
            kev_obj("CVE-2021-1234", "secondary_impact", "T1005", "Desc.", "Note."),
            kev_obj("CVE-2021-1234", "uncategorized", "T1068", "Desc.", "Note."),
            kev_obj("CVE-2021-1234", "non_mappable", None, "Desc.", ""),
        ]}
        entry = p3.kev_entries(data)["CVE-2021-1234"]
        self.assertEqual(entry["labels"], {"T1190", "T1059"})
        self.assertEqual(entry["descriptions"], ["Desc."])
        self.assertEqual(entry["comments"], ["Note."])

    def test_cve_csv_uses_only_exploitation_and_primary_columns(self):
        labels = p3.cve_csv_labels(cve_csv([("CVE-2020-0002", "T1059; T1005", "T1068", "T1190")]))
        self.assertEqual(labels, {"CVE-2020-0002": {"T1059", "T1005", "T1190"}})

    def test_cve_csv_missing_column_is_an_error(self):
        with self.assertRaisesRegex(p3.DataError, "its header is CVE, Impact"):
            p3.cve_csv_labels("CVE,Impact\nCVE-2020-0001,T1190\n")

    def test_cve_csv_with_byte_order_mark(self):
        raw = b"\xef\xbb\xbf" + cve_csv([("CVE-2020-0001", "T1059", "", "T1190")]).encode("utf-8")
        expected = {"CVE-2020-0001": {"T1059", "T1190"}}
        self.assertEqual(p3.cve_csv_labels(raw), expected)
        self.assertEqual(p3.cve_csv_labels(raw.decode("utf-8")), expected)  # str keeps the mark

    def test_kev_object_missing_a_key_is_an_error(self):
        obj = kev_obj("CVE-2021-1", "primary_impact", "T1190")
        del obj["mapping_type"]
        with self.assertRaisesRegex(p3.DataError, "object 1 lacks keys mapping_type"):
            p3.kev_entries({"metadata": {}, "mapping_objects": [obj]})

    def test_kev_comments_may_be_missing_none_or_empty(self):
        no_key = kev_obj("CVE-2021-2000", "exploitation_technique", "T1190", "Desc A.")
        del no_key["comments"]
        data = {"mapping_objects": [
            no_key,
            kev_obj("CVE-2021-2000", "primary_impact", "T1059", "Desc A.", None),
            kev_obj("CVE-2021-2000", "secondary_impact", "T1005", "Desc B.", ""),
            kev_obj("CVE-2021-2000", "uncategorized", "T1068", "Desc A.", "Real note."),
        ]}
        entry = p3.kev_entries(data)["CVE-2021-2000"]
        self.assertEqual(entry["labels"], {"T1190", "T1059"})
        self.assertEqual(entry["descriptions"], ["Desc A.", "Desc B."])
        self.assertEqual(entry["comments"], ["Real note."])

    def test_kev_object_missing_a_required_key_other_than_comments_is_an_error(self):
        for key in ("capability_id", "capability_description", "mapping_type",
                    "attack_object_id"):
            obj = kev_obj("CVE-2021-1", "primary_impact", "T1190")
            del obj["comments"], obj[key]
            with self.subTest(key=key), self.assertRaisesRegex(
                    p3.DataError, "object 1 lacks keys " + key + ";"):
                p3.kev_entries({"mapping_objects": [obj]})

    def test_kev_without_mapping_objects_is_an_error(self):
        with self.assertRaisesRegex(p3.DataError, "mapping_objects"):
            p3.kev_entries({"metadata": {}})

    def test_kev_and_cve_labels_merge_per_cve(self):
        result = p3.build(**base_inputs())
        rows = [r for r in all_rows(result) if r["group"] == "CVE-2020-0001"]
        self.assertEqual(sorted(r["source"] for r in rows),
                         ["ctid_cve", "ctid_kev", "ctid_kev", "exploitdb"])
        for row in rows:
            self.assertEqual(row["labels"], ["T1059", "T1190"])  # never T1005 (secondary)
        kev_sentences = {r["sentence"] for r in rows if r["source"] == "ctid_kev"}
        self.assertEqual(kev_sentences, {"Struts lets attackers run code.", "Exploited in the wild."})


class ExploitDbTests(unittest.TestCase):

    def test_sentence_format_and_cve_join(self):
        entries = p3.exploitdb_entries(edb_csv([
            ("100", "Struts 2.3 - Remote Code Execution", "CVE-2020-0001"),
            ("400", "Two Bugs - Combo", "CVE-2020-10000;CVE-2020-9999;OSVDB-5"),
            ("500", "Unmapped - Thing", "CVE-2019-1234"),
            ("600", "No Code - Thing", ""),
        ]))
        cve_labels = {"CVE-2020-0001": ["T1190"], "CVE-2020-9999": ["T1059"],
                      "CVE-2020-10000": ["T1068"]}
        rows = {r["_edb"]: r for r in p3.exploitdb_rows(entries, cve_labels)}
        self.assertEqual(sorted(rows), ["100", "400"])
        self.assertEqual(rows["100"]["sentence"],
                         "Known exploits (Exploit-DB): Struts 2.3 - Remote Code Execution (EDB-100).")
        self.assertEqual(rows["100"]["labels"], ["T1190"])
        self.assertEqual(rows["400"]["labels"], ["T1059", "T1068"])
        self.assertEqual(rows["400"]["group"], "CVE-2020-9999")  # numeric CVE order

    def test_missing_column_reports_the_header(self):
        with self.assertRaisesRegex(p3.DataError,
                                    "lacks columns codes; its header is id, file, description"):
            p3.exploitdb_entries("id,file,description\n1,a,b\n")

    def test_byte_order_mark_does_not_hide_the_id_column(self):
        raw = b"\xef\xbb\xbf" + edb_csv([("100", "Struts - RCE", "CVE-2020-0001")]).encode("utf-8")
        self.assertEqual(p3.exploitdb_entries(raw)[0]["edb_id"], "100")

    def test_exam_exploits_reads_ids_and_titles(self):
        findings = [{"text": "Port 21/tcp is open running ftp: vsftpd 2.3.4. Risk: a; b. "
                             "Known exploits (Exploit-DB): vsftpd 2.3.4 - Backdoor (Metasploit) "
                             "(EDB-17491); vsftpd 2.3.4 - Backdoor (EDB-49757)."},
                    {"text": "Port 80/tcp is open running http."}]
        ids, titles = p3.exam_exploits(findings)
        self.assertEqual(ids, {"17491", "49757"})
        self.assertEqual(titles, {"vsftpd 2.3.4 - backdoor (metasploit)", "vsftpd 2.3.4 - backdoor"})


class LabelCleanupTests(unittest.TestCase):

    def test_unknown_revoked_and_deprecated_ids_are_dropped_and_counted(self):
        inputs = base_inputs()
        inputs["attack_bundle"]["objects"] += [
            pattern("attack-pattern--dep", "T1002"),
            pattern("attack-pattern--unk", "T9999"),
            uses("relationship--8", "attack-pattern--dep", "Compressed the data."),
            uses("relationship--9", "attack-pattern--unk", "Did something new."),
        ]
        inputs["kev_data"]["mapping_objects"].append(
            kev_obj("CVE-2020-0001", "primary_impact", "T1001"))
        inputs["cve_map"]["CVE-2020-0002"].add("T9998")
        inputs["tram_splits"]["train"].append(
            tram_row("tram-00009", "Obfuscated it.", ["T1001", "T1059"], "doc c"))
        result = p3.build(**inputs)
        dropped = result["report"]["dropped_labels"]
        self.assertEqual(dropped["attack"]["deprecated"], {"T1002": 1})
        self.assertEqual(dropped["attack"]["unknown"], {"T9999": 1})
        self.assertEqual(dropped["attack"]["total"], 2)
        self.assertEqual(dropped["ctid_kev"]["revoked"], {"T1001": 1})
        self.assertEqual(dropped["ctid_cve"]["unknown"], {"T9998": 1})
        self.assertEqual(dropped["tram"]["revoked"], {"T1001": 1})
        self.assertEqual(result["report"]["rows_without_valid_labels"]["attack"], 2)
        used = {lab for r in all_rows(result) for lab in r["labels"]}
        self.assertFalse(used & {"T1001", "T1002", "T9998", "T9999"})
        tram9 = [r for r in all_rows(result) if r["id"] == "tram-00009"]
        self.assertEqual(tram9[0]["labels"], ["T1059"])


class LeakageTests(unittest.TestCase):

    def test_rule1_removes_exam_edb_ids_and_their_cves_from_every_source(self):
        inputs = base_inputs()
        inputs["attack_bundle"]["objects"].append(
            uses("relationship--10", "attack-pattern--a", "APT1 used CVE-2020-0001 on servers."))
        inputs["tram_splits"]["train"].append(
            tram_row("tram-00010", "The actor exploited cve-2020-0001.", ["T1190"], "doc d"))
        inputs["edb_entries"] += p3.exploitdb_entries(edb_csv([
            ("700", "Struts 2.3 - Other Exploit", "CVE-2020-0001")]))
        inputs["exam_edb_ids"] = {"100"}
        result = p3.build(**inputs)
        rows = all_rows(result)
        for row in rows:
            self.assertNotEqual(row["group"], "CVE-2020-0001")
            self.assertNotIn("CVE-2020-0001", row["sentence"].upper())
            self.assertNotIn("EDB-100", row["sentence"])
            self.assertNotIn("EDB-700", row["sentence"])
        self.assertTrue(any(r["group"] == "CVE-2020-0002" for r in rows))
        leak = result["report"]["leakage"]
        self.assertEqual(leak["exam_edb_ids"], ["100"])
        self.assertEqual(leak["exam_cves"], ["CVE-2020-0001"])
        self.assertEqual(leak["rule1_rows_dropped"],
                         {"attack": 1, "ctid_kev": 2, "ctid_cve": 1, "exploitdb": 2, "tram": 1})

    def test_exam_title_under_another_edb_id_is_dropped(self):
        inputs = base_inputs()
        inputs["exam_titles"] = {p3.normalize("Linux Kernel 2.6 -  Local Root")}
        result = p3.build(**inputs)
        sources = [r["source"] for r in all_rows(result) if r["group"] == "CVE-2020-0002"]
        self.assertEqual(sources, ["ctid_cve"])
        self.assertEqual(result["report"]["leakage"]["exam_title_rows_dropped"], 1)

    def test_rule2_removes_tram_test_or_eval_duplicates(self):
        inputs = base_inputs()
        test_rows = [{"sentence": "APT1   RAN commands."}]
        eval_rows = [{"sentence": "a kernel bug lets local users gain ROOT."},
                     {"sentence": "Adversary used PowerShell."}]
        inputs["holdout"] = p3.holdout_sentences(test_rows, eval_rows)
        result = p3.build(**inputs)
        sentences = [r["sentence"] for r in all_rows(result)]
        self.assertNotIn("APT1 ran commands.", sentences)
        self.assertNotIn("A kernel bug lets local users gain root.", sentences)
        self.assertIn("Adversary used PowerShell.", sentences)  # TRAM rows are kept as they are
        self.assertEqual(result["report"]["leakage"]["rule2_rows_dropped"],
                         {"attack": 1, "ctid_kev": 0, "ctid_cve": 1, "exploitdb": 0})


class SplitTests(unittest.TestCase):

    def many_inputs(self):
        inputs = base_inputs()
        objs = inputs["kev_data"]["mapping_objects"]
        for n in range(10, 50):
            objs.append(kev_obj("CVE-2022-{n:04d}".format(n=n), "exploitation_technique",
                                "T1190", "Bug {n}.".format(n=n), "Note {n}.".format(n=n)))
        return inputs

    def test_groups_stay_on_one_side_and_split_is_deterministic(self):
        first = p3.build(**self.many_inputs())
        second = p3.build(**self.many_inputs())
        self.assertEqual(first, second)
        groups = {name: {r["group"] for r in first["splits"][name] if r["source"] != "tram"}
                  for name in ("train", "val")}
        self.assertFalse(groups["train"] & groups["val"])
        self.assertTrue(groups["val"])
        self.assertEqual({r["id"] for r in first["splits"]["val"] if r["source"] == "tram"},
                         {"tram-00003"})

    def test_val_rows_repeating_a_train_sentence_are_dropped(self):
        inputs = self.many_inputs()
        objs = inputs["attack_bundle"]["objects"]
        # 200 groups share one sentence (case and spacing vary), so some land in each split.
        for n in range(200):
            text = "Shared   sentence." if n % 2 else "SHARED sentence."
            objs.append(uses("relationship--s{n:03d}".format(n=n), "attack-pattern--a", text))
        inputs["tram_splits"]["val"].append(
            tram_row("tram-00004", "shared sentence.", ["T1190"], "doc b"))
        result = p3.build(**inputs)
        train = {p3.normalize(r["sentence"]) for r in result["splits"]["train"]}
        self.assertIn("shared sentence.", train)
        for row in result["splits"]["val"]:
            if row["source"] != "tram":
                self.assertNotIn(p3.normalize(row["sentence"]), train)
        self.assertIn("tram-00004", {r["id"] for r in result["splits"]["val"]})  # TRAM kept
        dropped = result["report"]["cross_split_rows_dropped"]
        self.assertGreaterEqual(dropped["attack"], 1)
        self.assertEqual(set(dropped), {"attack", "ctid_kev", "ctid_cve", "exploitdb"})

    def test_split_groups_fraction_and_seed(self):
        groups = ["g{n}".format(n=n) for n in range(20)]
        train, val = p3.split_groups(groups, seed=9)
        self.assertEqual((len(train), len(val)), (18, 2))
        self.assertEqual(p3.split_groups(list(reversed(groups)), seed=9), (train, val))
        self.assertTrue(any(p3.split_groups(groups, seed=s) != (train, val)
                            for s in range(10, 15)))


class LabelSetTests(unittest.TestCase):

    def test_minimum_train_count_after_dedupe(self):
        def row(n, labels, source="attack"):
            return {"id": str(n), "sentence": "s{n}".format(n=n), "labels": labels,
                    "source": source, "group": "g"}
        train = [row(n, ["T1190"]) for n in range(5)]
        train += [row(n, ["T1059"]) for n in (10, 11)]
        train += [dict(row(11, ["T1059"]), id="dup")]  # exact duplicate, counts once
        train += [row(20, ["T1059"], "tram"), row(21, ["T1059", "T1190"], "exploitdb")]
        # T1059 has 5 train rows before dedupe and 4 after, so it is left out.
        val = [row(30, ["T1059"]), row(31, ["T1190"])]
        splits, labels, first, stats = p3.apply_label_set({"train": train, "val": val}, 5)
        self.assertEqual(labels, ["T1190"])
        self.assertEqual(first["T1059"], 4)
        self.assertEqual(first["T1190"], 6)
        self.assertEqual(stats["duplicates_removed"]["train"], 1)
        kept = {r["id"]: r["labels"] for r in splits["train"]}
        self.assertEqual(kept["20"], [])  # TRAM row kept with no labels
        self.assertEqual(kept["21"], ["T1190"])
        self.assertNotIn("10", kept)
        self.assertEqual([r["id"] for r in splits["val"]], ["31"])
        self.assertEqual(stats["dropped_no_label_in_set"]["train"]["attack"], 2)
        self.assertEqual(stats["dropped_no_label_in_set"]["val"]["attack"], 1)

    def test_pruning_that_creates_duplicates_is_rechecked(self):
        rows = [{"id": str(n), "sentence": "same", "labels": ["T1190", "T1059"][:1 + n % 2],
                 "source": "attack", "group": "g"} for n in range(2)]
        rows += [{"id": "x{n}".format(n=n), "sentence": "t{n}".format(n=n), "labels": ["T1190"],
                  "source": "attack", "group": "g"} for n in range(4)]
        # Before pruning T1190 has 6 rows; once T1059 goes, rows 0 and 1 merge to 5.
        splits, labels, _, _ = p3.apply_label_set({"train": rows, "val": []}, 6)
        self.assertEqual(labels, [])
        self.assertEqual(splits["train"], [])


class CveFetchTests(unittest.TestCase):

    def test_unfetchable_cve_is_skipped_and_counted(self):
        good = {"containers": {"cna": {"descriptions": [
            {"lang": "es", "value": "Hola."}, {"lang": "en-US", "value": "  A remote  bug. "}]}}}
        no_english = {"containers": {"cna": {"descriptions": [{"lang": "fr", "value": "Non."}]}}}
        calls = []

        def fetch(url):
            calls.append(url)
            if url.endswith("CVE-2020-0002.json"):
                raise urllib.error.HTTPError(url, 404, "Not Found", None, None)
            if url.endswith("CVE-2021-44228.json"):
                return b"not json"
            body = no_english if url.endswith("CVE-2020-0003.json") else good
            return json.dumps(body).encode("utf-8")

        cves = ["CVE-2020-0003", "CVE-2020-0001", "CVE-2020-0002", "CVE-2021-44228"]
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            texts, skipped = p3.fetch_cve_texts(cves, tmp, fetch)
            self.assertEqual(texts, {"CVE-2020-0001": "A remote bug."})
            self.assertEqual(sorted(skipped), ["CVE-2020-0002", "CVE-2020-0003", "CVE-2021-44228"])
            self.assertEqual(skipped["CVE-2020-0003"], "no English description")
            self.assertTrue(os.path.exists(os.path.join(tmp, "CVE-2020-0001.json")))
            self.assertFalse(os.path.exists(os.path.join(tmp, "CVE-2020-0002.json")))
            self.assertFalse(os.path.exists(os.path.join(tmp, "CVE-2021-44228.json")))

            def offline(url):
                raise urllib.error.URLError("offline")
            texts2, _ = p3.fetch_cve_texts(["CVE-2020-0001"], tmp, offline)
            self.assertEqual(texts2, texts)  # served from the cache
        self.assertTrue(calls[0].endswith("/cves/2020/0xxx/CVE-2020-0001.json"))
        self.assertIn(p3.CVELIST_COMMIT, calls[0])
        self.assertTrue(p3.cvelist_url("CVE-2021-44228").endswith(
            "/cves/2021/44xxx/CVE-2021-44228.json"))


class MainTests(unittest.TestCase):

    def test_script_never_names_the_answer_key_file(self):
        with open(SCRIPT) as fh:
            self.assertNotIn("labels.jsonl", fh.read())

    def run_main(self, tmp, edb_text):
        """Write every fake input in tmp, run main on it and say what happened."""
        inputs = base_inputs()
        bundle = json.dumps(inputs["attack_bundle"]).encode("utf-8")
        kev = json.dumps(inputs["kev_data"]).encode("utf-8")
        cves = cve_csv([("CVE-2020-0001", "T1059", "", ""),
                        ("CVE-2020-0002", "", "T1005", "T1068"),
                        ("CVE-2020-0404", "T1190", "", "")]).encode("utf-8")
        record = {"containers": {"cna": {"descriptions": [{"lang": "en", "value": "Bug."}]}}}
        served = {"https://fake/attack.json": bundle, "https://fake/kev.json": kev,
                  "https://fake/cve.csv": cves}

        def fetch(url, timeout=120):
            if url in served:
                return served[url]
            if url.endswith("CVE-2020-0404.json"):
                raise urllib.error.HTTPError(url, 404, "Not Found", None, None)
            return json.dumps(record).encode("utf-8")

        pinned = tuple({"source": s, "url": u, "commit": "c" + s, "sha256": p3.sha256_hex(served[u]),
                        "cache": s + ".cache"}
                       for s, u in (("attack", "https://fake/attack.json"),
                                    ("ctid_kev", "https://fake/kev.json"),
                                    ("ctid_cve", "https://fake/cve.csv")))
        real_open = builtins.open
        opened = []

        def recording_open(path, *args, **kwargs):
            opened.append(str(path))
            return real_open(path, *args, **kwargs)

        def put(rel, text):
            path = os.path.join(tmp, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with real_open(path, "w") as fh:
                fh.write(text)
            return path

        def jsonl(rows):
            return "".join(json.dumps(r) + "\n" for r in rows)

        attack_path = put("attack_techniques.json", json.dumps({"techniques": TECHNIQUES}))
        put("tram/train.jsonl", jsonl(inputs["tram_splits"]["train"]))
        put("tram/val.jsonl", jsonl(inputs["tram_splits"]["val"]))
        put("tram/test.jsonl", jsonl([tram_row("t1", "APT1 ran commands.", [], "x")]))
        put("tram/eval.jsonl", jsonl([tram_row("t1", "APT1 ran commands.", [], "x")]))
        findings = put("exam/findings.jsonl", jsonl([{"id": "f", "text":
            "Port 1/tcp is open running x. Known exploits (Exploit-DB): Linux Kernel 2.6 - "
            "Local Root (EDB-200)."}]))
        put("exam/labels.jsonl", "this file must never be opened\n")
        edb = put("files_exploits.csv", edb_text)
        out_dir = os.path.join(tmp, "run3")
        copy_path = os.path.join(tmp, "results", "run3_data_manifest.json")
        stdout = io.StringIO()
        with mock.patch.multiple(p3, PINNED=pinned, OUT_DIR=out_dir,
                                 CACHE_DIR=os.path.join(out_dir, "cache"),
                                 CVE_CACHE_DIR=os.path.join(out_dir, "cache", "cve"),
                                 RESULTS_COPY_PATH=copy_path, ATTACK_PATH=attack_path,
                                 TRAM_DIR=os.path.join(tmp, "tram"), FINDINGS_PATH=findings,
                                 MIN_TRAIN_ROWS=1, _http_get=fetch), \
                mock.patch("builtins.open", recording_open), \
                contextlib.redirect_stdout(stdout):
            code = p3.main(["--exploitdb-csv", edb])
        return {"code": code, "printed": stdout.getvalue(), "out_dir": out_dir,
                "copy_path": copy_path, "opened": opened, "pinned": pinned}

    def test_exploitdb_csv_without_needed_columns_stops_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = self.run_main(tmp, "id,file,description\n100,x,Struts 2.3 - RCE\n")
            self.assertEqual(run["code"], 1, run["printed"])
            self.assertIn("lacks columns codes; its header is id, file, description",
                          run["printed"])
            for name in ("train.jsonl", "val.jsonl", "labels.json", "manifest.json"):
                self.assertFalse(os.path.exists(os.path.join(run["out_dir"], name)))
            self.assertFalse(os.path.exists(run["copy_path"]))

    def test_end_to_end_in_temp_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = self.run_main(tmp, edb_csv([
                ("100", "Struts 2.3 - Remote Code Execution", "CVE-2020-0001"),
                ("200", "Linux Kernel 2.6 - Local Root", "CVE-2020-0002")]))
            self.assertEqual(run["code"], 0, run["printed"])
            out_dir = run["out_dir"]
            with open(os.path.join(out_dir, "manifest.json")) as fh:
                manifest = json.load(fh)
            with open(run["copy_path"]) as fh:
                self.assertEqual(json.load(fh), manifest)
            with open(os.path.join(out_dir, "labels.json")) as fh:
                table = json.load(fh)
            rows = []
            for name in ("train", "val"):
                with open(os.path.join(out_dir, name + ".jsonl")) as fh:
                    rows += [json.loads(line) for line in fh]

        pinned, printed = run["pinned"], run["printed"]
        self.assertFalse([p for p in run["opened"] if p.endswith("labels.jsonl")])
        self.assertEqual([t["id"] for t in table], sorted(t["id"] for t in table))
        self.assertEqual(len(table), manifest["label_set_size"])
        for row in rows:
            self.assertEqual(set(row), {"id", "sentence", "labels", "source", "group"})
            self.assertNotEqual(row["group"], "CVE-2020-0002")
        self.assertEqual(manifest["leakage"]["exam_edb_ids"], ["200"])
        self.assertEqual(manifest["leakage"]["exam_cves"], ["CVE-2020-0002"])
        self.assertEqual(manifest["leakage"]["rule2_rows_dropped"]["attack"], 1)
        self.assertEqual(manifest["cvelist"]["skipped"], 1)
        self.assertIn("CVE-2020-0404", manifest["cvelist"]["skipped_cves"])
        self.assertEqual(manifest["exploitdb_csv"]["file"], "files_exploits.csv")
        self.assertEqual(len(manifest["exam_techniques"]), 16)
        self.assertEqual(manifest["sources"]["attack"]["sha256"], pinned[0]["sha256"])
        self.assertEqual(set(manifest["cross_split_rows_dropped"]),
                         {"attack", "ctid_kev", "ctid_cve", "exploitdb"})
        self.assertIn("cross split:", printed)
        self.assertIn("UNDER 1", printed)  # answer key IDs with no rows are flagged
        self.assertNotIn(chr(0x2014), printed)  # em dash
        self.assertNotIn(chr(0x2013), printed)  # en dash
        self.assertNotIn(" -- ", printed)
        self.assertNotIn("---", printed)


if __name__ == "__main__":
    unittest.main()
