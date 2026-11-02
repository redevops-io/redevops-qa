# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Mutation tests: removing a guard makes the suite fail. Each case names the guard, the source it lives in, and the tests that must catch its
removal; the same tests must pass on an unmodified copy."""
import re

import pytest

from qe_mutation import baseline_result, mutant_result

TAMPER = "test_qe_tamper.py::test_the_tamper_row_is_detected"


def row(name):
    return f"{TAMPER}[{name}]"


def t(file, name):
    return f"{file}::{name}"


CASES = [
    # ---- verify.py -------------------------------------------------------------------------------------------------------------------
    ("file digest comparison", "verify.py", 'elif "sha256:" + h.hexdigest() != entry["digest"]:', "elif False:", [row("altered artifact")]),
    ("size comparison before and while hashing", "verify.py",
     ('if safe[path] != entry["size"]:', 'if read != entry["size"]:'), ("if False:", "if False:"), [row("report swapped from another run")]),
    ("missing file", "verify.py", "if path not in everything:", "if False:", [row("deleted artifact")]),
    ("extra file", "verify.py", "if path not in listed and path not in RESERVED_UNLISTED:", "if False:", [row("extra file")]),
    ("canonical bytes of the manifest and the report", "verify.py", "if canonical != data:", "if False:", [row("manifest bytes not canonical")]),
    ("integrity statement must be present", "verify.py", 'if man["integrity"]["statement"] != INTEGRITY_STATEMENT:', "if False:", [row("integrity statement replaced")]),
    ("anchor block statement must be present", "verify.py", 'if man["anchor"]["statement"] != ANCHOR_BLOCK_STATEMENT:', "if False:",
     [t("test_qe_tamper.py", "test_the_anchor_block_statement_cannot_be_changed")]),
    ("manifest file order", "verify.py", "if previous is not None and path < previous:", "if False:", [t("test_qe_tamper.py", "test_a_manifest_with_files_out_of_order_is_refused")]),
    ("duplicate manifest entries", "verify.py", "if path in listed:", "if False:", [row("file listed twice")]),
    ("case collision in the manifest", "verify.py", "if key in folds and folds[key] != path:", "if False:",
     [t("test_qe_tamper.py", "test_case_colliding_names_in_the_manifest_are_refused")]),
    ("manifest cannot list itself or the anchor", "verify.py", 'if path in RESERVED_UNLISTED:\n            _add(findings, "RESERVED_LISTED"', 'if False:\n            _add(findings, "RESERVED_LISTED"',
     [t("test_qe_tamper.py", "test_a_manifest_that_lists_the_manifest_or_the_anchor_is_refused")]),
    ("declared size cap", "verify.py", 'if f["size"] > limits.max_file_bytes:', "if False:", [t("test_qe_tamper.py", "test_an_oversize_entry_is_refused_by_the_size_the_manifest_declares")]),
    ("actual size cap", "verify.py", "if entry.size > limits.max_file_bytes:", "if False:", [t("test_qe_tamper.py", "test_an_oversize_entry_is_refused_by_its_actual_size")]),
    ("actual total cap", "verify.py", 'if total > limits.max_total_bytes:\n        _add(findings, "OVERSIZE_BUNDLE", "",', 'if False:\n        _add(findings, "OVERSIZE_BUNDLE", "",',
     [t("test_qe_tamper.py", "test_an_oversize_bundle_and_too_many_files_are_refused")]),
    ("declared total cap", "verify.py", 'if total > limits.max_total_bytes:\n        _add(findings, "OVERSIZE_BUNDLE", file_name,', 'if False:\n        _add(findings, "OVERSIZE_BUNDLE", file_name,',
     [t("test_qe_tamper.py", "test_an_oversize_bundle_and_too_many_files_are_refused")]),
    ("file count cap in the manifest", "verify.py", 'if len(man["files"]) > limits.max_files:', "if False:", [t("test_qe_tamper.py", "test_an_oversize_bundle_and_too_many_files_are_refused")]),
    ("exactly one report entry", "verify.py", 'if len(reports) != 1 or reports[0]["path"] != man["report_path"]:', "if False:", [row("report entry has another role")]),
    ("format document must be listed", "verify.py", 'if doc is None or doc["role"] != "documentation":', "if False:", [row("format document not listed")]),
    ("format document content", "verify.py", "if source.read_all(FORMAT_DOC_NAME, limits.max_json_bytes) != FORMAT_DOC.encode(\"utf-8\"):", "if False:", [row("format document edited")]),
    ("duplicate lane id in the manifest", "verify.py", 'if lane_ids.count(x["lane_id"]) > 1:', "if False:", [row("duplicated lane id (manifest)")]),
    ("manifest and report name the same run", "verify.py", 'if man["run_id"] != rep["run_id"]:', "if False:", [row("manifest names another run")]),
    ("manifest and report agree on lanes", "verify.py", "if mlanes != rlanes:", "if False:", [row("manifest and report disagree about an engine version")]),
    ("manifest and report agree on the environment", "verify.py", 'if man["environment"].get(key) != rep["environment"].get(key):', "if False:",
     [row("environment differs between manifest and report")]),
    ("manifest and report agree on the assertion digest", "verify.py", 'if sorted(man["assertion_set_digests"]) != [rep["assertion_set"]["digest"]]:', "if False:",
     [row("changed assertion digest in the manifest")]),
    ("native artifacts are in the manifest with the same digest", "verify.py", 'if entry is None or entry["digest"] != art["digest"] or entry["size"] != art["size"]:', "if False:",
     [row("native artifact digest differs in the report")]),
    ("native artifacts keep their role", "verify.py", 'elif entry["role"] != "native-artifact":', "elif False:", [row("native artifact has another role in the manifest")]),
    ("evidence is in the manifest with the same digest", "verify.py", 'if entry is None or entry["digest"] != ev["digest"]:', "if False:", [row("evidence file removed from the bundle and the manifest")]),
    ("evidence is never a native artifact", "verify.py", 'elif entry["role"] not in ("observation", "record"):', "elif False:", [row("verdict evidence is a native artifact")]),
    ("anchor value must be well formed", "verify.py", 'if not isinstance(supplied, str) or not DIGEST_RE.fullmatch(supplied):\n            _add(findings, "ANCHOR_VALUE_MALFORMED"', 'if False:\n            _add(findings, "ANCHOR_VALUE_MALFORMED"',
     [t("test_qe_tamper.py", "test_a_malformed_anchor_value_is_refused")]),
    ("supplied anchor must equal the manifest digest", "verify.py", "if supplied != manifest_digest:", "if False:", [t("test_qe_tamper.py", "test_a_wrong_anchor_fails")]),
    ("sidecar must agree with a supplied anchor", "verify.py", "if sidecar_ok and declared != manifest_digest:", "if False:",
     [t("test_qe_tamper.py", "test_a_sidecar_that_disagrees_with_a_matching_supplied_value_is_flagged")]),
    ("sidecar must name this manifest", "verify.py", "if manifest_digest is None or declared != manifest_digest:", "if False:",
     [t("test_qe_tamper.py", "test_a_sidecar_that_names_another_manifest_fails_even_without_a_supplied_value")]),
    ("sidecar alone is only declared", "verify.py", 'return AnchorResult("declared", anchor_type, reference, None, declared, manifest_digest)',
     'return AnchorResult("verified", anchor_type, reference, None, declared, manifest_digest)', [t("test_qe_tamper.py", "test_an_anchor_sidecar_alone_is_declared_not_established")]),
    ("manifest is required", "verify.py", "if MANIFEST_NAME not in safe:", "if False:", [t("test_qe_tamper.py", "test_a_missing_manifest_and_a_missing_report_are_reported")]),
    ("report is required", "verify.py", "if rpath not in safe:", "if False:", [t("test_qe_tamper.py", "test_a_missing_manifest_and_a_missing_report_are_reported")]),
    ("duplicate paths in the source", "verify.py", "if counts[entry.path] == 2:", "if False:", [t("test_qe_tamper.py", "test_two_entries_with_one_path_are_reported_by_the_verifier_itself")]),
    ("case collision between entries", "verify.py", "if len(names) > 1:", "if False:", [t("test_qe_tamper.py", "test_case_colliding_names_are_refused_in_an_archive")]),
    ("file and directory with one name", "verify.py", "if any(q.startswith(p + \"/\") for q in paths):", "if False:", [t("test_qe_tamper.py", "test_a_file_that_is_also_a_directory_is_refused")]),
    # ---- schemas.py ------------------------------------------------------------------------------------------------------------------
    ("unknown major version refused", "schemas.py", "if version[0] != SUPPORTED_MAJOR:", "if False:", [row("unknown major version (manifest)")]),
    ("schema id must match", "schemas.py", 'if doc.get("schema") != schema_id:', "if False:", [row("report names another schema")]),
    ("newer minor is noted", "schemas.py", "if version[1] > SUPPORTED_MINOR:", "if False:", [t("test_qe_tamper.py", "test_a_newer_minor_version_is_read_with_the_same_rules")]),
    ("unknown fields keep their own code", "schemas.py", 'code = "UNKNOWN_FIELD" if issue.code == "UNKNOWN_FIELD" else "SCHEMA_INVALID"', 'code = "SCHEMA_INVALID"', [row("unknown security-sensitive field (manifest)")]),
    # ---- minischema.py ---------------------------------------------------------------------------------------------------------------
    ("unknown properties are refused", "minischema.py", "elif additional is False:", "elif False:", [row("adapter-originated verified field")]),
    ("informational extras must be plain scalars", "minischema.py", "ok = INFO_KEY_RE.fullmatch(key) is not None and (", "ok = True or (",
     [t("test_qe_minischema.py", "test_informational_extras_of_the_wrong_form_are_refused")]),
    ("required properties", "minischema.py", "if name not in value:", "if False:", [t("test_qe_report.py", "test_every_required_top_level_field_is_required")]),
    ("enum", "minischema.py", 'if "enum" in schema and not any(', 'if False and not any(', [row("native status replaced by a verdict word")]),
    ("const", "minischema.py", 'if "const" in schema and (value != schema["const"] or type(value) is not type(schema["const"])):', "if False:",
     [t("test_qe_minischema.py", "test_each_keyword_accepts_good_values_and_rejects_bad_ones")]),
    ("pattern", "minischema.py", 'if "pattern" in schema and not re.fullmatch(schema["pattern"], value):', "if False:", [t("test_qe_minischema.py", "test_each_keyword_accepts_good_values_and_rejects_bad_ones")]),
    ("integers exclude booleans", "minischema.py", "return isinstance(value, int) and not isinstance(value, bool)", "return isinstance(value, int)",
     [t("test_qe_report.py", "test_the_schema_refuses")]),
    ("an unsupported schema keyword is an error", "minischema.py", "if key not in KEYWORDS and key not in ANNOTATIONS:", "if False:",
     [t("test_qe_minischema.py", "test_a_keyword_the_validator_does_not_implement_makes_the_schema_unusable")]),
    ("an open object must be informational", "minischema.py", 'if schema.get("additionalProperties") is True and schema.get("x-qa-informational") is not True:', "if False:",
     [t("test_qe_minischema.py", "test_an_object_schema_must_say_what_happens_to_unknown_properties_and_refs_must_resolve")]),
    ("property names", "minischema.py", 'if "pattern" in names and not re.fullmatch(names["pattern"], key):', "if False:", [t("test_qe_minischema.py", "test_each_keyword_accepts_good_values_and_rejects_bad_ones")]),
    # ---- paths.py --------------------------------------------------------------------------------------------------------------------
    ("traversal has its own code", "paths.py", '"PATH_TRAVERSAL" if comp == ".." else "PATH_UNSAFE"', '"PATH_UNSAFE"', [t("test_qe_paths.py", "test_unsafe_paths_name_the_rule_they_break")]),
    ("absolute paths", "paths.py", 'if path.startswith("/"):', "if False:", [t("test_qe_paths.py", "test_unsafe_paths_name_the_rule_they_break")]),
    ("ASCII character set (backslash, colon, space, wildcards)", "paths.py", "if not _ASCII_OK.fullmatch(comp):", "if False:", [t("test_qe_paths.py", "test_unsafe_paths_name_the_rule_they_break")]),
    ("non-ASCII has its own code", "paths.py", "if not comp.isascii():", "if False:", [t("test_qe_paths.py", "test_unsafe_paths_name_the_rule_they_break")]),
    ("device names", "paths.py", 'if comp.split(".")[0].lower() in _RESERVED:', "if False:", [t("test_qe_paths.py", "test_unsafe_paths_name_the_rule_they_break")]),
    ("leading and trailing dots", "paths.py", 'if comp.endswith(".") or comp.startswith("."):', "if False:", [t("test_qe_paths.py", "test_unsafe_paths_name_the_rule_they_break")]),
    ("path length", "paths.py", 'if len(path.encode("utf-8", "replace")) > limits.max_path_bytes:', "if False:", [t("test_qe_paths.py", "test_the_caps_are_parameters")]),
    ("component length", "paths.py", 'if len(comp.encode("utf-8", "replace")) > limits.max_component_bytes:', "if False:", [t("test_qe_paths.py", "test_the_caps_are_parameters")]),
    ("case folding", "paths.py", 'return "".join(c.lower() if c < "\\x80" else c for c in path)', "return path",
     [t("test_qe_paths.py", "test_fold_key_makes_case_variants_collide_and_never_depends_on_the_unicode_database")]),
    # ---- canon.py --------------------------------------------------------------------------------------------------------------------
    ("duplicate JSON keys", "canon.py", "if key in seen:", "if False:", [t("test_qe_canon.py", "test_what_cannot_be_read_strictly_is_refused_with_a_stable_code")]),
    ("floats", "canon.py", '    raise CanonError("FLOAT_REFUSED", f"numbers must be integers (got {text!r})")', "    return 0",
     [t("test_qe_canon.py", "test_what_cannot_be_read_strictly_is_refused_with_a_stable_code")]),
    ("NaN and Infinity", "canon.py", '    raise CanonError("CONSTANT_REFUSED", f"{text} is not allowed")', "    return 0", [t("test_qe_canon.py", "test_what_cannot_be_read_strictly_is_refused_with_a_stable_code")]),
    ("byte-order mark", "canon.py", 'if data.startswith(b"\\xef\\xbb\\xbf"):', "if False:", [t("test_qe_canon.py", "test_what_cannot_be_read_strictly_is_refused_with_a_stable_code")]),
    ("document size cap", "canon.py", "if len(data) > limits.max_json_bytes:", "if False:", [t("test_qe_canon.py", "test_caps_on_size_strings_and_item_counts")]),
    ("nesting cap", "canon.py", "if depth > limits.max_json_depth:", "if False:", [t("test_qe_canon.py", "test_what_cannot_be_read_strictly_is_refused_with_a_stable_code")]),
    ("lone surrogates", "canon.py", '            value.encode("utf-8")\n', "            pass\n", [t("test_qe_canon.py", "test_what_cannot_be_read_strictly_is_refused_with_a_stable_code")]),
    ("canonical key order", "canon.py", "sort_keys=True, indent=2,", "sort_keys=False, indent=2,", [t("test_qe_canon.py", "test_canonical_form_is_one_byte_sequence_per_document")]),
    ("canonical ASCII escapes", "canon.py", "ensure_ascii=True, separators", "ensure_ascii=False, separators", [t("test_qe_canon.py", "test_canonical_form_is_one_byte_sequence_per_document")]),
    ("text sanitising", "canon.py", '_STRIP = {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp", "Zs"}', "_STRIP = set()", [t("test_qe_canon.py", "test_safe_text_leaves_no_control_or_format_character")]),
    # ---- report.py -------------------------------------------------------------------------------------------------------------------
    ("duplicate lane ids in the report", "report.py", 'if lane_ids.count(x["lane_id"]) > 1:', "if False:", [row("duplicated lane id (report)")]),
    ("duplicate lane run ids", "report.py", 'if run_ids.count(x["run_id"]) > 1:', "if False:", [t("test_qe_report.py", "test_the_semantic_check_refuses[duplicate lane run id]")]),
    ("time order", "report.py", 'if report["started_at"] > report["finished_at"]:', "if False:", [t("test_qe_report.py", "test_the_semantic_check_refuses[finished before started]")]),
    ("duplicate frozen assertion", "report.py", 'if a["assertion_id"] in frozen_by_id:', "if False:", [row("duplicated assertion id")]),
    ("frozen assertion on an unknown lane", "report.py", 'if a["lane_id"] not in lane_ids:', "if False:", [t("test_qe_report.py", "test_the_semantic_check_refuses[frozen assertion on an unknown lane]")]),
    ("assertion set digest", "report.py", 'if assertion_set_digest(frozen) != report["assertion_set"]["digest"]:', "if False:", [row("changed assertion digest in the report")]),
    ("an assertion accounted twice", "report.py", "if seen[aid] == 2:", "if False:", [t("test_qe_report.py", "test_the_semantic_check_refuses[an assertion is accounted twice]")]),
    ("an unfrozen assertion accounted", "report.py", "if aid not in frozen_by_id:\n            out.append((\"ACCOUNTING_UNKNOWN\"", "if False:\n            out.append((\"ACCOUNTING_UNKNOWN\"",
     [t("test_qe_report.py", "test_the_semantic_check_refuses[an assertion outside the frozen set is accounted]")]),
    ("result on another lane", "report.py", 'if frozen_by_id[aid]["lane_id"] != r["lane_id"]:', "if False:", [t("test_qe_report.py", "test_the_semantic_check_refuses[result on another lane]")]),
    ("every frozen assertion accounted", "report.py", "if aid not in seen:", "if False:", [row("frozen assertion not accounted")]),
    ("declared counts", "report.py", "if acc[key] != value:", "if False:", [row("accounting that does not add up")]),
    ("UNACCOUNTED has no provenance", "report.py", "if prov is not None:\n                out.append((\"PROVENANCE_RULE\"", "if False:\n                out.append((\"PROVENANCE_RULE\"",
     [t("test_qe_report.py", "test_the_semantic_check_refuses[UNACCOUNTED with provenance]")]),
    ("a verdict needs provenance", "report.py", "if prov is None:\n            out.append((\"PROVENANCE_RULE\"", "if False:\n            out.append((\"PROVENANCE_RULE\"", [row("verdict without provenance")]),
    ("VERIFIED needs evidence", "report.py", 'if v["state"] == "VERIFIED" and prov["evidence"] is None:', "if False:", [t("test_qe_report.py", "test_the_semantic_check_refuses[VERIFIED without evidence]")]),
    ("verdict bound to the frozen assertion digest", "report.py", 'if prov["assertion_digest"] != frozen_by_id[aid]["digest"]:', "if False:",
     [t("test_qe_report.py", "test_the_semantic_check_refuses[verdict over another assertion digest]")]),
    ("one verifier per run", "report.py", 'if prov["verifier"] != report["verdict"]["provenance"]["verifier"]:', "if False:", [t("test_qe_report.py", "test_the_semantic_check_refuses[another verifier per assertion]")]),
    ("outcome comes from the accounting", "report.py", 'if verdict["outcome"] != outcome:', "if False:", [row("run outcome flipped to VERIFIED")]),
    ("verdict bound to the assertion set", "report.py", 'if verdict["provenance"]["assertion_set_digest"] != report["assertion_set"]["digest"]:', "if False:",
     [t("test_qe_report.py", "test_the_semantic_check_refuses[verdict bound to another assertion set]")]),
    ("verdict bound to the evidence set", "report.py", 'if verdict["provenance"]["evidence_set_digest"] != evidence_set_digest(results):', "if False:",
     [t("test_qe_report.py", "test_the_semantic_check_refuses[verdict bound to other evidence]")]),
    ("required limitations present", "report.py", "if need not in ids:", "if False:", [row("required limitation removed")]),
    ("required limitations unchanged", "report.py", 'if x["id"] in LIMITATION_TEXTS and x["text"] != LIMITATION_TEXTS[x["id"]]:', "if False:",
     [t("test_qe_report.py", "test_the_semantic_check_refuses[required limitation altered]")]),
    ("any failure fails the run", "report.py", 'if "FAILED" in states:\n        return "FAILED"', 'if False:\n        return "FAILED"', [t("test_qe_report.py", "test_the_run_outcome_comes_only_from_the_verdicts")]),
    ("only all-verified verifies", "report.py", 'if frozen == 0 or any(s != "VERIFIED" for s in states) or len(states) != frozen:', "if False:",
     [t("test_qe_report.py", "test_the_run_outcome_comes_only_from_the_verdicts")]),
    # ---- tarfmt.py -------------------------------------------------------------------------------------------------------------------
    ("canonical header comparison", "tarfmt.py", "if size is None or not raw_name or block != encode_header(name, size):", "if size is None or not raw_name:",
     [t("test_qe_tar.py", "test_links_directories_and_devices_are_not_canonical")]),
    ("entry order", "tarfmt.py", "elif previous is not None and name < previous:", "elif False:", [t("test_qe_tar.py", "test_entries_out_of_order_or_duplicated_are_reported")]),
    ("duplicate names", "tarfmt.py", "if previous is not None and name == previous:", "if False:", [t("test_qe_tar.py", "test_entries_out_of_order_or_duplicated_are_reported")]),
    ("trailing data", "tarfmt.py", "if total != padded:", "if False:", [t("test_qe_tar.py", "test_trailing_data_a_missing_marker_and_truncation_are_reported")]),
    ("data after the marker", "tarfmt.py", "if rest.strip(b\"\\x00\"):", "if False:", [t("test_qe_tar.py", "test_trailing_data_a_missing_marker_and_truncation_are_reported")]),
    ("end marker", "tarfmt.py", "if second != b\"\\x00\" * BLOCK:", "if False:", [t("test_qe_tar.py", "test_trailing_data_a_missing_marker_and_truncation_are_reported")]),
    ("truncated entry", "tarfmt.py", "if data_start + size > total:", "if False:", [t("test_qe_tar.py", "test_trailing_data_a_missing_marker_and_truncation_are_reported")]),
    ("missing end marker", "tarfmt.py", "if not ended:", "if False:", [t("test_qe_tar.py", "test_trailing_data_a_missing_marker_and_truncation_are_reported")]),
    ("entry count cap", "tarfmt.py", "if len(entries) > limits.max_files:", "if False:", [t("test_qe_tar.py", "test_the_entry_cap_is_enforced_while_scanning")]),
    # ---- sources.py ------------------------------------------------------------------------------------------------------------------
    ("symbolic links in a directory", "sources.py", "if stat.S_ISLNK(st.st_mode):\n                self.problems.append((\"SYMLINK_REFUSED\"", "if False:\n                self.problems.append((\"SYMLINK_REFUSED\"",
     [t("test_qe_tamper.py", "test_a_symbolic_link_in_a_directory_bundle_is_refused")]),
    ("junctions", "sources.py", 'elif getattr(st, "st_file_attributes", 0) & _REPARSE:', "elif False:", [t("test_qe_tamper.py", "test_a_junction_is_refused")]),
    ("special files", "sources.py", 'self.problems.append(("SPECIAL_FILE"', 'pass  # self.problems.append(("SPECIAL_FILE"', [t("test_qe_tamper.py", "test_a_fifo_is_refused_as_a_special_file")]),
    ("the location itself may not be a link", "sources.py", "if stat.S_ISLNK(st.st_mode):\n        raise SourceError", "if False:\n        raise SourceError",
     [t("test_qe_tamper.py", "test_a_bundle_location_that_is_itself_a_symbolic_link_is_not_opened")]),
    ("reads do not follow links", "sources.py", 'getattr(os, "O_NOFOLLOW", 0)', "0", [t("test_qe_sources.py", "test_reading_never_follows_a_symbolic_link_even_if_one_appears_after_listing")]),
    ("reads only regular files", "sources.py", "if not stat.S_ISREG(os.fstat(fd).st_mode):", "if False:", [t("test_qe_sources.py", "test_reading_refuses_a_pipe_that_replaced_a_file")]),
    ("directory depth cap", "sources.py", "if depth > MAX_DIR_DEPTH:", "if False:", [t("test_qe_sources.py", "test_directories_nested_deeper_than_the_cap_are_refused")]),
    ("directory file cap", "sources.py", "if len(self.entries) > self._limits.max_files:", "if False:", [t("test_qe_sources.py", "test_a_directory_with_more_files_than_the_cap_is_refused")]),
    ("archive size ceiling", "sources.py", "if total > ceiling:", "if False:", [t("test_qe_sources.py", "test_an_archive_larger_than_the_ceiling_is_refused_without_being_read")]),
    ("bounded reads", "sources.py", "remaining = limit + 1\n", "remaining = 1 << 62\n", [t("test_qe_sources.py", "test_reads_are_bounded_by_the_limit_plus_one_in_every_form")]),
    # ---- model.py, build.py, cli.py, render.py --------------------------------------------------------------------------------------
    ("only a verified anchor is established", "model.py", 'be trusted."""\n        return self.state == "verified"', 'be trusted."""\n        return self.state in ("verified", "declared")',
     [t("test_qe_tamper.py", "test_an_anchor_sidecar_alone_is_declared_not_established")]),
    ("assurance names the limit", "model.py", 'return "matches-supplied-anchor" if self.anchor.matches else "internal-consistency-only"', 'return "matches-supplied-anchor"',
     [t("test_qe_tamper.py", "test_the_clean_bundle_has_no_finding_and_says_it_is_not_anchored")]),
    ("the builder checks its own output", "build.py", "if check.findings:", "if False:", [t("test_qe_bundle.py", "test_the_builder_refuses_a_report_that_does_not_match_the_files")]),
    ("the builder refuses reserved names", "build.py", "if path in RESERVED_UNLISTED or path in (REPORT_NAME, FORMAT_DOC_NAME, ASSERTION_LOCK_NAME):", "if False:",
     [t("test_qe_bundle.py", "test_the_builder_refuses_unsafe_or_reserved_inputs")]),
    ("the builder refuses a caller-supplied report role", "build.py", 'if spec.role not in ROLES or spec.role in ("report", "documentation", "assertion-lock"):', "if False:",
     [t("test_qe_bundle.py", "test_the_builder_refuses_unsafe_or_reserved_inputs")]),
    ("require-anchor", "cli.py", "if status == 0 and args.require_anchor and not v.anchor.matches:", "if False:", [t("test_qe_cli.py", "test_require_anchor_makes_an_unanchored_bundle_exit_3")]),
    ("digest only for a verified bundle", "cli.py", 'if v.manifest_digest is None or not v.ok:\n            print("error: refusing to print', 'if v.manifest_digest is None:\n            print("error: refusing to print',
     [t("test_qe_cli.py", "test_digest_prints_the_value_an_anchor_should_hold")]),
    ("a text report of unrecomputed verdicts shows no OK", "render.py", '(("OK - internally consistent" if verdicts_recomputed else NOT_RECOMPUTED_OK) if v.ok', '("OK - internally consistent" if v.ok', [t("test_qe_render.py", "test_a_caller_that_did_not_recompute_the_verdicts_gets_a_report_that_does_not_say_verified_or_ok")]),
    ("an html report of unrecomputed verdicts has no green banner", "render.py", 'vclass = ("ok" if verdicts_recomputed else "warn") if v.ok else "bad"', 'vclass = "ok" if v.ok else "bad"', [t("test_qe_render.py", "test_a_caller_that_did_not_recompute_the_verdicts_gets_a_report_that_does_not_say_verified_or_ok")]),
    ("unrecomputed verdicts are not an independent verdict", "render.py", '"INDEPENDENT VERDICT (verifier over recorded observations and frozen assertions)" if verdicts_recomputed', '"INDEPENDENT VERDICT (verifier over recorded observations and frozen assertions)" if True', [t("test_qe_render.py", "test_a_caller_that_did_not_recompute_the_verdicts_gets_a_report_that_does_not_say_verified_or_ok")]),
    ("text rendering names the anchor state", "render.py", 'lines.append("External anchor: " + v.anchor.notice)', "pass", [t("test_qe_render.py", "test_a_clean_unanchored_bundle_says_integrity_against_reforging_is_not_established")]),
    ("html rendering names the anchor state", "render.py", "out.append('<div class=\"banner %s\">External anchor: %s</div>' % (aclass, e(v.anchor.notice)))", "pass",
     [t("test_qe_render.py", "test_a_clean_unanchored_bundle_says_integrity_against_reforging_is_not_established")]),
    ("text values are sanitised", "render.py", "    return safe_text(value, limit)", "    return str(value)", [t("test_qe_render.py", "test_control_bidi_and_zero_width_characters_are_made_visible_in_both_renderings")]),
    ("html values are escaped", "render.py", "e = lambda value, limit=2000: html.escape(safe_text(value, limit), quote=True)", "e = lambda value, limit=2000: safe_text(value, limit)",
     [t("test_qe_render.py", "test_hostile_text_never_becomes_markup")]),
    ("html forbids loading resources", "render.py", "default-src \\'none\\'; ", "", [t("test_qe_render.py", "test_the_page_is_one_self_contained_file_with_no_script_and_no_external_resource")]),
    ("failed bundles are flagged as untrusted", "render.py", "if not ins.content_trusted:\n            out.append(", "if False:\n            out.append(",
     [t("test_qe_render.py", "test_a_failed_bundle_is_flagged_and_its_content_is_marked_untrusted")]),
    ("native and verdict are rendered apart", "render.py", 'lines += [_RULE, "NATIVE ENGINE RESULTS (what each engine itself reported; not verdicts)"]',
     'lines += [_RULE, "RESULTS"]', [t("test_qe_render.py", "test_native_results_and_verdicts_are_in_separate_sections")]),
]


R = "test_qe_review.py"


def rv(name):
    return t(R, name)


# ---- the independent review of the first version: one or more mutants per finding ----------------------------------------------------------------
CASES += [
    # B1: documents that are not objects
    ("a document that is not a JSON object is unreadable", "verify.py", "if not isinstance(doc, dict):", "if False:", [rv("test_b1_a_non_object_manifest_never_verifies"), rv("test_b1_a_non_object_report_never_verifies")]),
    ("completeness is computed from both documents", "verify.py", "complete = docs.manifest is not None and docs.report is not None", "complete = True", [rv("test_b1_a_non_object_manifest_never_verifies")]),
    ("an incomplete verification is a finding", "verify.py", "    if not complete:\n", "    if False:\n", [rv("test_b1_a_non_object_manifest_never_verifies")]),
    ("ok needs completeness", "model.py", "def ok(self) -> bool:\n        return self.complete and not self.findings", "def ok(self) -> bool:\n        return not self.findings",
     [rv("test_b1_ok_needs_both_documents_parsed_and_valid")]),
    ("the digest command refuses a bundle that does not verify", "cli.py", 'if v.manifest_digest is None or not v.ok:\n            print("error: refusing to print', 'if v.manifest_digest is None:\n            print("error: refusing to print',
     [rv("test_b1_the_cli_does_not_verify_or_name_a_digest_for_a_null_manifest")]),
    # H1: lanes that did not complete or account for nothing
    ("a lane that did not complete caps the outcome", "report.py", "if any(s not in COMPLETING_STATUSES for s in lane_statuses):", "if False:",
     [rv("test_h1_compute_outcome_knows_the_lane_statuses"), rv("test_h1_a_lane_that_did_not_complete_caps_the_outcome_at_inconclusive")]),
    ("the capped outcome has its own reason", "report.py", 'if outcome == "INCONCLUSIVE" and frozen > 0 and len(states) == frozen and all(s == "VERIFIED" for s in states):', "if False:",
     [rv("test_h1_a_lane_that_did_not_complete_caps_the_outcome_at_inconclusive")]),
    ("a lane without assertions is a finding", "report.py", 'if not any(a["lane_id"] == x["lane_id"] for a in frozen):', "if False:", [rv("test_h1_a_lane_with_no_frozen_assertion_is_a_finding")]),
    ("a lane that did not complete but whose assertions all verified is shown", "report.py", 'elif native != "NATIVE_PASS" and all_verified:', "elif False:",
     [rv("test_h1_the_inspection_surfaces_every_lane_whose_native_status_and_verdicts_disagree")]),
    ("a lane without assertions is shown by the inspection", "report.py", "        if not states:\n", "        if False:\n",
     [rv("test_h1_the_inspection_shows_a_lane_without_assertions")]),
    # H2: evidence is never what the engine wrote
    ("evidence with the bytes of a native artifact", "verify.py", 'if ev["digest"] in native_digests:', "if False:", [rv("test_h2_evidence_with_the_bytes_of_a_native_artifact_is_refused")]),
    ("native artifacts named only in the report count too", "verify.py", 'native_digests |= {a["digest"] for lane in rep["lanes"] for a in lane["native"]["artifacts"]}', "pass",
     [rv("test_h2_evidence_with_the_bytes_of_a_native_artifact_the_manifest_does_not_list_is_still_refused")]),
    ("native directory files count as native bytes whatever their label", "verify.py", 'if NATIVE_DIR_RE.fullmatch(e["path"]) or e["role"] == "native-artifact"}',
     'if e["role"] == "native-artifact"}', [rv("test_h2_native_directory_bytes_count_whatever_the_label")]),
    ("evidence inside a native directory", "verify.py", 'if NATIVE_DIR_RE.fullmatch(ev["path"]):', "if False:", [rv("test_h2_evidence_inside_a_lanes_native_output_directory_is_refused_even_labelled_observation")]),
    ("a lane's native artifacts live in its native directory", "report.py", "if not a[\"path\"].startswith(f\"lanes/{x['lane_id']}/native/\"):", "if False:", [rv("test_h2_a_native_artifact_must_live_in_its_lanes_native_directory")]),
    ("files in a native directory are native artifacts", "verify.py", 'if NATIVE_DIR_RE.fullmatch(f["path"]) and f["role"] != "native-artifact":', "if False:", [rv("test_h2_the_manifest_labels_must_agree_with_the_native_directory")]),
    ("a native-artifact label outside the native directory", "verify.py", 'if f["role"] == "native-artifact" and not NATIVE_DIR_RE.fullmatch(f["path"]):', "if False:", [rv("test_h2_the_manifest_labels_must_agree_with_the_native_directory")]),
    # H3: terminal output
    ("findings are sanitised before printing", "cli.py", 'print(f"  {safe_text(f.code)} {safe_text(f.path)}: {safe_text(f.message)}", file=out)', 'print(f"  {f.code} {f.path}: {f.message}", file=out)',
     [rv("test_h3_hostile_names_never_reach_the_terminal_raw"), rv("test_h3_a_hostile_name_cannot_forge_an_ok_line")]),
    ("error messages are sanitised", "cli.py", 'print(f"error: {safe_text(str(exc))}", file=err)', 'print(f"error: {exc}", file=err)', [rv("test_h3_error_messages_are_sanitised_too")]),
    ("space separators are made visible", "canon.py", '"Zl", "Zp", "Zs"}', '"Zl", "Zp"}', [rv("test_h3_safe_text_escapes_every_space_separator_but_the_plain_space")]),
    ("the plain space stays a space", "canon.py", 'and ch != " ") or ch in', ') or ch in', [rv("test_h3_safe_text_escapes_every_space_separator_but_the_plain_space")]),
    # M1, M2, M3
    ("zero padding after each entry", "tarfmt.py", 'if fh.read(pad).strip(b"\\x00"):', "if False:", [rv("test_m1_padding_after_an_entrys_data_must_be_zero")]),
    ("path characters are matched in full", "paths.py", "if not _ASCII_OK.fullmatch(comp):", "if not _ASCII_OK.match(comp):", [rv("test_m2_paths_with_newlines_are_refused")]),
    ("schema patterns are matched in full", "minischema.py", 'if "pattern" in schema and not re.fullmatch(schema["pattern"], value):', 'if "pattern" in schema and not re.search(schema["pattern"], value):',
     [rv("test_m2_every_pattern_is_a_full_match")]),
    ("anchor values are matched in full", "verify.py", 'if not isinstance(supplied, str) or not DIGEST_RE.fullmatch(supplied):\n            _add(findings, "ANCHOR_VALUE_MALFORMED"',
     'if not isinstance(supplied, str) or not DIGEST_RE.match(supplied):\n            _add(findings, "ANCHOR_VALUE_MALFORMED"', [rv("test_m2_an_anchor_value_with_a_trailing_newline_is_malformed")]),
    ("plan values are matched in full", "verify.py", 'if not isinstance(supplied, str) or not DIGEST_RE.fullmatch(supplied):\n        _add(findings, "PLAN_VALUE_MALFORMED"',
     'if not isinstance(supplied, str) or not DIGEST_RE.match(supplied):\n        _add(findings, "PLAN_VALUE_MALFORMED"', [rv("test_m4_a_malformed_plan_digest_is_refused")]),
    ("version strings are matched in full", "schemas.py", "m = VERSION_RE.fullmatch(text) if", "m = VERSION_RE.match(text) if", [rv("test_m2_a_schema_version_with_a_trailing_newline_is_a_shape_error_not_a_version")]),
    ("informational names are matched in full", "minischema.py", "ok = INFO_KEY_RE.fullmatch(key) is not None and (", "ok = INFO_KEY_RE.match(key) is not None and (", [rv("test_m2_informational_names_are_full_matches")]),
    ("schema patterns must be anchored", "minischema.py", 'if not (schema["pattern"].startswith("^") and schema["pattern"].endswith("$")):', "if False:", [rv("test_m2_schema_patterns_must_be_anchored_so_that_other_validators_agree")]),
    ("property-name patterns must be anchored", "minischema.py", 'if names_pattern is not None and not (names_pattern.startswith("^") and names_pattern.endswith("$")):', "if False:",
     [rv("test_m2_schema_patterns_must_be_anchored_so_that_other_validators_agree")]),
    # M4: the assertion set and the plan
    ("the plan digest is compared with the supplied value", "verify.py", "if declared != supplied:", "if False:", [rv("test_m4_a_failing_assertion_removed_and_every_digest_recomputed_verifies_internally_but_the_plan_digest_catches_it")]),
    ("a supplied plan digest must be well formed", "verify.py", 'if not isinstance(supplied, str) or not DIGEST_RE.fullmatch(supplied):\n        _add(findings, "PLAN_VALUE_MALFORMED"',
     'if False:\n        _add(findings, "PLAN_VALUE_MALFORMED"', [rv("test_m4_a_malformed_plan_digest_is_refused")]),
    ("an unchecked plan says so", "verify.py", "    if supplied is None:\n        return PlanResult(\"absent\", None, declared)", "    if False:\n        return PlanResult(\"absent\", None, declared)",
     [rv("test_m4_a_failing_assertion_removed_and_every_digest_recomputed_verifies_internally_but_the_plan_digest_catches_it")]),
    ("the plan digest is the digest of the assertion set", "report.py", 'if report["plan_digest"] != report["assertion_set"]["digest"]:', "if False:", [rv("test_m4_plan_digests_must_agree_everywhere")]),
    ("the verdict is bound to the plan digest", "report.py", 'if verdict["provenance"]["plan_digest"] != report["plan_digest"]:', "if False:", [rv("test_m4_plan_digests_must_agree_everywhere")]),
    ("manifest and report agree on the plan digest", "verify.py", 'if man["plan_digest"] != rep["plan_digest"]:', "if False:", [rv("test_m4_plan_digests_must_agree_everywhere")]),
    ("exactly one assertion lock", "verify.py", 'if len(locks) != 1 or locks[0]["path"] != ASSERTION_LOCK_NAME:', "if False:", [rv("test_m4_the_assertion_lock_is_required_and_must_match")]),
    ("the assertion lock is the frozen set", "verify.py", 'if lock is not None and lock["role"] == "assertion-lock" and lock["digest"] != rep["assertion_set"]["digest"]:', "if False:",
     [rv("test_m4_the_assertion_lock_is_required_and_must_match")]),
    ("the builder writes the assertion lock", "build.py", 'entries[ASSERTION_LOCK_NAME] = FileSpec(assertion_lock_bytes(report["assertion_set"]["assertions"]), "assertion-lock")', "pass",
     [rv("test_m4_the_report_manifest_and_verdict_carry_one_plan_digest_equal_to_the_digest_of_the_assertion_lock")]),
    ("the assembler requires a plan digest", "report.py", "    if plan_digest is None:\n", "    if False:\n", [rv("test_m4_a_null_plan_digest_is_refused_by_the_schema_and_the_assembler")]),
    # M5
    ("report lane run ids are bound to the run id", "report.py", "if x[\"run_id\"] != f\"{report['run_id']}.{x['lane_id']}\":", "if False:", [rv("test_m5_a_lane_run_id_must_be_the_run_id_and_the_lane_id")]),
    ("manifest lane run ids are bound to the run id", "verify.py", "if x[\"run_id\"] != f\"{man['run_id']}.{x['lane_id']}\":", "if False:", [rv("test_m5_the_manifest_lanes_are_bound_to_the_run_too")]),
    # M6
    ("the digest command says where a digest is meaningful", "cli.py", "print(v.manifest_digest, file=out)\n        print(DIGEST_ORIGIN_NOTICE, file=err)", "print(v.manifest_digest, file=out)",
     [rv("test_m6_digest_and_anchor_output_carry_the_provenance_sentence")]),
    ("the anchor command says where a digest is meaningful", "cli.py", ".decode(\"ascii\"))\n        print(DIGEST_ORIGIN_NOTICE, file=err)", ".decode(\"ascii\"))",
     [rv("test_m6_digest_and_anchor_output_carry_the_provenance_sentence")]),
    ("require-anchor success is a match, not a proof", "cli.py", "    if status == 0 and args.require_anchor:\n        print(", "    if False:\n        print(", [rv("test_m6_require_anchor_success_says_it_is_a_match_not_a_proof")]),
    # M7
    ("a passing lane reports no failures", "report.py", 'if counts is not None and (counts["failed"] or counts["errored"]):', "if False:", [rv("test_m7_native_status_counts_and_exit_code_must_agree")]),
    ("a passing lane has exit code 0", "report.py", "if code not in (0, None):", "if False:", [rv("test_m7_native_status_counts_and_exit_code_must_agree")]),
    ("a failing lane has a non-zero exit code", "report.py", "        if code == 0:\n", "        if False:\n", [rv("test_m7_native_status_counts_and_exit_code_must_agree")]),
    ("a failing lane reports a failure", "report.py", 'if counts is not None and not (counts["failed"] or counts["errored"]):', "if False:", [rv("test_m7_native_status_counts_and_exit_code_must_agree")]),
    ("a reason code belongs to its state", "report.py", 'if v["reason_code"] not in REASON_CODES[v["state"]]:', "if False:", [rv("test_m7_a_reason_code_must_belong_to_the_state")]),
    ("the run reason belongs to the outcome", "report.py", 'if verdict["reason_code"] != run_reason(verdict["outcome"], states, len(frozen), statuses):', "if False:",
     [rv("test_m7_the_run_level_reason_code_must_belong_to_the_outcome")]),
    ("the manifest names the verifier the report names", "verify.py", 'if man["tools"].get(verifier["id"]) != verifier["version"]:', "if False:", [rv("test_m7_the_manifest_tools_must_name_the_verifier_the_report_names")]),
    ("redaction rules need redaction", "report.py", 'if not report["redaction"]["applied"] and report["redaction"]["rules"]:', "if False:", [rv("test_m7_redaction_cannot_claim_rules_that_were_not_applied")]),
    # R1
    ("a NATIVE_FAIL lane is not a verified run", "report.py", '    if any(s == "NATIVE_FAIL" for s in lane_statuses):\n        return "INCONCLUSIVE"\n', '    if False:\n        return "INCONCLUSIVE"\n',
     [t("test_qe_r1.py", "test_the_rule_in_the_outcome_functions"), t("test_qe_r1.py", "test_a_native_fail_lane_with_verified_assertions_builds_as_inconclusive_with_the_named_reason")]),
    ("verify prints the run outcome", "cli.py", "            if v.run_outcome is not None:", "            if False:", [t("test_qe_r1.py", "test_verify_text_and_json_surface_the_disagreement")]),
    ("verify carries the disagreements", "verify.py", "disagreements=rpt.engine_verifier_disagreements(docs.report) if docs.report is not None else None)",
     "disagreements=None)", [t("test_qe_r1.py", "test_verify_text_and_json_surface_the_disagreement")]),
    # L1 - L9
    ("a $ref has no sibling keyword", "minischema.py", "        if beside:\n", "        if False:\n", [rv("test_l1_a_ref_with_a_sibling_keyword_or_pointing_at_another_ref_is_refused")]),
    ("a $ref does not point at a $ref", "minischema.py", 'if "$ref" in root["$defs"][ref[8:]]:', "if False:", [rv("test_l1_a_ref_with_a_sibling_keyword_or_pointing_at_another_ref_is_refused")]),
    ("type names are checked with the schema", "minischema.py", "if name is not None and name not in TYPE_NAMES:", "if False:", [rv("test_l1_unique_items_compares_objects_regardless_of_key_order_and_an_unknown_type_name_is_a_schema_error")]),
    ("unique items compare as JSON", "minischema.py", "json.dumps(v, sort_keys=True) for v in value", "repr(v) for v in value", [rv("test_l1_unique_items_compares_objects_regardless_of_key_order_and_an_unknown_type_name_is_a_schema_error")]),
    ("empty directories", "sources.py", "        if not children:\n", "        if False:\n", [rv("test_l4_an_empty_directory_in_a_directory_bundle_is_a_finding")]),
    ("only attestations are anchor types", "constants.py", 'ANCHOR_TYPES = ("ci-artifact-attestation",)', 'ANCHOR_TYPES = ("ci-artifact-attestation", "signed-bundle")', [rv("test_l5_signed_bundle_is_not_an_accepted_anchor_type")]),
    ("a crash has its own exit status", "cli.py", "    except Exception as exc:", "    except ZeroDivisionError as exc:", [rv("test_l8_a_crash_has_its_own_exit_status_and_leaks_nothing_from_the_bundle")]),
    ("lane ids that differ in case", "report.py", 'elif folded_lanes.count(x["lane_id"].lower()) > 1:', "elif False:", [rv("test_l9_ids_that_differ_only_in_case_are_a_finding")]),
    ("assertion ids that differ in case", "report.py", 'elif folded_ids.count(a["assertion_id"].lower()) > 1:', "elif False:", [rv("test_l9_ids_that_differ_only_in_case_are_a_finding")]),
    ("non-ASCII path bytes are named in findings without crashing", "paths.py", 'len(path.encode("utf-8", "replace")) > limits.max_path_bytes', 'len(path.encode("utf-8")) > limits.max_path_bytes',
     [rv("test_h3_a_name_that_is_not_valid_utf8_does_not_crash_the_command_line")]),
]


@pytest.mark.parametrize("name,rel,old,new,tests", CASES, ids=[c[0] for c in CASES])
def test_removing_the_guard_makes_the_tests_fail(tmp_path, name, rel, old, new, tests):
    result = mutant_result(tmp_path, rel, old, new, tests)
    # exit status 1 means "tests ran and at least one failed"; 2 (interrupted, collection error), 4 (usage) and 5 (nothing ran) are not kills
    assert result.returncode == 1, f"mutant not killed by a failing test (exit {result.returncode}): {name}\n{result.stdout[-1500:]}"
    assert re.search(r"\b[1-9][0-9]* failed\b", result.stdout), result.stdout[-1500:]


def test_the_selected_tests_pass_on_an_unmodified_copy(tmp_path):
    tests = sorted({x for c in CASES for x in c[4]})
    result = baseline_result(tmp_path, tests)
    assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-1500:]
