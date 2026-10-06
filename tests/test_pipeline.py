import json
import io
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import pipeline


class PipelineTests(unittest.TestCase):
    def test_default_cycle_runs_only_static_and_frida(self) -> None:
        args = pipeline.build_parser().parse_args(["run", "--apk-dir", "apks/example"])
        self.assertEqual(pipeline.selected_stages(args.stage), ("static", "frida"))
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(pipeline, "RUNS_ROOT", Path(temporary)), \
             mock.patch.object(pipeline, "resolve_apk_dir", return_value=Path("apks/example")), \
             mock.patch.object(pipeline, "inventory_apks", return_value={"base_apk_sha256": "a" * 64}), \
             mock.patch.object(pipeline, "preflight_claude"), \
             mock.patch.object(pipeline, "codex_binary", return_value="codex"), \
             mock.patch.object(pipeline, "execute_stage") as execute, \
             mock.patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(pipeline.command_run(args), 0)
            self.assertEqual([call.args[0].name for call in execute.call_args_list], ["static", "frida"])
            run_dir = execute.call_args.args[1]
            self.assertEqual(set(pipeline.load_json(run_dir / "run-state.json")["stages"]), {"static", "frida"})
            self.assertFalse((run_dir / "03-final").exists())
            self.assertTrue((run_dir / "01-static/artifacts").is_dir())

    def test_final_execution_is_temporarily_disabled(self) -> None:
        with self.assertRaisesRegex(pipeline.PipelineError, "temporarily disabled"):
            pipeline.selected_stages("final")
        with mock.patch.object(pipeline, "validate_before_stage") as validate:
            with self.assertRaisesRegex(pipeline.PipelineError, "temporarily disabled"):
                pipeline.execute_stage(pipeline.STAGES["final"], Path("unused"), "model", "high", False)
            validate.assert_not_called()
        with mock.patch("sys.stderr", new_callable=io.StringIO), self.assertRaises(SystemExit):
            pipeline.build_parser().parse_args(["run", "--stage", "final", "--run-id", "test"])

    def make_apk(self, path: Path) -> None:
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"manifest")

    def test_inventory_selects_base_and_hashes_every_split(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            apk_dir = Path(temporary)
            self.make_apk(apk_dir / "base.apk")
            self.make_apk(apk_dir / "split_config.en.apk")

            with mock.patch.object(pipeline, "ROOT", apk_dir.parent):
                inventory = pipeline.inventory_apks(apk_dir)

            self.assertEqual(inventory["base_apk"], f"{apk_dir.name}/base.apk")
            self.assertEqual(len(inventory["apk_files"]), 2)
            self.assertEqual(len(inventory["base_apk_sha256"]), 64)

    def test_inventory_rejects_ambiguous_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            apk_dir = Path(temporary)
            self.make_apk(apk_dir / "one.apk")
            self.make_apk(apk_dir / "two.apk")
            with self.assertRaisesRegex(pipeline.PipelineError, "no base.apk"):
                pipeline.inventory_apks(apk_dir)

    def test_codex_command_contains_model_schema_and_secret_filter(self) -> None:
        run_dir = pipeline.ROOT / "runs" / "test-run"
        spec = pipeline.STAGES["static"]
        command = pipeline.build_codex_command(spec, run_dir, "example-model", "high")
        self.assertIn("example-model", command)
        self.assertIn('model_reasoning_effort="high"', command)
        self.assertIn("shell_environment_policy.ignore_default_excludes=false", command)
        self.assertIn(str(spec.schema), command)
        self.assertNotIn("CODEX_API_KEY", command)

    def test_pipeline_defaults_to_astra_high(self) -> None:
        spec = pipeline.STAGES["static"]
        with mock.patch.dict(
            pipeline.os.environ,
            {},
            clear=True,
        ):
            self.assertEqual(pipeline.model_for(spec, None), "gpt-6-astra")
            self.assertEqual(pipeline.reasoning_effort_for(None), "high")

    def test_claude_stage_does_not_inherit_codex_model(self) -> None:
        with mock.patch.dict(pipeline.os.environ, {"APK_PIPELINE_MODEL": "custom-codex"}, clear=True):
            self.assertEqual(pipeline.model_for(pipeline.STAGES["static"], None), "custom-codex")
            self.assertEqual(pipeline.model_for(pipeline.STAGES["final"], None), "custom-codex")
            self.assertEqual(pipeline.model_for(pipeline.STAGES["frida"], None), "claude-opus-4-7")
            with mock.patch.dict(pipeline.os.environ, {"APK_PIPELINE_FRIDA_MODEL": "claude-env"}):
                self.assertEqual(pipeline.model_for(pipeline.STAGES["frida"], None), "claude-env")
                self.assertEqual(pipeline.model_for(pipeline.STAGES["frida"], "claude-cli"), "claude-cli")

    def test_claude_command_uses_stream_schema_and_high_effort(self) -> None:
        spec = pipeline.STAGES["frida"]
        with mock.patch.object(pipeline, "claude_binary", return_value="claude"):
            command = pipeline.build_stage_command(spec, pipeline.ROOT / "runs/test", "claude-opus-4-7", "high")
        self.assertEqual(command[0], "claude")
        self.assertEqual(command[command.index("--model") + 1], "claude-opus-4-7")
        self.assertEqual(command[command.index("--effort") + 1], "high")
        self.assertEqual(command[command.index("--output-format") + 1], "stream-json")
        schema = json.loads(command[command.index("--json-schema") + 1])
        for field in ("markdown_report", "bypass_script"):
            self.assertIn(field, schema["required"])
            schema["required"].remove(field)
            schema["properties"].pop(field)
        self.assertEqual(schema, pipeline.load_json(spec.schema))
        self.assertNotIn("--sandbox", command)
        self.assertIn("dontAsk", command)
        self.assertNotIn("--bare", command)  # saved subscription authentication remains usable
        self.assertEqual(command[command.index("--tools") + 1], "")
        self.assertIn("--disable-slash-commands", command)
        self.assertIn("--strict-mcp-config", command)
        self.assertEqual(command[command.index("--mcp-config") + 1], '{"mcpServers":{}}')
        self.assertEqual(command[command.index("--settings") + 1], '{"disableAllHooks":true}')

    def test_claude_schema_describes_generation_only(self) -> None:
        schema = pipeline.load_json(pipeline.STAGES["frida"].schema)
        self.assertEqual(schema["$schema"], "http://json-schema.org/draft-07/schema#")
        self.assertEqual(schema["properties"]["schema_version"]["const"], "2.0")
        self.assertEqual(schema["properties"]["runtime_validation"]["const"], "NOT_PERFORMED")
        properties = schema["properties"]
        self.assertTrue({"environment", "installation", "attempts", "overall_result", "runtime_evidence_sha256"}.isdisjoint(properties))
        statuses = properties["generation"]["items"]["properties"]["status"]["enum"]
        self.assertEqual(set(statuses), {"GENERATED", "NOT_APPLICABLE", "INSUFFICIENT_EVIDENCE"})

    def test_claude_effort_override_and_environment(self) -> None:
        args = pipeline.build_parser().parse_args([
            "run", "--reasoning-effort", "minimal", "--frida-effort", "high",
        ])
        with mock.patch.dict(pipeline.os.environ, {
            "CODEX_API_KEY": "fake-codex-key", "OPENAI_API_KEY": "fake-openai-key",
            "ANTHROPIC_API_KEY": "fake-anthropic-key", "CLAUDE_CODE_EFFORT_LEVEL": "max",
        }, clear=True):
            self.assertEqual(pipeline.effort_for_stage(pipeline.STAGES["frida"], args), "high")
            env = pipeline.stage_environment(pipeline.STAGES["frida"], "high")
            self.assertNotIn("CODEX_API_KEY", env)
            self.assertNotIn("OPENAI_API_KEY", env)
            self.assertEqual(env["ANTHROPIC_API_KEY"], "fake-anthropic-key")
            self.assertEqual(env["CLAUDE_CODE_EFFORT_LEVEL"], "high")
            self.assertNotIn("ANTHROPIC_API_KEY", pipeline.stage_environment(pipeline.STAGES["static"], "high"))
            args.frida_effort = None
            with self.assertRaisesRegex(pipeline.PipelineError, "does not support"):
                pipeline.effort_for_stage(pipeline.STAGES["frida"], args)

    def test_claude_result_rejects_errors_and_missing_structured_output(self) -> None:
        cases = [
            "not json\n",
            json.dumps({"type": "assistant", "text": "done"}),
            json.dumps({"type": "result", "subtype": "error_max_turns", "is_error": True}),
            json.dumps({"type": "result", "subtype": "success", "structured_output": "{}"}),
            json.dumps({"type": "result", "subtype": "success", "structured_output": {}}),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            events = Path(temporary) / "events.jsonl"
            output = Path(temporary) / "report.json"
            for data in cases:
                with self.subTest(data=data):
                    events.write_text(data)
                    with self.assertRaises(pipeline.PipelineError):
                        pipeline.save_claude_result(events, output)
                    self.assertFalse(output.exists())

    def test_missing_claude_auth_stops_all_before_creating_run(self) -> None:
        args = pipeline.build_parser().parse_args([
            "run", "--stage", "all", "--apk-dir", "apks/example",
        ])
        with mock.patch.object(pipeline, "codex_binary", return_value="codex"), \
             mock.patch.object(pipeline, "claude_binary", return_value="claude"), \
             mock.patch.object(pipeline.subprocess, "run", return_value=mock.Mock(returncode=1, stdout='{"loggedIn":false}')), \
             mock.patch.object(pipeline, "create_run") as create:
            with self.assertRaisesRegex(pipeline.PipelineError, "not authenticated"):
                pipeline.command_run(args)
            create.assert_not_called()

    def test_generation_run_needs_no_dynamic_authorization(self) -> None:
        args = pipeline.build_parser().parse_args(["run", "--stage", "frida", "--run-id", "test"])
        with mock.patch.object(pipeline, "preflight_claude") as preflight, \
             mock.patch.object(pipeline, "execute_stage") as execute, \
             mock.patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(pipeline.command_run(args), 0)
        preflight.assert_called_once()
        execute.assert_called_once()

    def generation_fixture(self, root):
        run_dir = root / "test"
        for folder in ("input", "01-static", "02-frida"):
            (run_dir / folder).mkdir(parents=True)
        pipeline.atomic_json_write(run_dir / "run-state.json", {"stages": {"frida": {"status": "pending"}}})
        application = {"base_apk_sha256": "a" * 64, "package_name": "com.example.test"}
        pipeline.atomic_json_write(run_dir / "input/apk-set.json", application)
        pipeline.atomic_json_write(run_dir / "01-static/static-analysis.json", {
            "run_id": "test", "application": application,
            "protections": [{"category": category, "verdict": "PRESENT"} for category in sorted(pipeline.PROTECTION_CATEGORIES)],
        })
        (run_dir / "01-static/static-analysis.md").write_text("Static report with insufficient target signatures")
        report = {
            "schema_version": "2.0", "run_id": "test", "generated_at": "2026-10-06T10:00:00Z",
            "application": application, "steps_6_7_performed": False,
            "runtime_validation": "NOT_PERFORMED", "fatal_errors": [],
            "limitations": ["Script has not been checked or executed"],
            "generation": [{"category": category, "static_verdict": "PRESENT", "status": "INSUFFICIENT_EVIDENCE",
                            "targets": [], "rationale": "Missing signature in static report", "limitations": ["Missing signature"]}
                           for category in sorted(pipeline.PROTECTION_CATEGORIES)],
        }
        return run_dir, report

    def test_generation_executes_only_one_model_call_and_saves_untested_script(self) -> None:
        for script in ('// No sufficiently specified target in the static report.', 'deliberately invalid JavaScript {'):
            with self.subTest(script=script), tempfile.TemporaryDirectory() as temporary:
                run_dir, report = self.generation_fixture(Path(temporary))

                def simulate_claude(command, **kwargs):
                    self.assertEqual(command[0], "claude")
                    self.assertEqual(command[command.index("--tools") + 1], "")
                    self.assertIn("Static report with insufficient target signatures", kwargs["input"])
                    self.assertIn("com.example.test", kwargs["input"])
                    self.assertNotIn("CONTROLLER PHASE", kwargs["input"])
                    self.assertNotIn(kwargs["input"], command)
                    kwargs["stdout"].write(json.dumps({
                        "type": "result", "subtype": "success", "is_error": False,
                        "structured_output": {**report, "markdown_report": "# Generated script (untested)", "bypass_script": script},
                    }) + "\n")
                    return mock.Mock(returncode=0)

                with mock.patch.object(pipeline, "claude_binary", return_value="claude"), \
                     mock.patch.object(pipeline.subprocess, "run", side_effect=simulate_claude) as run, \
                     mock.patch("sys.stdout", new_callable=io.StringIO):
                    pipeline.execute_stage(pipeline.STAGES["frida"], run_dir, "claude-opus-4-7", "high", False)
                run.assert_called_once()  # No ADB, Frida, Node, or verification subprocess.
                self.assertEqual((run_dir / "02-frida/bypass.js").read_text(), script)
                self.assertEqual(pipeline.load_json(run_dir / "02-frida/frida-bypass-report.json"), report)
                self.assertEqual(pipeline.load_json(run_dir / "run-state.json")["stages"]["frida"]["status"], "completed")
                self.assertFalse((run_dir / "02-frida/frida.log").exists())
                self.assertFalse((run_dir / "02-frida/runtime-evidence.json").exists())
                # Final reporting accepts generation without runtime artifacts.
                pipeline.validate_before_stage("final", run_dir)

    def test_generation_handoff_rejects_inconsistent_metadata_and_runtime_claims(self) -> None:
        cases = [
            (lambda r: r["application"].update(base_apk_sha256="b" * 64), "hash does not match"),
            (lambda r: r["application"].update(package_name="other"), "package name does not match"),
            (lambda r: r.update(run_id="other"), "run_id does not match"),
            (lambda r: r.update(schema_version="1.1"), "generation-only"),
            (lambda r: r.update(runtime_validation="SUCCEEDED"), "must not claim runtime"),
            (lambda r: r.update(installation={"status": "SUCCEEDED"}), "fields do not match"),
            (lambda r: r["generation"].pop(), "categories"),
            (lambda r: r["generation"][0].update(static_verdict="ABSENT"), "static verdict"),
            (lambda r: r["generation"][0].update(status="SUCCEEDED"), "generation status"),
            (lambda r: r["generation"][0].update(status="GENERATED"), "require targets"),
            (lambda r: r["generation"][0].update(hook_invoked=True), "entry fields"),
        ]
        for mutate, error in cases:
            with self.subTest(error=error), tempfile.TemporaryDirectory() as temporary:
                run_dir, report = self.generation_fixture(Path(temporary))
                (run_dir / "02-frida/bypass.js").write_text("// Untested")
                (run_dir / "02-frida/frida-bypass-report.md").write_text("Untested")
                mutate(report)
                pipeline.atomic_json_write(run_dir / "02-frida/frida-bypass-report.json", report)
                with self.assertRaisesRegex(pipeline.PipelineError, error):
                    pipeline.validate_frida_handoff(run_dir)

    def test_generation_missing_script_marks_stage_failed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir, report = self.generation_fixture(Path(temporary))

            def invoke(command, events_path, effort):
                events_path.write_text(json.dumps({"type": "result", "subtype": "success",
                    "structured_output": {**report, "markdown_report": "Notes", "bypass_script": " "}}))

            with mock.patch.object(pipeline, "invoke_claude", side_effect=invoke), \
                 mock.patch("sys.stdout", new_callable=io.StringIO):
                with self.assertRaisesRegex(pipeline.PipelineError, "omitted bypass_script"):
                    pipeline.execute_stage(pipeline.STAGES["frida"], run_dir, "claude-opus-4-7", "high", False)
            self.assertEqual(pipeline.load_json(run_dir / "run-state.json")["stages"]["frida"]["status"], "failed")
            self.assertFalse((run_dir / "02-frida/bypass.js").exists())

    def test_static_handoff_rejects_missing_categories(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary) / "run-one"
            (run_dir / "input").mkdir(parents=True)
            (run_dir / "01-static").mkdir()
            inventory = {"base_apk_sha256": "a" * 64}
            report = {
                "run_id": "run-one",
                "application": {"base_apk_sha256": "a" * 64},
                "protections": [],
            }
            (run_dir / "input/apk-set.json").write_text(json.dumps(inventory))
            (run_dir / "01-static/static-analysis.json").write_text(json.dumps(report))
            (run_dir / "01-static/static-analysis.md").write_text("report")
            with self.assertRaisesRegex(pipeline.PipelineError, "categories mismatch"):
                pipeline.validate_static_handoff(run_dir)

    def test_doctor_has_no_device_or_script_runtime_dependencies(self) -> None:
        with mock.patch.object(pipeline, "availability", return_value=(True, "available")) as available, \
             mock.patch.object(pipeline, "preflight_claude"), \
             mock.patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(pipeline.command_doctor(None), 0)
        names = {Path(call.args[0]).name for call in available.call_args_list}
        self.assertTrue({"adb", "frida", "frida-ps", "node", "weasyprint"}.isdisjoint(names))

    def test_evidence_path_cannot_escape_stage_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            stage_dir = Path(temporary) / "stage"
            stage_dir.mkdir()
            report = {"finding": {"evidence": [{"path": "../secret", "line": None}]}}
            with self.assertRaisesRegex(pipeline.PipelineError, "escape"):
                pipeline.validate_evidence_paths(report, stage_dir)


if __name__ == "__main__":
    unittest.main()
