import os
import subprocess
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
IPGREP = PROJECT_ROOT / "ipgrep"
FIXTURES = Path(__file__).resolve().parent / "fixtures"


class IpGrepFunctionalTests(unittest.TestCase):
    def run_ipgrep(self, *args, input_text="", env=None):
        if not IPGREP.exists():
            self.fail("ipgrep is not built; run 'make' before the functional tests")

        process_env = os.environ.copy()
        if env:
            process_env.update(env)

        return subprocess.run(
            [str(IPGREP), *args],
            cwd=PROJECT_ROOT,
            input=input_text,
            text=True,
            capture_output=True,
            env=process_env,
        )

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(result.stderr, "")

    def test_reads_stdin_and_reports_positions(self):
        result = self.run_ipgrep(
            input_text="src=192.168.1.10\ndst=10.1.2.3"
        )

        self.assert_success(result)
        self.assertEqual(
            result.stdout,
            "1:5:192.168.1.10\n"
            "2:5:10.1.2.3\n",
        )

    def test_reads_input_file(self):
        result = self.run_ipgrep(
            "-f", str(FIXTURES / "input.txt")
        )

        self.assert_success(result)
        self.assertEqual(
            result.stdout,
            "1:5:192.168.1.10\n"
            "2:5:10.1.2.3\n"
            "3:6:10.1.0.0/16\n",
        )

    def test_explicit_stdin_file_argument(self):
        result = self.run_ipgrep(
            "-f", "-", input_text="value=10.2.3.4\n"
        )

        self.assert_success(result)
        self.assertEqual(result.stdout, "1:7:10.2.3.4\n")

    def test_inline_network_filter(self):
        result = self.run_ipgrep(
            "-n", "10.0.0.0/8",
            input_text="src=192.168.1.10\n"
                        "dst=10.1.2.3\n"
                        "cidr=10.1.0.0/16\n",
        )

        self.assert_success(result)
        self.assertEqual(
            result.stdout,
            "2:5:10.1.2.3\n"
            "3:6:10.1.0.0/16\n",
        )

    def test_filter_file(self):
        result = self.run_ipgrep(
            "-f", str(FIXTURES / "input.txt"),
            "-nf", str(FIXTURES / "network-filters.txt"),
        )

        self.assert_success(result)
        self.assertEqual(
            result.stdout,
            "1:5:192.168.1.10\n"
            "2:5:10.1.2.3\n"
            "3:6:10.1.0.0/16\n",
        )

    def test_network_filter_uses_detected_address(self):
        result = self.run_ipgrep(
            "-n", "172.16.4.12/30",
            input_text="value=172.16.4.12/24\n",
        )

        self.assert_success(result)
        self.assertEqual(result.stdout, "1:7:172.16.4.12/24\n")

    def test_subnet_coverage_reports_matches_and_uncovered_targets(self):
        result = self.run_ipgrep(
            "-f", str(FIXTURES / "routes.txt"),
            "-s", "10.1.0.2,172.16.4.0/24,10.2.0.0/16",
        )

        self.assert_success(result)
        self.assertEqual(
            result.stdout,
            "M,1,7:10.1.0.0/16\n"
            "M,2,7:172.16.4.0/24\n"
            "U,10.2.0.0/16\n",
        )

    def test_trie_mode_matches_list_mode(self):
        args = (
            "-f", str(FIXTURES / "input.txt"),
            "-n", "10.0.0.0/8,192.168.1.0/24",
        )
        list_result = self.run_ipgrep(*args)
        trie_result = self.run_ipgrep(*args, env={"IPGREP_USE_TRIE": "1"})

        self.assert_success(list_result)
        self.assert_success(trie_result)
        self.assertEqual(trie_result.stdout, list_result.stdout)

    def test_match_can_cross_read_buffer_boundary(self):
        input_text = "x" * 4094 + "10.0.0.1\n"
        result = self.run_ipgrep(input_text=input_text)

        self.assert_success(result)
        self.assertEqual(result.stdout, "1:4095:10.0.0.1\n")

    def test_invalid_filter_returns_error(self):
        result = self.run_ipgrep(
            "-n", "10.0.0.0/33", input_text="value=10.0.0.1\n"
        )

        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("Invalid IP/CIDR input", result.stderr)

    def test_network_and_subnet_filters_are_mutually_exclusive(self):
        result = self.run_ipgrep(
            "-n", "10.0.0.0/8",
            "-s", "10.0.0.0/8",
        )

        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("Usage:", result.stderr)

    def test_filter_file_is_read_as_a_file(self):
        with tempfile.TemporaryDirectory() as directory:
            filter_path = Path(directory) / "filters.txt"
            filter_path.write_text("192.168.0.0/16, 10.0.0.0/8\n")

            result = self.run_ipgrep(
                "-f", str(FIXTURES / "input.txt"),
                "-nf", str(filter_path),
            )

        self.assert_success(result)
        self.assertEqual(
            result.stdout,
            "1:5:192.168.1.10\n"
            "2:5:10.1.2.3\n"
            "3:6:10.1.0.0/16\n",
        )


if __name__ == "__main__":
    unittest.main()
