import tempfile
import unittest
from pathlib import Path

from auto_surface.analyzer import analyze, parse_file


class AutoSurfaceTests(unittest.TestCase):
    def test_candump_and_uds_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.log"
            path.write_text("(1.0) can0 7E0#02270100\n(1.1) can0 7E8#067F2735\n")
            records, errors = parse_file(str(path))
        self.assertEqual(len(records), 2)
        self.assertFalse(errors)
        result = analyze(records)
        self.assertEqual(result["frames"], 2)
        self.assertTrue(any(x["name"] == "SecurityAccess" for x in result["uds_services"]))
        self.assertTrue(any(x["name"].startswith("NegativeResponse") for x in result["uds_services"]))

    def test_variable_length_is_review_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.csv"
            path.write_text("timestamp,arbitration_id,data\n1,123,0102\n2,123,01020304\n")
            records, errors = parse_file(str(path))
        self.assertEqual(len(records), 2)
        self.assertFalse(errors)
        self.assertEqual(result := analyze(records)["anomalies"][0]["type"], "variable_payload_length")


if __name__ == "__main__":
    unittest.main()
