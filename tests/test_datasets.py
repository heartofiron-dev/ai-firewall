import csv
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

from ai_firewall.cli import run_convert_dataset
from ai_firewall.datasets import UNSW_NB15_RAW_COLUMNS, iter_dataset
from ai_firewall.io import FLOW_COLUMNS, read_flows, write_flows_csv


CIC_COLUMNS = [
    "Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol",
    "Timestamp", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "SYN Flag Count",
    "RST Flag Count", "Label",
]

UNSW_COLUMNS = [
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes",
    "dbytes", "Spkts", "Dpkts", "stime", "attack_cat", "Label",
]


def write_rows(path: Path, columns: list[str], rows: list[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


class DatasetTests(unittest.TestCase):
    def test_converts_cicids_units_labels_and_rolling_context(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "cic.csv"
            base = {
                "Source IP": "10.0.0.5", "Destination IP": "192.0.2.10",
                "Source Port": 50000, "Destination Port": 80, "Protocol": 6,
                "Timestamp": "07/07/2017 08:00:00", "Flow Duration": 2500,
                "Total Fwd Packets": 2, "Total Backward Packets": 3,
                "Total Length of Fwd Packets": 120, "Total Length of Bwd Packets": 240,
                "SYN Flag Count": 1, "RST Flag Count": 0, "Label": "BENIGN",
            }
            second = base | {
                "Destination Port": 22, "Timestamp": "07/07/2017 08:00:30",
                "RST Flag Count": 1, "Label": "SSH-Patator",
            }
            write_rows(source, CIC_COLUMNS, [base, second])
            flows = list(iter_dataset("cicids2017", source, timestamp_format="%m/%d/%Y %H:%M:%S"))

        self.assertEqual(flows[0].duration_ms, 2.5)
        self.assertEqual(flows[0].packets, 5)
        self.assertEqual(flows[0].label, "benign")
        self.assertEqual(flows[1].label, "attack")
        self.assertEqual(flows[1].unique_dst_ports_60s, 2)
        self.assertEqual(flows[1].connections_60s, 2)
        self.assertEqual(flows[1].failed_connections_60s, 1)

    def test_converts_unsw_epoch_hex_port_and_round_trips_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "unsw.csv"
            output = Path(directory) / "flows.csv"
            rows = [{
                "srcip": "10.0.0.8", "sport": "0xc350", "dstip": "198.51.100.4",
                "dsport": "443", "proto": "tcp", "state": "FIN", "dur": "0.125",
                "sbytes": "400", "dbytes": "800", "Spkts": "4", "Dpkts": "6",
                "stime": "1700000000", "attack_cat": "Normal", "Label": "0",
            }]
            write_rows(source, UNSW_COLUMNS, rows)
            count = write_flows_csv(iter_dataset("unsw-nb15", source), output)
            flows = read_flows(output)
            with output.open(encoding="utf-8", newline="") as handle:
                output_columns = set(csv.DictReader(handle).fieldnames or [])

        self.assertEqual(count, 1)
        self.assertEqual(output_columns, set(FLOW_COLUMNS))
        self.assertEqual(flows[0].src_port, 50000)
        self.assertEqual(flows[0].duration_ms, 125.0)
        self.assertEqual(flows[0].packets, 10)
        self.assertEqual(flows[0].label, "benign")

    def test_converts_official_headerless_unsw_raw_layout(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "UNSW-NB15_1.csv"
            row = {column: "0" for column in UNSW_NB15_RAW_COLUMNS}
            row.update({
                "srcip": "10.0.0.8", "sport": "12345", "dstip": "203.0.113.9",
                "dsport": "53", "proto": "udp", "state": "CON", "dur": "0.5",
                "sbytes": "100", "dbytes": "200", "Spkts": "2", "Dpkts": "3",
                "Stime": "1700000000", "attack_cat": "Generic", "Label": "1",
            })
            with source.open("w", encoding="utf-8", newline="") as handle:
                csv.writer(handle).writerow([row[column] for column in UNSW_NB15_RAW_COLUMNS])
            flows = list(iter_dataset("unsw-nb15", source))

        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].protocol, "UDP")
        self.assertEqual(flows[0].bytes_total, 300)
        self.assertEqual(flows[0].label, "attack")

    def test_rejects_missing_identifiers_and_non_finite_values(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "bad.csv"
            columns = [column for column in CIC_COLUMNS if column != "Source IP"]
            row = {column: "1" for column in columns}
            write_rows(source, columns, [row])
            with self.assertRaisesRegex(ValueError, "src_ip"):
                list(iter_dataset("cicids2017", source))

            row = {column: "1" for column in CIC_COLUMNS}
            row.update({
                "Source IP": "10.0.0.1", "Destination IP": "10.0.0.2",
                "Timestamp": "2026-01-01T00:00:00", "Flow Duration": "Infinity",
            })
            write_rows(source, CIC_COLUMNS, [row])
            with self.assertRaisesRegex(ValueError, "有限非负数"):
                list(iter_dataset("cicids2017", source))

    def test_rejects_per_source_time_reversal(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "unsorted.csv"
            base = {
                "srcip": "10.0.0.8", "sport": 50000, "dstip": "198.51.100.4",
                "dsport": 443, "proto": "tcp", "state": "FIN", "dur": 1,
                "sbytes": 10, "dbytes": 20, "Spkts": 1, "Dpkts": 1,
                "stime": 200, "attack_cat": "Normal", "Label": 0,
            }
            write_rows(source, UNSW_COLUMNS, [base, base | {"stime": 100}])
            with self.assertRaisesRegex(ValueError, "时间倒退"):
                list(iter_dataset("unsw-nb15", source))

    def test_cli_refuses_to_overwrite_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "cic.csv"
            output = Path(directory) / "existing.csv"
            row = {
                "Source IP": "10.0.0.1", "Destination IP": "10.0.0.2",
                "Source Port": 12345, "Destination Port": 443, "Protocol": 6,
                "Timestamp": "2026-01-01T00:00:00", "Flow Duration": 1000,
                "Total Fwd Packets": 1, "Total Backward Packets": 1,
                "Total Length of Fwd Packets": 10, "Total Length of Bwd Packets": 20,
                "SYN Flag Count": 1, "RST Flag Count": 0, "Label": "BENIGN",
            }
            write_rows(source, CIC_COLUMNS, [row])
            output.write_text("keep me", encoding="utf-8")
            args = Namespace(
                format="cicids2017", input=str(source), output=str(output),
                timestamp_format=None, max_rows=None, overwrite=False,
            )
            with self.assertRaisesRegex(ValueError, "输出文件已存在"):
                run_convert_dataset(args)
            self.assertEqual(output.read_text(encoding="utf-8"), "keep me")


if __name__ == "__main__":
    unittest.main()
