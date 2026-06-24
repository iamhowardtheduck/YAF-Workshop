#!/usr/bin/env python3
"""
Synthetic event generator for the `e1e-instruqt` data stream.

Produces ECS-aligned netflow / network-security records (DNS, HTTP, TLS, FTP,
SMTP/email, flow stats) matching the supplied mapping and bulk-ships them to
Elasticsearch.

Auth: basic auth (username/password) against an ephemeral VM cluster, read from
the standard Instruqt-style environment variables:
    ELASTICSEARCH_URL       (default http://localhost:30920)
    ELASTICSEARCH_PASSWORD  (required unless --dry-run)
    ELASTICSEARCH_USERNAME  (default "elastic")

Usage:
    # env vars ELASTICSEARCH_URL / ELASTICSEARCH_PASSWORD already exported in VM
    python generate_e1e_instruqt.py --count 5000 --batch 500

    # dry run (print sample docs, no shipping)
    python generate_e1e_instruqt.py --count 3 --dry-run
"""

import argparse
import os
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone

try:
    from elasticsearch import Elasticsearch, helpers
except ImportError:
    Elasticsearch = None
    helpers = None

# Ephemeral VM may use http or a self-signed cert; quiet the TLS warning.
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

from faker import Faker

fake = Faker()

DATA_STREAM = "e1e-instruqt"
ECS_VERSION = "8.17.0"
AGENT_VERSION = "8.12.0"

PROTOCOLS = ["dns", "http", "tls", "ftp", "smtp", "flow"]
PROTO_WEIGHTS = [0.25, 0.30, 0.20, 0.05, 0.10, 0.10]

DNS_QTYPES = ["A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT"]
DNS_RCODES = ["NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED"]
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]
HTTP_STATUS = ["200", "201", "204", "301", "302", "304", "400", "401", "403", "404", "500", "502"]
MIME_TYPES = ["text/html", "application/json", "image/png", "text/css",
              "application/javascript", "application/octet-stream"]
TLS_VERSIONS = ["1.0", "1.1", "1.2", "1.3"]
TCP_FLAGS = ["S", "SA", "A", "PA", "FA", "R", "RA", "FPA"]
SENSOR_TYPES = ["yaf", "super_mediator", "pmacct", "netflow-v9"]
EXPORTERS = ["sensor-edge-01", "sensor-core-02", "sensor-dmz-03"]

# Pools to create realistic repetition / entity correlation
SRC_IPS = [fake.ipv4() for _ in range(40)]
DST_IPS = [fake.ipv4() for _ in range(60)]
DOMAINS = [fake.domain_name() for _ in range(50)]
HOSTS = [f"host-{i:03d}" for i in range(1, 26)]
USER_AGENTS = [fake.user_agent() for _ in range(15)]


def now_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def epoch_millis(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)


def mac() -> str:
    return ":".join(f"{random.randint(0,255):02x}" for _ in range(6))


def base_doc(ts: datetime) -> dict:
    src_ip = random.choice(SRC_IPS)
    dst_ip = random.choice(DST_IPS)
    src_port = random.randint(1024, 65535)
    dst_port = random.choice([53, 80, 443, 21, 25, 8080, 22, 3389, random.randint(1, 65535)])
    duration = random.randint(1, 5_000_000)  # ns-ish
    start = ts
    end = ts + timedelta(milliseconds=random.randint(1, 30000))

    return {
        "@timestamp": now_iso(ts),
        "ecs": {"version": ECS_VERSION},
        "agent": {
            "ephemeral_id": str(uuid.uuid4()),
            "id": str(uuid.uuid4()),
            "name": random.choice(EXPORTERS),
            "type": "filebeat",
            "version": AGENT_VERSION,
        },
        "data_stream": {"dataset": DATA_STREAM, "namespace": "default"},
        "host": {"name": random.choice(HOSTS)},
        "input": {"type": "netflow"},
        "observer": {
            "name": random.choice(EXPORTERS),
            "egress": {"interface": {"id": str(random.randint(1, 8))}},
            "ingress": {"interface": {"id": str(random.randint(1, 8))}},
        },
        "labels": {
            "sensorType": random.choice(SENSOR_TYPES),
            "observation_domain_id": str(random.randint(1, 10)),
            "silkapplabel": str(dst_port),
            "ip_class_of_service": str(random.randint(0, 7)),
        },
        "source": {
            "ip": src_ip,
            "address": src_ip,
            "port": src_port,
            "mac": mac(),
            "bytes": random.randint(40, 1_500_000),
            "bytes_Reverse": random.randint(40, 1_500_000),
            "Tcp_flags": {
                "initial": random.choice(TCP_FLAGS),
                "union": random.choice(TCP_FLAGS),
            },
            "tcpSequenceNumber": str(random.randint(0, 2**32 - 1)),
        },
        "destination": {
            "ip": dst_ip,
            "address": dst_ip,
            "port": dst_port,
            "mac": mac(),
            "packets": random.randint(1, 5000),
            "Tcp_flags": {"union": random.choice(TCP_FLAGS)},
        },
        "network": {
            "iana_number": str(random.choice([6, 17, 1])),
            "packets": random.randint(1, 5000),
            "vlan": {"id": str(random.randint(1, 4094))},
        },
        "event": {
            "duration": duration,
            "start": now_iso(start),
            "end": now_iso(end),
            "Delta_ms": random.randint(0, 30000),
        },
        "netflowId": str(uuid.uuid4()),
        "flowStartDate": ts.strftime("%Y-%m-%d"),
        "retry": False,
    }


def add_dns(doc: dict):
    qname = random.choice(DOMAINS)
    doc["event"]["category"] = "network"
    doc["event"]["type"] = "protocol"
    doc["dns"] = {
        "ID": str(random.randint(1, 65535)),
        "id": str(random.randint(1, 65535)),
        "QName": qname,
        "QRType": random.choice(DNS_QTYPES),
        "response_code": random.choice(DNS_RCODES),
        "question": {"name": qname},
        "A": fake.ipv4() if random.random() > 0.3 else None,
        "TTL": str(random.choice([60, 300, 3600, 86400])),
        "answers": {"ttl": str(random.choice([60, 300, 3600]))},
    }
    doc["dns"] = {k: v for k, v in doc["dns"].items() if v is not None}


def add_http(doc: dict):
    doc["event"]["category"] = "web"
    doc["event"]["type"] = "access"
    ua = random.choice(USER_AGENTS)
    doc["http"] = {
        "Host": random.choice(DOMAINS),
        "version": random.choice(["1.0", "1.1", "2"]),
        "Connection": random.choice(["keep-alive", "close"]),
        "request": {
            "method": random.choice(HTTP_METHODS),
            "referer": f"https://{random.choice(DOMAINS)}/",
            "Header": {
                "accept": "text/html,application/xhtml+xml",
                "host": random.choice(DOMAINS),
                "x-Forwarded-For": random.choice(SRC_IPS),
            },
        },
        "response": {
            "status_code": random.choice(HTTP_STATUS),
            "mime_type": random.choice(MIME_TYPES),
            "Header": {
                "server": random.choice(["nginx", "apache", "cloudflare", "envoy"]),
                "bytes": str(random.randint(100, 500000)),
            },
        },
        "user_agent": {"original": ua},
    }
    doc["user_agent"] = {"original": ua}


def add_tls(doc: dict):
    doc["event"]["category"] = "network"
    doc["event"]["type"] = "connection"
    sni = random.choice(DOMAINS)
    doc["tls"] = {
        "version": random.choice(TLS_VERSIONS),
        "Record_version": random.choice([769, 770, 771, 772]),
        "ServerCipher": random.randint(1, 60000),
        "Compression_method": random.choice([0, 1]),
        "client": {
            "server_name": sni,
            "x509": {
                "subject": {"common_name": sni, "organization": fake.company(),
                            "country": fake.country_code()},
                "issuer": {"common_name": random.choice(
                    ["DigiCert CA", "Let's Encrypt R3", "GlobalSign"]),
                    "organization": fake.company()},
                "not_before": fake.date_time_this_year().isoformat(),
                "not_after": fake.date_time_this_year().isoformat(),
                "serial_number": uuid.uuid4().hex,
                "public_key_algorithm": random.choice(["RSA", "EC"]),
                "public_key_size": str(random.choice([2048, 256, 384, 4096])),
            },
        },
        "sslClientJA3": uuid.uuid4().hex,
        "sslServerJA3S": uuid.uuid4().hex,
    }


def add_ftp(doc: dict):
    doc["event"]["category"] = "file"
    doc["event"]["type"] = "access"
    doc["ftp"] = {
        "User_name": fake.user_name(),
        "User_password": "********",
        "Data_type": random.choice(["ASCII", "Binary", "Image"]),
        "Response_code": random.choice(["200", "230", "331", "425", "530"]),
        "Return": random.choice(["RETR", "STOR", "LIST", "PASV", "USER"]),
    }


def add_email(doc: dict):
    doc["event"]["category"] = "email"
    doc["event"]["type"] = "info"
    frm = fake.email()
    to = fake.email()
    doc["email"] = {
        "from": {"address": frm},
        "to": {"address": to},
        "subject": fake.sentence(nb_words=6),
        "content_type": random.choice(["text/plain", "text/html", "multipart/mixed"]),
        "Size": str(random.randint(500, 5_000_000)),
        "Hello": fake.domain_name(),
        "Response": random.choice(["250 OK", "550 No such user", "421 Service unavailable"]),
        "attachments": {"file": {"name": fake.file_name()}} if random.random() > 0.6 else {},
    }


def add_flow_stats(doc: dict):
    doc["event"]["category"] = "network"
    doc["event"]["type"] = "connection"
    doc["stats"] = {
        "packetTotalCount": random.randint(1, 1_000_000),
        "droppedPacketTotalCount": random.randint(0, 500),
        "ignoredPacketTotalCount": random.randint(0, 200),
        "exportedFlowTotalCount": random.randint(1, 100000),
        "flowTablePeakCount": random.randint(1, 50000),
        "meanFlowRate": random.randint(0, 100000),
        "meanPacketRate": random.randint(0, 1_000_000),
        "exporterName": random.choice(EXPORTERS),
        "exporterIPv4Address": fake.ipv4(),
        "observationDomainId": random.randint(1, 10),
        "exportingProcessId": random.randint(1000, 9999),
    }


PROTO_FUNCS = {
    "dns": add_dns,
    "http": add_http,
    "tls": add_tls,
    "ftp": add_ftp,
    "smtp": add_email,
    "flow": add_flow_stats,
}


def make_doc(ts: datetime) -> dict:
    doc = base_doc(ts)
    proto = random.choices(PROTOCOLS, weights=PROTO_WEIGHTS, k=1)[0]
    PROTO_FUNCS[proto](doc)
    doc["tags"] = [proto, "synthetic", "instruqt"]
    return doc


def gen_docs(count: int, span_minutes: int):
    start = datetime.now(timezone.utc) - timedelta(minutes=span_minutes)
    for i in range(count):
        offset = (span_minutes * 60) * (i / max(count, 1))
        ts = start + timedelta(seconds=offset + random.uniform(0, 1))
        yield make_doc(ts)


def main():
    p = argparse.ArgumentParser(description="Generate events for the e1e-instruqt data stream")
    p.add_argument("--count", type=int, default=1000, help="number of events")
    p.add_argument("--batch", type=int, default=500, help="bulk batch size")
    p.add_argument("--span-minutes", type=int, default=60,
                   help="spread timestamps over the last N minutes")
    p.add_argument("--index", default=DATA_STREAM, help="target data stream / index")
    p.add_argument("--dry-run", action="store_true", help="print sample docs, do not ship")
    args = p.parse_args()

    if args.dry_run:
        import json
        for d in gen_docs(min(args.count, 5), args.span_minutes):
            print(json.dumps(d, indent=2))
        return

    if Elasticsearch is None:
        sys.exit("elasticsearch package not installed. Run: pip install elasticsearch")

    es_url = os.environ.get("ELASTICSEARCH_URL", "http://localhost:30920")
    username = os.environ.get("ELASTICSEARCH_USERNAME", "elastic")
    password = os.environ.get("ELASTICSEARCH_PASSWORD")
    if not password:
        sys.exit("Set ELASTICSEARCH_PASSWORD (and optionally ELASTICSEARCH_URL / "
                 "ELASTICSEARCH_USERNAME) environment variables.")

    es = Elasticsearch(
        es_url,
        basic_auth=(username, password),
        request_timeout=30,
        verify_certs=False,   # ephemeral VM, http/self-signed friendly
    )

    info = es.info()
    print(f"Connected to {es_url} | cluster '{info['cluster_name']}' "
          f"| version {info['version']['number']}")

    def actions():
        for doc in gen_docs(args.count, args.span_minutes):
            # create op -> required for data streams (append-only)
            yield {"_op_type": "create", "_index": args.index, "_source": doc}

    ok, errors = 0, []
    for success, info in helpers.streaming_bulk(
        es, actions(), chunk_size=args.batch, raise_on_error=False
    ):
        if success:
            ok += 1
        else:
            errors.append(info)

    print(f"Indexed {ok}/{args.count} into '{args.index}'")
    if errors:
        print(f"{len(errors)} errors; first: {errors[0]}")


if __name__ == "__main__":
    main()
