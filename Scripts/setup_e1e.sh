# Load ingest pipelines
curl -X PUT "http://localhost:30920/_ingest/pipeline/netflow-redate" -H "Content-Type: application/x-ndjson" -u "elastic:${ELASTICSEARCH_PASSWORD}" -d @/root/YAF-Workshop/Ingest-Pipelines/netflow-redate.json

# Start data-gen
pip install pandas numpy elasticsearch
python3 /root/YAF-Workshop/Scripts/e1e_instruqt.py
