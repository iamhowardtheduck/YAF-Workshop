# Add sdg user with superuser role
curl -X POST "http://localhost:30920/_security/user/instruqt" -H "Content-Type: application/json" -u "elastic:${ELASTICSEARCH_PASSWORD}" -d '{
  "password" : "workshops",
  "roles" : [ "superuser" ],
  "full_name" : "Instruqt Workshop",
  "email" : "Instruqt-Workshop@omnicorp.co"
}'

# Load ingest pipelines
curl -X PUT "http://localhost:30920/_ingest/pipeline/netflow-redate" -H "Content-Type: application/x-ndjson" -u "elastic:${ELASTICSEARCH_PASSWORD}" -d @/root/YAF-Workshop/Ingest-Pipelines/netflow-redate.json

# Start data-gen
pip install pandas numpy elasticsearch faker
python3 /root/YAF-Workshop/Scripts/e1e_instruqt.py
