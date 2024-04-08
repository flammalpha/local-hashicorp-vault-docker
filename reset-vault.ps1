# stop container
docker compose stop
# delete data
remove-item -Recurse -Force ~/.vault-data/*
# start container
docker compose up -d