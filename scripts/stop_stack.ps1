# Stop Sentinel's optional Elastic/Kibana Docker Compose stack.
#
# This script is a developer utility for the future Elastic/Kibana version
# of Sentinel.
#
# It is not required for the current file scanner UI.
# The current scanner uses Docker directly for:
# - the custom sentinel-scanner image
# - the ClamAV Docker image
#
# This script only applies if a docker-compose.yml file exists at:
#     backend/docker-compose.yml
#
# The command below stops and removes the containers created by that compose file.

docker compose -f .\backend\docker-compose.yml down