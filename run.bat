docker volume prune -f
docker image rm ctfthingy_webapp -f
docker image prune -f
docker-compose rm -f
docker-compose build
docker-compose up