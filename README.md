1. First way to run
- Install maven and jdk
- mvn clean package
- java -jar target/quantile-0.0.1-SNAPSHOT.jar

2. Second way to run
- Install docker
- docker-compose up -d

3. Run following command to test
```
curl --location --request POST 'http://localhost:8080/create' \
--header 'Content-Type: application/json' \
--data-raw '{
    "poolId": 2,
    "poolValues": [3, 1, 2, 0, 4, 5, 9, 7, 8, 6]
}'
```

```
curl --location --request POST 'http://localhost:8080/get' \
--header 'Content-Type: application/json' \
--data-raw '{
    "poolId": 2,
    "percentile": 76
}'
```