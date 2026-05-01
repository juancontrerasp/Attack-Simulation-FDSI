# ST-10.1 — Multi-stage build: elimina fuentes .java de la imagen final
FROM eclipse-temurin:17-jdk AS builder
WORKDIR /app
RUN mkdir -p lib && \
    apt-get update -qq && apt-get install -y -qq wget && \
    wget -q https://repo1.maven.org/maven2/org/yaml/snakeyaml/2.2/snakeyaml-2.2.jar -O lib/snakeyaml-2.2.jar
COPY AttackEngine.java .
COPY attacks/ ./attacks/
COPY config/ ./config/
COPY model/ ./model/
COPY util/ ./util/
RUN mkdir -p out && \
    find . -name '*.java' | xargs javac -cp lib/snakeyaml-2.2.jar -d out/

FROM eclipse-temurin:17-jre
WORKDIR /app
COPY --from=builder /app/out/ ./out/
COPY --from=builder /app/lib/ ./lib/
ARG TARGET_URL=http://localhost:8080
ENV TARGET_URL=${TARGET_URL}
VOLUME ["/app/config", "/app/output"]
ENTRYPOINT ["java", "-cp", "out:lib/snakeyaml-2.2.jar", "AttackEngine"]
