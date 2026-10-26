# Stage 1 : Build
FROM maven:3.9-eclipse-temurin-21-alpine AS builder

WORKDIR /build
COPY pom.xml .
RUN mvn dependency:go-offline -q
COPY src ./src
RUN mvn package -DskipTests -q

# Stage 2 : Runtime
FROM eclipse-temurin:21-jre-alpine AS runtime

RUN addgroup -S securevault && adduser -S securevault -G securevault

WORKDIR /app
COPY --from=builder /build/target/*.jar app.jar
RUN chown -R securevault:securevault /app

USER securevault
EXPOSE 8080

ENTRYPOINT ["java", \
  "-XX:+UseContainerSupport", \
  "-XX:MaxRAMPercentage=75.0", \
  "-Djava.security.egd=file:/dev/./urandom", \
  "-Dfile.encoding=UTF-8", \
  "-jar", "app.jar"]