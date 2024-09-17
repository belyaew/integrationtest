plugins {
	java
	id("org.springframework.boot") version "3.3.3"
	id("io.spring.dependency-management") version "1.1.6"
}

group = "com.example"
version = "0.0.1-SNAPSHOT"

java {
	toolchain {
		languageVersion = JavaLanguageVersion.of(17)
	}
}

repositories {
	mavenCentral()
}

dependencies {
	// https://mvnrepository.com/artifact/org.apache.http/httpcore
	implementation("org.apache.http:httpcore:4.0.1")

	// https://mvnrepository.com/artifact/commons-io/commons-io
	implementation("commons-io:commons-io:2.16.1")
	// https://mvnrepository.com/artifact/org.apache.commons/commons-collections4
	implementation("org.apache.commons:commons-collections4:4.4")
	// https://mvnrepository.com/artifact/org.junit.jupiter/junit-jupiter-api
	implementation("org.junit.jupiter:junit-jupiter-api:5.11.0")
	// https://mvnrepository.com/artifact/org.apache.commons/commons-lang3
	implementation("org.apache.commons:commons-lang3:3.12.0")
	// https://mvnrepository.com/artifact/io.qameta.allure/allure-junit5
	implementation("io.qameta.allure:allure-junit5:2.29.0")
	implementation("org.springframework.boot:spring-boot-starter-web")
	testImplementation("org.springframework.boot:spring-boot-starter-test")
	testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<Test> {
	useJUnitPlatform()
}
