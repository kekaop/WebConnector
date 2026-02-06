plugins {
    id("java")
}

group = "com.eldryn"
version = "1.0.2"

repositories {
    mavenCentral()
    maven("https://repo.papermc.io/repository/maven-public/")
}

dependencies {
    add("compileOnly", "io.papermc.paper:paper-api:1.21.1-R0.1-SNAPSHOT")
    add("compileOnly", "com.google.code.gson:gson:2.10.1")
}

extensions.configure(org.gradle.api.plugins.JavaPluginExtension::class.java) {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
}

tasks.withType<JavaCompile> {
    options.encoding = "UTF-8"
}
