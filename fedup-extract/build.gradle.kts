plugins {
    id("java")
    id("application")
}

group = "com.tridevmc"
version = "0"

repositories {
    mavenCentral()
    // Android SDK
    google()
}

dependencies {
    repositories {
        mavenCentral()
        // Android SDK
        google()
    }

    testImplementation(platform("org.junit:junit-bom:5.9.1"))
    testImplementation("org.junit.jupiter:junit-jupiter")

    // Guava
    implementation("com.google.guava:guava:32.0.1-jre")

    // JADX
    implementation("io.github.skylot:jadx-core:1.4.7")
    implementation("io.github.skylot:jadx-dex-input:1.4.7")

    // GSON
    implementation("com.google.code.gson:gson:2.10.1")

    // TinyLog
    implementation("org.tinylog:tinylog-api:2.6.2")
    implementation("org.tinylog:tinylog-impl:2.6.2")
    implementation("org.tinylog:slf4j-tinylog:2.6.2")

    // PicoCLI
    implementation("info.picocli:picocli:4.7.4")
    annotationProcessor("info.picocli:picocli-codegen:4.7.4")
}

tasks.withType<JavaCompile> {
    options.compilerArgs.addAll(listOf("-Aproject=${project.group}/${project.name}"))
}

application {
    mainClass.set("com.tridevmc.fedup.extract.FedUpExtractCLI")
}

tasks.test {
    useJUnitPlatform()
}