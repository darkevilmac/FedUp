plugins {
    id("java")
    id("application")
}

group = "com.tridevmc"
version = "0"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.9.1"))
    testImplementation("org.junit.jupiter:junit-jupiter")

    // We need to add fedup-extract as a dependency as it has some data classes.
    implementation(project(":fedup-extract"))

    // Guava
    implementation("com.google.guava:guava:32.0.1-jre")

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

tasks.test {
    useJUnitPlatform()
}