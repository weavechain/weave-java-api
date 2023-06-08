import com.github.jk1.license.filter.DependencyFilter
import com.github.jk1.license.filter.LicenseBundleNormalizer

group = "com.weavechain"
version = "1.39"

plugins {
    java
    `maven-publish`
    id("org.jetbrains.dokka") version "1.8.20"
    id("com.github.jk1.dependency-license-report") version "2.4"
    id("io.github.gradle-nexus.publish-plugin") version "1.3.0"
    signing

    id("java-library")
}

repositories {
    java

    mavenCentral()
    maven("https://jitpack.io")
    maven("https://hyperledger.jfrog.io/artifactory/besu-maven")
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

dependencies {
    compileOnly("org.projectlombok:lombok:1.18.28")
    annotationProcessor("org.projectlombok:lombok:1.18.28")

    implementation("com.weavechain:bulletproofs:1.0")
    implementation("com.weavechain:bulletproofs-gadgets:1.0")

    implementation("javax.servlet:javax.servlet-api:3.1.0")

    implementation("net.thiim.dilithium:dilithium-java:0.0.1")
    implementation("com.swiftcryptollc:kyberJCE:2.1.5")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.72")
    //implementation("org.bouncycastle:bc-fips:1.0.2.+")

    implementation("commons-codec:commons-codec:1.15")
    implementation("org.slf4j:slf4j-api:2.0.0")
    implementation("ch.qos.logback:logback-core:1.4.7")
    implementation("ch.qos.logback:logback-classic:1.4.7")
    implementation("org.hdrhistogram:HdrHistogram:2.1.12")
    implementation("com.squareup.moshi:moshi:1.13.0")
    implementation("org.msgpack:msgpack-core:0.9.0")
    implementation("com.github.fzakaria:ascii85:1.2")
    implementation("com.google.guava:guava:32.0.0-jre")
    implementation("com.github.ben-manes:caffeine:3.1.6") {
        exclude("com.github.ben-manes.caffeine", "simulator")
    }

    implementation("com.github.multiformats:java-multibase:1.1.1")
    implementation("org.bitcoinj:bitcoinj-core:0.17-alpha1")
    implementation("com.codahale:shamir:0.7.0")
    implementation("org.ssohub:ecc:1.0.18")
    implementation("org.apache.tuweni:tuweni-bytes:2.3.1")
    implementation("org.apache.tuweni:tuweni-crypto:2.3.1")
    implementation("org.hyperledger.besu.internal:trie:22.10.1")
    implementation("org.hyperledger.besu:plugin-api:22.10.1")
    implementation("cafe.cryptography:curve25519-elisabeth:0.1.2")
    implementation("tech.pegasys:jc-kzg-4844:0.2.1")
    implementation("tech.pegasys:jblst:0.3.8")
    implementation("ch.obermuhlner:big-math:2.3.2")
    //implementation("info.debatty:java-lsh:0.12")

    implementation("org.java-websocket:Java-WebSocket:1.5.3")
    implementation("com.rabbitmq:amqp-client:5.13.1")
    implementation("com.google.code.gson:gson:2.8.9")
    implementation("com.github.aelstad:keccakj:1.1.0")
    implementation("net.i2p.crypto:eddsa:0.3.0")
    implementation("org.apache.httpcomponents:httpclient:4.5.14")
    implementation("org.apache.kafka:kafka-clients:3.4.1")
    implementation("io.airlift:aircompressor:0.21")

    implementation("org.zeromq:jeromq:0.5.3")

    testCompileOnly("org.projectlombok:lombok:1.18.28")
    testAnnotationProcessor("org.projectlombok:lombok:1.18.28")
    testImplementation("org.testng:testng:7.8.0")
    testImplementation("com.google.truth:truth:1.1.4")
}

tasks.withType<Test>().configureEach {
    useTestNG()
}

val sourcesJar by tasks.registering(Jar::class) {
    classifier = "sources"
    from(sourceSets.main.get().allSource)
}

val dokkaHtml by tasks.getting(org.jetbrains.dokka.gradle.DokkaTask::class)

val javadocJar: TaskProvider<Jar> by tasks.registering(Jar::class) {
    dependsOn(dokkaHtml)
    archiveClassifier.set("javadoc")
    from(dokkaHtml.outputDirectory)
}

publishing {
    repositories {
        maven {
            url = uri("./build/repo")
            name = "Maven"
        }
    }

    publications {
        create<MavenPublication>("Maven") {
            groupId = "com.weavechain"
            artifactId = "api"
            version = "1.0"
            from(components["java"])
        }
        withType<MavenPublication> {
            artifact(sourcesJar)
            artifact(javadocJar)

            pom {
                name.set(project.name)
                description.set("Weavechain Java API")
                url.set("https://github.com/weavechain/weave-java-api")
                licenses {
                    license {
                        name.set("MIT")
                        url.set("https://opensource.org/licenses/mit")
                    }
                }
                issueManagement {
                    system.set("Github")
                    url.set("https://github.com/weavechain/weave-java-api/issues")
                }
                scm {
                    connection.set("scm:git:git://github.com/weavechain/weave-java-api.git")
                    developerConnection.set("scm:git:git@github.com:weavechain/weave-java-api.git")
                    url.set("https://github.com/weavechain/weave-java-api")
                }
                developers {
                    developer {
                        name.set("Ioan Moldovan")
                        email.set("ioan.moldovan@weavechain.com")
                    }
                }
            }
        }
    }
}

signing {
    useGpgCmd()
    sign(configurations.archives.get())
    sign(publishing.publications["Maven"])
}

tasks {
    sourceSets.getByName("test") {
        java.srcDir("src/test/java")
    }

    val releaseJar by creating(Jar::class) {
        archiveClassifier.set("api")

        from(sourceSets.main.get().output.classesDirs)
        include("com/weavechain/**")
    }

    artifacts {
        add("archives", releaseJar)
        add("archives", sourcesJar)
    }
}

tasks.withType<PublishToMavenRepository> {
    dependsOn("checkLicense")
}

licenseReport {
    filters = arrayOf<DependencyFilter>(
            LicenseBundleNormalizer(
                    "$rootDir/license-normalizer-bundle.json",
                    true
            )
    )
    excludeGroups = arrayOf<String>(
    )
    allowedLicensesFile = File("$rootDir/allowed-licenses.json")
}