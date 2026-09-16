version = "0.0.1"

plugins {
    id("java")
}

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.7")

    // QUIC transport only. HTTP/3 framing and QPACK are ours — see the phase 1 design spec.
    // LGPL-3.0: keep Kwik replaceable in the shipped jar and publish any fork.
    implementation("tech.kwik:kwik:0.10.3") {
        // HP3 is a QUIC client. Kwik uses SipHash only in its server connection registry.
        exclude(group = "com.io7m.repackage.io.whitfin", module = "io.whitfin.siphash")
    }
}

tasks.withType<JavaCompile>().configureEach {
    sourceCompatibility = "21"
    targetCompatibility = "21"
    options.encoding = "UTF-8"
}

tasks.named<Jar>("jar") {
    manifest {
        attributes(
            "Implementation-Title" to project.name,
            "Implementation-Version" to project.version,
        )
    }
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(configurations.runtimeClasspath.get().filter { it.isDirectory })
    from(configurations.runtimeClasspath.get().filterNot { it.isDirectory }.map { zipTree(it) })

    from("THIRD-PARTY-NOTICES.md") {
        into("META-INF")
    }
    from("LICENSE") {
        into("META-INF/licenses")
        rename { "AGPL-3.0-only.txt" }
    }
    from("LICENSES-GPL-3.0.txt") {
        into("META-INF/licenses")
        rename { "GPL-3.0.txt" }
    }
    from("LICENSES-LGPL-3.0.txt") {
        into("META-INF/licenses")
        rename { "LGPL-3.0.txt" }
    }
    from("LICENSES-APACHE-2.0.txt") {
        into("META-INF/licenses")
        rename { "Apache-2.0.txt" }
    }

    // at.favre.lib:hkdf (via Kwik) is a signed jar. Copying its signature files into the fat jar
    // leaves digests that no longer match the merged contents, and Burp refuses to start with
    // "SecurityException: Invalid signature file digest for Manifest main attributes".
    exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA", "META-INF/*.EC")
}
