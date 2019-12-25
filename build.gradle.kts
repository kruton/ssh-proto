import name.valery1707.kaitai.KaitaiExtension

buildscript {
    repositories {
        jcenter()
    }
    dependencies {
        classpath("name.valery1707.kaitai:kaitai-gradle-plugin:0.1.3")
    }
}

plugins {
    java
}

apply(plugin = "name.valery1707.kaitai")

configure<KaitaiExtension> {
    packageName = "org.connectbot.sshlib.struct"
}

repositories {
    jcenter()
}

dependencies {
    implementation("io.kaitai:kaitai-struct-runtime:0.8")

    testImplementation("junit:junit:4.12")
}
