import name.valery1707.kaitai.KaitaiExtension

buildscript {
    repositories {
        jcenter()
    }
    dependencies {
        classpath("name.valery1707.kaitai:kaitai-gradle-plugin:0.1.3")
        classpath("com.fsryan.gradle.smc:smc:0.0.2")
    }
}

plugins {
    java
}

apply(plugin = "name.valery1707.kaitai")
apply(plugin = "smc")

configure<KaitaiExtension> {
    packageName = "org.connectbot.sshlib.struct"
}

repositories {
    jcenter()
}

dependencies {
    implementation("io.kaitai:kaitai-struct-runtime:0.8")
    implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("*.jar"))))

    testImplementation("junit:junit:4.12")
}
