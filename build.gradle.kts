/*
 * Copyright 2019 Kenny Root
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import java.net.URL
import com.fsryan.gradle.smc.SmcExtension
import name.valery1707.kaitai.KaitaiExtension

buildscript {
    repositories {
        mavenCentral()
    }
    dependencies {
        classpath("name.valery1707.kaitai:kaitai-gradle-plugin:0.1.3")
        classpath("com.fsryan.gradle.smc:smc:0.2.0")
    }
}

plugins {
    java
}

apply(plugin = "name.valery1707.kaitai")
apply(plugin = "smc")

configure<KaitaiExtension> {
    packageName = "org.connectbot.sshlib.struct"
    url = rootProject.file("./prebuilts/kaitai-struct-compiler-0.9-SNAPSHOT.zip").toURI().toURL()
}

configure<SmcExtension> {
    smcUri = rootProject.file("./prebuilts/Smc-7.1.0.jar").toURI().toString()
    statemapJarUri = rootProject.file("./libs/statemap.jar").toURI().toString()
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("*.jar"))))

    testImplementation("junit:junit:4.13.2")
}
