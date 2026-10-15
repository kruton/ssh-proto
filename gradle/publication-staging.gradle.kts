import org.gradle.api.publish.PublishingExtension
import org.gradle.api.publish.maven.MavenPublication
import org.gradle.api.publish.maven.tasks.GenerateMavenPom
import org.gradle.api.publish.tasks.GenerateModuleMetadata

// Export unsigned publication bytes. Signing and upload happen after isolated attestation.
afterEvaluate {
    val publication = extensions.getByType<PublishingExtension>()
        .publications.getByName("maven") as MavenPublication
    val pom = tasks.named<GenerateMavenPom>("generatePomFileForMavenPublication")
    val metadata = tasks.named<GenerateModuleMetadata>("generateMetadataFileForMavenPublication")
    tasks.register<Sync>("stageMavenPublication") {
        group = "publishing"
        description = "Stages unsigned Maven artifacts for isolated provenance generation"
        into(rootProject.layout.buildDirectory.dir("publication/${project.name}"))
        publication.artifacts.forEach { artifact ->
            dependsOn(artifact.buildDependencies)
            from(artifact.file) {
                val classifier = artifact.classifier?.let { "-$it" }.orEmpty()
                rename { "${publication.artifactId}-${publication.version}$classifier.${artifact.extension}" }
            }
        }
        dependsOn(pom, metadata)
        from(pom.map { it.destination }) {
            rename { "${publication.artifactId}-${publication.version}.pom" }
        }
        from(metadata.flatMap { it.outputFile }) {
            rename { "${publication.artifactId}-${publication.version}.module" }
        }
    }
}
