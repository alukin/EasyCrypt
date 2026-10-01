# Publishing the EasyCrypt libraries

Only these artifacts are released to Maven Central:

- `ua.cn.al:easycrypt`
- `ua.cn.al:easycrypt-identity`
- `ua.cn.al:easycrypt-parent` (the parent POM required to consume the two libraries)

The CLI and example modules remain in this repository and are not part of the release. The `central-release` Maven profile excludes them as a safeguard. A normal Maven build does not activate the publishing profile.

## One-time setup

1. **Manual step pending:** Register and verify the `ua.cn.al` namespace in the [Central Portal](https://central.sonatype.com/). This group ID corresponds to the `al.cn.ua` domain; use the verification method offered by the Portal for a namespace you control.
2. Create a Central Portal user token and add it to Maven `settings.xml` under server ID `central`:

   ```xml
   <settings>
     <servers>
       <server>
         <id>central</id>
         <username>PORTAL_TOKEN_USERNAME</username>
         <password>PORTAL_TOKEN_PASSWORD</password>
       </server>
     </servers>
   </settings>
   ```

3. Configure a GPG key for Maven artifact signing. Keep the private key and Central credentials outside this repository.

Until these steps are complete, local builds work, but release bundle preparation and publishing are not ready.

The `central-release` profile expects the Central token under server ID `central`, including when preparing a bundle with uploads skipped.

## Build and inspect a release bundle

The `central-release` profile signs the artifacts and prepares a Central bundle. Publishing is skipped by default:

```sh
./mvnw -Pcentral-release -pl easycrypt,easycrypt-identity -am clean deploy
```

Inspect the generated bundle under each participating module's `target/central-publishing/` directory. It should contain the parent POM and the two library artifacts, with POM, binary JAR, sources JAR, Javadoc JAR, signatures, and generated checksums. It must not contain the CLI or examples.

After confirming the bundle and completing the Central Portal namespace setup, upload it by setting `central.skipPublishing` to `false`:

```sh
./mvnw -Pcentral-release -Dcentral.skipPublishing=false -pl easycrypt,easycrypt-identity -am deploy
```

The profile leaves `autoPublish` disabled, so the validated deployment still requires an explicit publish action in the Central Portal. Do not reuse a version that has already been published; Central releases are immutable.
