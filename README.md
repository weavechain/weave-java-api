## Weavechain Java API
[https://weavechain.com](https://weavechain.com): Layer-0 For Data


### Usage

### Repositories

```
mavenCentral()
maven("https://jitpack.io")
maven("https://hyperledger.jfrog.io/artifactory/besu-maven")
```

#### Gradle Groovy DSL

```
implementation 'com.weavechain:api:1.1'
```

#### Gradle Kotlin DSL

```
implementation("com.weavechain:api:1.1")
```

##### Apache Maven

```xml
<dependency>
  <groupId>com.weavechain</groupId>
  <artifactId>api</artifactId>
  <version>1.1</version>
</dependency>
```


##### VM Args

```
--add-opens=java.base/sun.security.x509=ALL-UNNAMED --add-exports=java.base/sun.security.util=ALL-UNNAMED
```

```
val jvmAddedArgs = listOf(
        "--add-opens=java.base/sun.security.x509=ALL-UNNAMED",
        "--add-exports=java.base/sun.security.util=ALL-UNNAMED"
)

application {
    mainClass.set(mainCls)
    applicationDefaultJvmArgs += jvmAddedArgs
}
```

#### Data read sample

```java
Keys keys = Keys.generateKeys();
String pub = keys.getPublicKey();
String pvk = keys.getPrivateKey();
System.out.println("Public key: " + pub);
System.out.println("Private key:" + pvk);

String host = "public.weavechain.com";
int port = 443;
String seed = "92f30f0b6be2732cb817c19839b0940c";

String organization = "weavedemo";
String scope = "shared";
String table = "directory";

ChainClientConfig cfg =  new ChainClientConfig()
        .organization(organization)
        .seed(seed)
        .http(new HttpClientConfig()
                .host(host)
                .port(port)
                .useHttps(true)
        )
        .seed(seed)
        .privateKey(pvk)
        .publicKey(pub);

ApiClientV1 nodeApi = ChainApiFactory.createApiClient(cfg);
nodeApi.init();

Session session = nodeApi.login(organization, pub, "*").get();

OperationResult reply = nodeApi.read(session, scope, table, null, ReadOptions.DEFAULT_NO_CHAIN).get();
System.out.println(reply.getStringData());

nodeApi.logout(session);
```

#### Docs

[https://docs.weavechain.com](https://docs.weavechain.com)