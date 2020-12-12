## esycrypt-util

This is utility to generate CSR for X.509 v.3, check certificates, etc

##Compilation

You need JDK 8 or later and Maven 3.6.0 or later
Simple command will do the job
<pre>
mvn clean install
</pre>

##Examples

### Help

```
./easycrypt -h
```

### Generate self-signed X.509 certificate using template
```
./easycrypt certreq -t CR_person_template.properties --selfsigned --rqtype personal
```
