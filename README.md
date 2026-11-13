# linkja-hashing

The data linkage application is designed to disambiguate patients across sites / health systems, with minimal risk from transferring PHI by hashing the patient identifiers with a secured salt and hashing algorithm. Main Components of the application are:
1.	Web based Project, User and Key Manager
2.	Data Standardization, exceptions, and hashing 
3.	Disambiguation / matching

Each component is explained in more detail below:
1.	Web interface for Project, User and Key management - 
This component is designed to manage project specific Salt distribution. It allows the project managers to create projects, add users and authenticate the users. The authenticated users upload their RSA public keys and download the encrypted Salt file. 

2.	Data Standardization, exceptions, and hashing - 
This component includes a data pipeline to digest and validate the data, standardize the data, manage data exceptions, create composite variables from patient identifiers and hash using SHA512 algorithm and Salt

3.	Disambiguation / matching - 
This component allows the aggregator to merge files, disambiguate the hashes and assign Universal patient ID to matching patients


## Building
linkja-hashing has been tested under Java JDK 25 (specifically [Adoptium Temurin JDK](https://adoptium.net/temurin/releases)).  It can be opened from within an IDE like Eclipse or IntelliJ IDEA and compiled, or compiled from the command line using [Maven](https://maven.apache.org/). Maven downloads the linkja-core and linkja-crypto JARs from [linkja-mvn-repo](https://github.com/MRAIA-ORG/linkja-mvn-repo).

The tests call the linkja C library, so compile it first from the `develop` branch of [linkja-crypto](https://github.com/MRAIA-ORG/linkja-crypto). The tests need only the public build. Running the program at a site needs the secret build of the project. The C library needs OpenSSL 3, CMake and cmocka (e.g. `brew install openssl@3 cmake cmocka`), and CMake needs `JAVA_HOME` set to Java 25. From a linkja-crypto clone beside this one:

```
cmake . -DINCLUDE_SECRETS=OFF -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"
make linkjacrypto
```

On Linux, install `libssl-dev cmake libcmocka-dev` and leave out `-DOPENSSL_ROOT_DIR`.

Then, from this folder:

`mvn clean package -Dnative.lib.dir=../linkja-crypto/target`

This compiles the code, runs all unit tests, and creates an executable JAR file in the `target` folder with all dependency JARs included, e.g. `target/Hashing-1.1.1-jar-with-dependencies.jar`. If you do not give `native.lib.dir`, the tests look for the library in the `lib` folder.

CI runs the same steps on each pull request. See `.github/workflows/ci.yml`.

## Program Use
You can run the executable JAR file (the one including `with-dependencies` in the file name) using the standard Java command:
`java -jar <JAR path>`

For encryption, linkja-hashing uses a special C library (.dll/.dylib/.so, depending on your operating system).  You will need to tell Java where to find this library when you try to run the program.  Otherwise, you will get an error:

```
Exception in thread "main" java.lang.UnsatisfiedLinkError: no linkjacrypto in java.library.path:
```

The library may be placed in any directory found by the Java library path.  If you would like to specify the library, you can include the `-Djava.library.path=` option when running the program.
This can be the same directory as the linkja-hashing JAR file (e.g., `-Djava.library.path=.`).

By default, the program will perform the hashing operations on an input file.  More information about the parameters needed to run hashing is shown below.

If you specify `--version`, the program will display the application version and the signature of the linkja-crypto library that it is using.  

Note that where files are used for input, they can be specified as a relative or absolute path.

### Hashing
Usage: `java -Djava.library.path=. -jar Hashing-1.0-jar-with-dependencies.jar`

The program is expecting a minimum of four parameters:

```
 -key,--encryptionKey <arg>        Path to the aggregator's public key file, to
                                   encrypt results.
 -salt,--saltFile <arg>            Path to the salt file
 -patient,--patientFile <arg>      Path to the file containing patient data
 -date,--privateDate <arg>         The private date (as MM/DD/YYYY)
```

There are additional optional parameters that you may also specify:

```
 -out,--outDirectory <arg>         The base directory to create output. If not
                                   specified, will use the current directory.
 -delim,--delimiter <arg>          The delimiter used within the patient data
                                   file. Uses a comma "," by default.
```

**Examples:**

Display the version information

```
java -Djava.library.path=. -jar Hashing-1.0-jar-with-dependencies.jar --version
```

Required parameters specified

```
java -Djava.library.path=. -jar Hashing-1.0-jar-with-dependencies.jar
    --encryptionKey ./keys/public.key --saltFile ./data/project1_salt.txt
    --patientFile ./data/project1_patients.csv --privateDate 01/01/2018
```

Pipe delimited file as input, and specify the output.  Also includes writing out the unhashed data as unencrypted text for debugging.

```
java -Djava.library.path=. -jar Hashing-1.0-jar-with-dependencies.jar
    --encryptionKey ./keys/public.key --saltFile ./data/project1_salt.txt
    --patientFile ./data/project1_patients.csv --privateDate 01/01/2018
    --outDirectory ./data/output/ --delimiter |
```
