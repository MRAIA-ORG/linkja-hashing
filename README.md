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

The tests call the linkja C library, so compile it first from the `develop` branch of [linkja-crypto](https://github.com/MRAIA-ORG/linkja-crypto). The tests need only the public build. Running the program at a site needs the secret build of the project. The C library needs OpenSSL 3 and CMake (e.g. `brew install openssl@3 cmake`), and CMake needs `JAVA_HOME` set to Java 25. From a linkja-crypto clone beside this one:

```
cmake . -DINCLUDE_SECRETS=OFF -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"
make linkjacrypto
```

On Linux, install `libssl-dev cmake` and leave out `-DOPENSSL_ROOT_DIR`.

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

The patient file must have one column for each field. If two columns name the same field (e.g. `dob` and `birthdate`, or `ID` twice), the program stops before it writes any output. The accepted names for each field are in `src/main/resources/configuration/canonical-header-names.csv`.

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

#### Run config

You can put all the settings of a run in one run config file, and give only `--config`:

```
java -Djava.library.path=. -jar Hashing-1.1.1-jar-with-dependencies.jar --config run.properties
```

The run config is a Java Properties file in UTF-8, one `key=value` on each line:

```properties
# Secrets and keys
site.salt_file=keys/project1_salt.txt
aggregator.public_key=keys/aggregator_public.key
site.private_date=01/01/2018

# The input extract
input.file=data/extract.csv
input.delimiter=,
input.date_format=uuuu/MM/dd

# Column map: linkja field = column name in the input extract
column.patient_id=PAT_ID
column.first_name=GIVEN
column.last_name=SURNAME
column.birth_date=DOB_TXT
column.ssn=SOC

output.directory=out/
```

**Keep the run config as a secret file, the same as the salt file.** It can hold the private date. If you do not want the private date in the file, leave `site.private_date` out and give `--privateDate` on the command line.

Rules:

* The required keys are `site.salt_file`, `aggregator.public_key`, `site.private_date` and `input.file`. Each one can come from the file or from its command-line flag (`--saltFile`, `--encryptionKey`, `--privateDate`, `--patientFile`). If one is missing, the run stops before it makes an output file, and the message names the key.
* A key that is not one of the keys above, e.g. the typo `input.date_fromat`, stops the run, and the message gives its line number. It names the key only when the line has a value after it, so a line with no `=`, e.g. `site.private_date01/01/2018`, is never printed.
* A run config file that is not found or is not UTF-8 stops the run, and the message says which.
* A flag on the command line wins over the same key in the file, e.g. `--delimiter "|"` wins over `input.delimiter=,`.
* `output.directory` and `--outDirectory` are the same setting. Without either, the output goes to the current directory.
* A relative path is read from the folder where you run `java`. Write paths with `/`. In a Properties file, `\` starts an escape, so `C:\keys\salt.txt` does not read as you expect. `C:/keys/salt.txt` works.
* `input.date_format` is the format of the birth date, as a Java date pattern. Use `uuuu` for the year (e.g. `uuuu/MM/dd`), because the date parser is strict. A time of day after the date is allowed, e.g. `dd/MM/uuuu HH:mm`. When it is set, only that format is accepted. Without it, the default birth date formats apply. A pattern that cannot read a full date back unchanged stops the run, e.g. `yyyy/MM/dd` or the two-digit year `dd/MM/uu`.
* Without `input.date_format`, a birth date reads in any of these formats. Each one can have a time after it, e.g. `2001/2/3 13:02` or `2001/2/3 13:02:03`.
  * `uuuu/M/d`, e.g. `2001/2/3`
  * `uuuu-M-d`, e.g. `2001-2-3`
  * `uuuu M d`, e.g. `2001 2 3`
  * `uuuuMMdd`, e.g. `20010203`
  * `M/d/uuuu`, e.g. `2/3/2001`
  * `M-d-uuuu`, e.g. `2-3-2001`
  * `M d uuuu`, e.g. `2 3 2001`
* The 8 digits of a birth date do not read as `MMdduuuu`, e.g. `02032001` is read as year 0203, month 20, and is rejected.
* A `column.<field>=<header>` key names the column of the input extract that gives the field. The field can be any name in the `alias_name` column of `src/main/resources/configuration/canonical-header-names.csv`, e.g. `column.patient_id`, `column.first_name`, `column.last_name`, `column.birth_date` (or `column.dob`) and `column.ssn`. The field name ignores case, e.g. `column.FIRST_NAME` is the same as `column.first_name`. Header matching ignores case.
* For each field, the `column.` key wins over the fixed header list (`src/main/resources/configuration/canonical-header-names.csv`), even when that list maps the header to another field. The other columns that the list maps to that field are ignored.
* The fixed header list is used only for a field with no `column.` key.
* A column that is neither named by a `column.` key nor in the fixed header list is ignored. So you can use an extract you already have, with extra columns, as it is.
* The column map is applied first. Then, as in every run, two columns that give one field stop the run, e.g. both `ID` and `PATIENT_ID`. To use an extract with both, name the one to use with a `column.` key.
* A `column.` key that names a header the extract does not have stops the run before it makes an output file. The message names the key and the header.
* Two `column.` keys that name one header stop the run, e.g. `column.first_name=GIVEN` and `column.last_name=GIVEN`.
