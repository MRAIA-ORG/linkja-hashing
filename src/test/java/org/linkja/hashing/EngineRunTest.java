package org.linkja.hashing;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.linkja.core.LinkjaException;
import org.linkja.hashing.steps.HashingStep;
import org.linkja.hashing.steps.ValidationFilterStep;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Small synthetic extracts. The run_ tests call Engine.run. The hashValues_ test builds the pipeline by hand, see its
 * javadoc.
 */
class EngineRunTest {
  // The 11 hash columns in the order Engine.writeDataRowResult writes them, and whether each one is blanked when the
  // row has no SSN.
  private static final String[] HASH_FIELDS = {
    HashingStep.PIDHASH_FIELD, HashingStep.FNAMELNAMEDOBSSN_FIELD, HashingStep.LNAMEFNAMEDOBSSN_FIELD,
    HashingStep.FNAMELNAMEDOB_FIELD, HashingStep.LNAMEFNAMEDOB_FIELD, HashingStep.FNAMELNAMETDOBSSN_FIELD,
    HashingStep.FNAMELNAMETDOB_FIELD, HashingStep.FNAME3LNAMEDOBSSN_FIELD, HashingStep.FNAME3LNAMEDOB_FIELD,
    HashingStep.FNAMELNAMEDOBDSSN_FIELD, HashingStep.FNAMELNAMEDOBYSSN_FIELD };
  private static final boolean[] NEEDS_SSN = { false, true, true, false, false, true, false, true, false, true, true };

  // Hash values of ONE_COLUMN_PER_FIELD, made with the engine as it was before the duplicate column check.
  private static final String EXPECTED_HASHES_RESOURCE = "/engine-run/one-column-per-field-hashes.txt";

  private static final String PRIVATE_KEY_FILE = "private.pem";

  // A failed run must keep a file that has the name it would pick. The name has the time to the second, so the test
  // makes such files for this many seconds from the start of the run.
  private static final int SAME_NAME_WINDOW_SECONDS = 30;
  private static final String EARLIER_RUN = "earlier run";

  // Enough rows in small batches that the read loop is still running when the first batch fails.
  private static final int MID_RUN_ROWS = 5000;
  private static final int MID_RUN_BATCH_SIZE = 100;

  private static final String ONE_COLUMN_PER_FIELD =
    "patient_id,first_name,last_name,date_of_birth,social_security_number\n" +
    "P001,Alice,Example,1980-01-15,234-56-7890\n" +
    "P002,Robert,Sample,1975-12-02,\n" +
    "P003,Carol,Testcase,2001-07-30,987-65-4320\n";

  @Test
  void run_TwoColumnsForPatientId_StopsBeforeAnyOutput(@TempDir Path dir) throws Exception {
    // ID is unique, PATIENT_ID repeats P001. Both resolve to patient_id.
    assertStopsBeforeAnyOutput(dir,
      "ID,PATIENT_ID,first_name,last_name,date_of_birth\n" +
      "1,P001,Alice,Example,1980-01-15\n" +
      "2,P001,Robert,Sample,1975-12-02\n",
      "The field patient_id has more than one column: \"ID\" and \"PATIENT_ID\". " +
      "Keep one column for each field and run again.");
  }

  @Test
  void run_SameColumnNameTwiceForPatientId_StopsBeforeAnyOutput(@TempDir Path dir) throws Exception {
    assertStopsBeforeAnyOutput(dir,
      "ID,ID,first_name,last_name,dob\n" +
      "1,P001,Alice,Example,1980-01-15\n" +
      "2,P001,Robert,Sample,1975-12-02\n",
      "The field patient_id has more than one column: \"ID\" and \"ID\". " +
      "Keep one column for each field and run again.");
  }

  @Test
  void run_SameColumnNameTwiceForDateOfBirth_StopsBeforeAnyOutput(@TempDir Path dir) throws Exception {
    assertStopsBeforeAnyOutput(dir,
      "patient_id,first_name,last_name,dob,dob\n" +
      "P001,Alice,Example,1980-01-15,1981-02-16\n",
      "The field date_of_birth has more than one column: \"dob\" and \"dob\". " +
      "Keep one column for each field and run again.");
  }

  /**
   * Ticket #96. The secure hash step throws after the output files are open. UnsupportedOperationException is what the
   * public build of the C library throws. UnsatisfiedLinkError is what a library that cannot link throws. The run must
   * remove the files it made, and keep a file from an earlier run.
   */
  @ParameterizedTest
  @ValueSource(booleans = { false, true })
  void run_SecureHashThrows_RemovesFilesItMade(boolean linkError, @TempDir Path dir) throws Exception {
    Path outputDir = Files.createDirectory(dir.resolve("out"));
    Files.writeString(outputDir.resolve("hashes_site1_project1_20200101000000.enc"), "earlier run");
    Set<Path> before = listFiles(outputDir);

    assertThrows(Throwable.class, failingEngine(dir, outputDir, linkError)::run);
    assertEquals(before, listFiles(outputDir));
  }

  /**
   * Ticket #96. A run never opens a file that is already there, so a file from an earlier run with the name this run
   * picks is not changed. The run stops with a message that names the file, and removes the files it made before the
   * clash. Each case makes one of the three names, so the clash is on the first, second or third open. The name has the
   * time to the second, so the test makes such files for SAME_NAME_WINDOW_SECONDS.
   */
  @ParameterizedTest
  @ValueSource(strings = { "hashes_%s.enc", "DONOTSEND_crosswalk_%s.csv", "DONOTSEND_invaliddata_%s.csv" })
  void run_EarlierFileWithSameName_StopsAndKeepsIt(String namePattern, @TempDir Path dir) throws Exception {
    Path outputDir = Files.createDirectory(dir.resolve("out"));
    LocalDateTime now = LocalDateTime.now();
    for (int second = 0; second < SAME_NAME_WINDOW_SECONDS; second++) {
      String name = "site1_project1_" + now.plusSeconds(second).format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));
      Files.writeString(outputDir.resolve(String.format(namePattern, name)), EARLIER_RUN);
    }
    Set<Path> before = listFiles(outputDir);

    LinkjaException exc = assertThrows(LinkjaException.class, failingEngine(dir, outputDir, false)::run);
    assertTrue(exc.getMessage().matches("The output file .*" + outputDir.getFileName() + ".*_\\d{14}\\.\\w+ is already there\\. "
      + "Move it out of the output folder, and run again\\."), exc.getMessage());
    assertEquals(before, listFiles(outputDir));
    for (Path file : before) {
      assertEquals(EARLIER_RUN, Files.readString(file), file.toString());
    }
  }

  /**
   * Ticket #96. With many rows, small batches and one worker thread, the secure hash step fails while rows are still
   * being read, so the run stops in the middle of the read loop. It must still remove the files it made. Ticket #99:
   * that route returned without an exception, so the jar exited 0. It must throw, and name the failure.
   */
  @Test
  void run_SecureHashThrowsMidRun_RemovesFilesItMade(@TempDir Path dir) throws Exception {
    Path outputDir = Files.createDirectory(dir.resolve("out"));
    Engine engine = midRunFailingEngine(dir, outputDir);

    LinkjaException exc = assertThrows(LinkjaException.class, engine::run);
    assertEquals("The run stopped while writing the results: secure hash failed", exc.getMessage());
    assertEquals(Set.of(), listFiles(outputDir));
  }

  /** An engine whose secure hash step throws while the read loop is still running (see the test above). */
  static Engine midRunFailingEngine(Path dir, Path outputDir) throws Exception {
    StringBuilder extract = new StringBuilder("patient_id,first_name,last_name,date_of_birth,social_security_number\n");
    for (int row = 0; row < MID_RUN_ROWS; row++) {
      extract.append("P").append(row).append(",Alice,Example,1980-01-15,234-56-7890\n");
    }
    EngineParameters parameters = runParameters(dir, outputDir, extract.toString());
    parameters.setBatchSize(MID_RUN_BATCH_SIZE);
    parameters.setNumWorkerThreads(1);
    return new Engine(parameters, createHashParameters()) {
      @Override
      String createSecureHash(String hash, byte[] sessionKey, String rowId, String tokenId) {
        throw new UnsupportedOperationException("secure hash failed");
      }
    };
  }

  /** Ticket #96. An Error from the secure hash step stops the worker threads, so the JVM can exit. */
  @Test
  void run_SecureHashThrowsError_ShutsDownThreadPool(@TempDir Path dir) throws Exception {
    Path outputDir = Files.createDirectory(dir.resolve("out"));
    List<ExecutorService> pools = new ArrayList<>();
    Engine engine = new Engine(runParameters(dir, outputDir), createHashParameters()) {
      @Override
      String createSecureHash(String hash, byte[] sessionKey, String rowId, String tokenId) {
        throw new UnsatisfiedLinkError("secure hash failed");
      }

      @Override
      ExecutorService createThreadPool(int numThreads) {
        ExecutorService pool = super.createThreadPool(numThreads);
        pools.add(pool);
        return pool;
      }
    };

    assertThrows(UnsatisfiedLinkError.class, engine::run);
    assertEquals(1, pools.size());
    assertTrue(pools.get(0).isShutdown());
  }

  /**
   * Ticket #99. Each output file fails to close. The run must still stop with the error of the secure hash step, and
   * keep each close failure as a suppressed exception of that error.
   */
  @Test
  void run_CloseFailsAfterError_KeepsOriginalError(@TempDir Path dir) throws Exception {
    Path outputDir = Files.createDirectory(dir.resolve("out"));
    Engine engine = new Engine(runParameters(dir, outputDir), createHashParameters()) {
      @Override
      String createSecureHash(String hash, byte[] sessionKey, String rowId, String tokenId) {
        throw new UnsupportedOperationException("secure hash failed");
      }

      @Override
      OutputStream openOutput(Path path) throws IOException {
        return new FilterOutputStream(super.openOutput(path)) {
          @Override
          public void close() throws IOException {
            super.close();
            throw new IOException("close failed");
          }
        };
      }
    };

    LinkjaException exc = assertThrows(LinkjaException.class, engine::run);
    assertEquals("The run stopped while writing the results: secure hash failed", exc.getMessage());
    assertTrue(exc.getSuppressed().length > 0);
    for (Throwable suppressed : exc.getSuppressed()) {
      assertEquals("close failed", suppressed.getMessage());
    }
    assertEquals(Set.of(), listFiles(outputDir));
  }

  /**
   * Ticket #99. A failed run closes each output file while the file is still there, i.e. before it removes it. macOS and
   * Linux remove an open file, but Windows does not, so only this test finds a missing close.
   */
  @Test
  void run_Fails_ClosesEachFileBeforeRemovingIt(@TempDir Path dir) throws Exception {
    Path outputDir = Files.createDirectory(dir.resolve("out"));
    Map<Path, Boolean> thereWhenClosed = new ConcurrentHashMap<>();
    List<Path> opened = new ArrayList<>();
    Engine engine = new Engine(runParameters(dir, outputDir), createHashParameters()) {
      @Override
      String createSecureHash(String hash, byte[] sessionKey, String rowId, String tokenId) {
        throw new UnsupportedOperationException("secure hash failed");
      }

      @Override
      OutputStream openOutput(Path path) throws IOException {
        opened.add(path);
        return new FilterOutputStream(super.openOutput(path)) {
          @Override
          public void close() throws IOException {
            thereWhenClosed.putIfAbsent(path, Files.exists(path));
            super.close();
          }
        };
      }
    };

    assertThrows(LinkjaException.class, engine::run);
    assertEquals(3, opened.size());
    for (Path path : opened) {
      assertEquals(Boolean.TRUE, thereWhenClosed.get(path), path.toString());
    }
    assertEquals(Set.of(), listFiles(outputDir));
  }

  /** Ticket #96. A run that stops on a repeated patient ID leaves no output file. */
  @Test
  void run_DuplicatePatientId_LeavesNoOutputFiles(@TempDir Path dir) throws Exception {
    assertStopsBeforeAnyOutput(dir,
      "patient_id,first_name,last_name,date_of_birth\n" +
      "P001,Alice,Example,1980-01-15\n" +
      "P001,Robert,Sample,1975-12-02\n",
      "Patient IDs must be unique within the data file.  A duplicate copy of Patient ID P001 was found on row 2.");
  }

  /** An engine whose secure hash step throws UnsatisfiedLinkError (linkError) or UnsupportedOperationException. */
  static Engine failingEngine(Path dir, Path outputDir, boolean linkError) throws Exception {
    return new Engine(runParameters(dir, outputDir), createHashParameters()) {
      @Override
      String createSecureHash(String hash, byte[] sessionKey, String rowId, String tokenId) {
        if (linkError) {
          throw new UnsatisfiedLinkError("secure hash failed");
        }
        throw new UnsupportedOperationException("secure hash failed");
      }
    };
  }

  /**
   * Ticket #96. A run that succeeds still writes the three files, and the hash file still holds the hash values of
   * ONE_COLUMN_PER_FIELD. The secure hash step returns its input (CI has only the public build of the C library), so
   * the decrypted values are the plain hash values in EXPECTED_HASHES_RESOURCE, without the patient ID column.
   */
  @Test
  void run_Succeeds_SameFilesAndHashesAsBefore(@TempDir Path dir) throws Exception {
    Path outputDir = Files.createDirectory(dir.resolve("out"));
    new Engine(runParameters(dir, outputDir), createHashParameters()) {
      @Override
      String createSecureHash(String hash, byte[] sessionKey, String rowId, String tokenId) {
        return hash;
      }

      @Override
      String revertSecureHash(String secureHash, byte[] sessionKey, String rowId, String tokenId) {
        return secureHash;
      }
    }.run();

    List<String> names = new ArrayList<>();
    for (Path file : listFiles(outputDir)) {
      names.add(file.getFileName().toString().replaceAll("_\\d{14}\\.", "_TIMESTAMP."));
    }
    names.sort(null);
    assertEquals(List.of("DONOTSEND_crosswalk_site1_project1_TIMESTAMP.csv",
      "DONOTSEND_invaliddata_site1_project1_TIMESTAMP.csv", "hashes_site1_project1_TIMESTAMP.enc"), names);

    Set<String> expected = new HashSet<>();
    for (String line : expectedHashLines()) {
      expected.add(line.substring(line.indexOf(',') + 1));
    }
    assertEquals(expected, new HashSet<>(RunConfigTest.decryptHashFile(outputDir, dir.resolve(PRIVATE_KEY_FILE))));
  }

  /** Parameters for one ONE_COLUMN_PER_FIELD run. Writes the extract and a key pair into dir. */
  static EngineParameters runParameters(Path dir, Path outputDir) throws Exception {
    return runParameters(dir, outputDir, ONE_COLUMN_PER_FIELD);
  }

  /** Parameters for one run of extract. Writes the extract and a key pair into dir. */
  private static EngineParameters runParameters(Path dir, Path outputDir, String extract) throws Exception {
    Path patientFile = Files.writeString(dir.resolve("patients.csv"), extract);
    EngineParameters parameters = new EngineParameters();
    parameters.setPatientFile(patientFile.toFile());
    parameters.setOutputDirectory(outputDir);
    parameters.setEncryptionKeyFile(writePublicKey(dir).toFile());
    return parameters;
  }

  static Set<Path> listFiles(Path folder) throws Exception {
    try (Stream<Path> files = Files.list(folder)) {
      return files.collect(Collectors.toSet());
    }
  }

  private static void assertStopsBeforeAnyOutput(Path dir, String extract, String expectedMessage) throws Exception {
    Path patientFile = dir.resolve("patients.csv");
    Files.writeString(patientFile, extract);
    Path outputDir = Files.createDirectory(dir.resolve("out"));

    EngineParameters parameters = new EngineParameters();
    parameters.setPatientFile(patientFile.toFile());
    parameters.setOutputDirectory(outputDir);
    parameters.setEncryptionKeyFile(writePublicKey(dir).toFile());
    Engine engine = new Engine(parameters, createHashParameters());

    LinkjaException exc = assertThrows(LinkjaException.class, engine::run);
    assertEquals(expectedMessage, exc.getMessage());
    try (Stream<Path> files = Files.list(outputDir)) {
      assertEquals(0, files.count());
    }
  }

  /**
   * The hash file holds createSecureHash(value), and decrypting it gives back the value, so the values compared here
   * are the decrypted hash values. This test does not call Engine.run. It sets the Engine's private fields by
   * reflection and runs these steps on each row: DataHeaderMap.createFromCSVHeader and mergeCanonicalHeaders,
   * Engine.csvRecordToDataRow, EngineWorkerThread with normalization always on and the default exclusion mode, and
   * HashingStep. It skips the patient ID check, the secure hash step (it needs the secret build of the crypto library)
   * and the file writers.
   */
  @Test
  void hashValues_OneColumnPerField_Unchanged() throws Exception {
    assertEquals(new HashSet<>(expectedHashLines()), new HashSet<>(hashRows(ONE_COLUMN_PER_FIELD)));
  }

  /** The lines of EXPECTED_HASHES_RESOURCE: patient ID, then the 11 hash values. */
  private static List<String> expectedHashLines() throws Exception {
    List<String> lines = new ArrayList<>();
    try (InputStream stream = EngineRunTest.class.getResourceAsStream(EXPECTED_HASHES_RESOURCE)) {
      for (String line : new String(stream.readAllBytes(), StandardCharsets.UTF_8).split("\n")) {
        if (!line.isBlank()) {
          lines.add(line);
        }
      }
    }
    return lines;
  }

  @SuppressWarnings("unchecked")
  private List<String> hashRows(String extract) throws Exception {
    Engine engine = new Engine(new EngineParameters(), createHashParameters());
    engine.initialize();
    HashMap<String, String> canonicalHeaderNames =
      (HashMap<String, String>) FieldUtils.readStaticField(Engine.class, "canonicalHeaderNames", true);

    CSVParser parser = CSVParser.parse(new StringReader(extract), CSVFormat.DEFAULT.builder().setHeader().get());
    DataHeaderMap headerMap = new DataHeaderMap().createFromCSVHeader(parser.getHeaderNames()).mergeCanonicalHeaders(canonicalHeaderNames);
    FieldUtils.writeField(engine, "patientDataHeaderMap", headerMap, true);

    List<DataRow> rows = new ArrayList<>();
    for (CSVRecord record : parser) {
      rows.add(engine.csvRecordToDataRow(record));
    }
    rows = new EngineWorkerThread(rows, true, EngineParameters.DEFAULT_RECORD_EXCLUSION_MODE,
      (ArrayList<String>) FieldUtils.readStaticField(Engine.class, "prefixes", true),
      (ArrayList<String>) FieldUtils.readStaticField(Engine.class, "suffixes", true),
      (HashMap<String, String>) FieldUtils.readStaticField(Engine.class, "genericNames", true),
      ValidationFilterStep.DATE_OF_BIRTH_FORMATTER).call();

    HashingStep hashingStep = (HashingStep) FieldUtils.readField(engine, "hashingStep", true);
    List<String> lines = new ArrayList<>();
    for (DataRow row : rows) {
      hashingStep.run(row);
      assertTrue(row.shouldProcess(), row.getInvalidReason());
      Object ssn = row.get(Engine.SOCIAL_SECURITY_NUMBER);
      boolean hasSsn = !(ssn == null || ssn.equals(""));
      StringBuilder line = new StringBuilder((String) row.get(Engine.PATIENT_ID_FIELD));
      for (int index = 0; index < HASH_FIELDS.length; index++) {
        line.append(',');
        if (hasSsn || !NEEDS_SSN[index]) {
          line.append(((String) row.get(HASH_FIELDS[index])).toUpperCase());
        }
      }
      lines.add(line.toString());
    }
    return lines;
  }

  /** Writes a new key pair into dir. Returns the public key file. The private key is in dir/PRIVATE_KEY_FILE. */
  private static Path writePublicKey(Path dir) throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    KeyPair pair = generator.generateKeyPair();
    Files.writeString(dir.resolve(PRIVATE_KEY_FILE), pem("PRIVATE KEY", pair.getPrivate().getEncoded()));
    return Files.writeString(dir.resolve("public.pem"), pem("PUBLIC KEY", pair.getPublic().getEncoded()));
  }

  private static String pem(String type, byte[] der) {
    return "-----BEGIN " + type + "-----\n" + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der)
      + "\n-----END " + type + "-----\n";
  }

  static HashParameters createHashParameters() {
    HashParameters hashParameters = new HashParameters();
    hashParameters.setSiteId("site1");
    hashParameters.setSiteName("Test Site");
    hashParameters.setProjectId("project1");
    hashParameters.setPrivateSalt("private-salt-for-tests-0123456789");
    hashParameters.setProjectSalt("project-salt-for-tests-0123456789");
    hashParameters.setPrivateDate(LocalDate.of(2018, 1, 1));
    return hashParameters;
  }
}
