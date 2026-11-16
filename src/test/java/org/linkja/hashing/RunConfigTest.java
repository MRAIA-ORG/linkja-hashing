package org.linkja.hashing;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.linkja.core.EncryptedHashFileMetadata;
import org.linkja.core.LinkjaException;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End-to-end tests of the run config (--config). Each test hashes a small extract, then decrypts the hash file and
 * compares the hash values as sorted rows, because the session key is random and the row order can change.
 * The test engine skips the secure hash step (see hash()), so the hash values compared are the plain hash values.
 * The keys and the salt file are made fresh for the test run, so no key is kept in the repository.
 */
class RunConfigTest {
  private static final String PRIVATE_DATE = "01/01/2018";
  private static final int HASH_BLOCK_SIZE = 64;

  @TempDir
  static Path dir;
  private static Path publicKey;
  private static Path privateKey;
  private static Path saltFile;

  /** The same three people, in the fixed-list headers and the month-first date format. */
  private static final String STANDARD_EXTRACT = String.join("\n",
    "patient_id,first_name,last_name,dob,ssn",
    "P1,Alice,Smith,02/03/2001,123-45-6780",
    "P2,Bobby,Jones,11/30/1975,",
    "P3,Carol,Brown,07/04/1960,987-65-4320") + "\n";

  @BeforeAll
  static void makeKeysAndSalt() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    KeyPair pair = generator.generateKeyPair();
    publicKey = write("public.key", pem("PUBLIC KEY", pair.getPublic().getEncoded()));
    privateKey = write("private.key", pem("PRIVATE KEY", pair.getPrivate().getEncoded()));
    saltFile = write("salt.txt", String.format("001,Test Site,%s,%s,Test Project\n", randomHex(), randomHex()));
  }

  @Test
  void configOnly_SameHashesAsFlags() throws Exception {
    Path extract = write("standard.csv", STANDARD_EXTRACT);
    List<String> byFlags = hash(flagArgs(extract, newDir()));
    List<String> byConfig = hash("--config", writeConfig(requiredKeys(extract, newDir())).toString());
    assertEquals(3, byFlags.size());
    assertEquals(byFlags, byConfig);
  }

  @Test
  void headersNotInFixedList_HashWithColumnMap_ExtraColumnIgnored() throws Exception {
    Path extract = write("site-headers.csv", String.join("\n",
      "PAT_ID,GIVEN,SURNAME,DOB_TXT,SOC,WARD",
      "P1,Alice,Smith,2001/02/03,123-45-6780,North",
      "P2,Bobby,Jones,1975/11/30,,South",
      "P3,Carol,Brown,1960/07/04,987-65-4320,East") + "\n");
    List<String> lines = requiredKeys(extract, newDir());
    lines.addAll(List.of(
      "input.date_format=uuuu/MM/dd",
      "column.patient_id=PAT_ID",
      "column.first_name=GIVEN",
      "column.last_name=SURNAME",
      "column.birth_date=DOB_TXT",
      "column.ssn=SOC"));
    List<String> byConfig = hash("--config", writeConfig(lines).toString());
    List<String> expected = hash(flagArgs(write("standard.csv", STANDARD_EXTRACT), newDir()));
    assertEquals(3, byConfig.size());
    assertEquals(expected, byConfig);
  }

  @Test
  void columnKey_OtherFixedListHeaderForFieldIgnored() throws Exception {
    // "id" is in the fixed list for patient_id. column.patient_id names PAT_ID, so "id" is ignored and does not
    // count as a second column for patient_id.
    Path extract = write("two-ids.csv", String.join("\n",
      "id,PAT_ID,first_name,last_name,dob,ssn",
      "X1,P1,Alice,Smith,02/03/2001,123-45-6780",
      "X2,P2,Bobby,Jones,11/30/1975,",
      "X3,P3,Carol,Brown,07/04/1960,987-65-4320") + "\n");
    List<String> lines = requiredKeys(extract, newDir());
    lines.add("column.patient_id=PAT_ID");
    List<String> byConfig = hash("--config", writeConfig(lines).toString());
    List<String> expected = hash(flagArgs(write("standard.csv", STANDARD_EXTRACT), newDir()));
    assertEquals(expected, byConfig);
  }

  @Test
  void withConfig_TwoColumnsForOneField_StopsTheRun() throws Exception {
    Path extract = write("dup.csv", String.join("\n",
      "ID,PATIENT_ID,first_name,last_name,dob",
      "X1,P1,Alice,Smith,02/03/2001") + "\n");
    Path out = newDir();
    LinkjaException exc = assertThrows(LinkjaException.class,
      () -> hash("--config", writeConfig(requiredKeys(extract, out)).toString()));
    assertTrue(exc.getMessage().contains(Engine.PATIENT_ID_FIELD), exc.getMessage());
    assertTrue(exc.getMessage().contains("\"ID\"") && exc.getMessage().contains("\"PATIENT_ID\""), exc.getMessage());
    assertNoOutput(out);
  }

  @Test
  void noConfig_IdAndPatientId_StopsTheRun() throws Exception {
    // Ticket #88: two columns for one field stop every run, with or without a run config.
    Path extract = write("id-and-patient-id.csv", String.join("\n",
      "ID,first_name,last_name,dob,ssn,PATIENT_ID",
      "X1,Alice,Smith,02/03/2001,123-45-6780,P1") + "\n");
    Path out = newDir();
    LinkjaException exc = assertThrows(LinkjaException.class, () -> hash(flagArgs(extract, out)));
    assertEquals("The field patient_id has more than one column: \"ID\" and \"PATIENT_ID\". "
      + "Keep one column for each field and run again.", exc.getMessage());
    assertNoOutput(out);
  }

  @Test
  void flagWinsOverConfig() throws Exception {
    Path extract = write("standard.csv", STANDARD_EXTRACT);
    List<String> lines = requiredKeys(extract, newDir());
    lines.add("input.delimiter=|");
    String config = writeConfig(lines).toString();
    assertEquals('|', parameters("--config", config).getDelimiter());
    assertEquals(',', parameters("--config", config, "--delimiter", ",").getDelimiter());
  }

  @Test
  void dateFormatKey_ReadIntoParameters() throws Exception {
    Path extract = write("standard.csv", STANDARD_EXTRACT);
    List<String> lines = requiredKeys(extract, newDir());
    lines.add("input.date_format=uuuu/MM/dd");
    EngineParameters parameters = parameters("--config", writeConfig(lines).toString());
    assertEquals("2001-02-03", java.time.LocalDate.parse("2001/02/03", parameters.getDateOfBirthFormatter()).toString());
  }

  @Test
  void missingRequiredKey_StopsBeforeOutput_NamesKey() throws Exception {
    Path extract = write("standard.csv", STANDARD_EXTRACT);
    Path out = newDir();
    List<String> lines = requiredKeys(extract, out);
    lines.removeIf(line -> line.startsWith("site.private_date="));
    String config = writeConfig(lines).toString();
    Exception exc = assertThrows(Exception.class, () -> hash("--config", config));
    assertTrue(exc.getMessage().contains("site.private_date"), exc.getMessage());
    assertNoOutput(out);
  }

  @Test
  void columnKeyNamesNoHeader_StopsBeforeOutput_NamesKeyAndHeader() throws Exception {
    Path extract = write("standard.csv", STANDARD_EXTRACT);
    Path out = newDir();
    List<String> lines = requiredKeys(extract, out);
    lines.add("column.first_name=GIVEN");
    String config = writeConfig(lines).toString();
    LinkjaException exc = assertThrows(LinkjaException.class, () -> hash("--config", config));
    assertTrue(exc.getMessage().contains("column.first_name"), exc.getMessage());
    assertTrue(exc.getMessage().contains("GIVEN"), exc.getMessage());
    assertNoOutput(out);
  }

  // ---- Helpers ----

  private static EngineParameters parameters(String... args) throws Exception {
    return Runner.buildParameters(Runner.parseCommandLine(Runner.setUpCommandLine(), args));
  }

  /** Runs hashing the way Runner.main does, and returns the decrypted hash rows, sorted. */
  private static List<String> hash(String... args) throws Exception {
    EngineParameters parameters = parameters(args);
    HashParameters hashParameters = Runner.parseProjectSalt(parameters.getSaltFile(), parameters.getMinSaltLength());
    hashParameters.setPrivateDate(parameters.getPrivateDate());
    // CI has only the public build of the C library, which has no secure hash calls. This engine returns the hash
    // value unchanged in their place, so the hash file holds the plain hash values. All other steps are real.
    new Engine(parameters, hashParameters) {
      @Override
      String createSecureHash(String hash, byte[] sessionKey, String rowId, String tokenId) {
        return hash;
      }

      @Override
      String revertSecureHash(String secureHash, byte[] sessionKey, String rowId, String tokenId) {
        return secureHash;
      }
    }.run();
    return decryptHashFile(parameters.getOutputDirectory());
  }

  private static String[] flagArgs(Path extract, Path out) {
    return new String[] { "--saltFile", saltFile.toString(), "--encryptionKey", publicKey.toString(),
      "--privateDate", PRIVATE_DATE, "--patientFile", extract.toString(), "--outDirectory", out.toString() };
  }

  private static List<String> requiredKeys(Path extract, Path out) {
    return new ArrayList<>(List.of(
      "site.salt_file=" + saltFile,
      "aggregator.public_key=" + publicKey,
      "site.private_date=" + PRIVATE_DATE,
      "input.file=" + extract,
      "output.directory=" + out));
  }

  private static Path writeConfig(List<String> lines) throws Exception {
    return Files.writeString(Files.createTempFile(dir, "run", ".properties"), String.join("\n", lines) + "\n");
  }

  private static Path write(String name, String content) throws Exception {
    return Files.writeString(Files.createTempDirectory(dir, "in").resolve(name), content);
  }

  private static Path newDir() throws Exception {
    return Files.createTempDirectory(dir, "out");
  }

  private static void assertNoOutput(Path out) throws Exception {
    try (Stream<Path> files = Files.list(out)) {
      assertEquals(List.of(), files.collect(Collectors.toList()));
    }
  }

  /**
   * Reads the one hash file in the folder, and returns each row of hash values as one string, sorted. The session key
   * comes out of the RSA envelope. The hash values need no reverting, because the test stubs createSecureHash.
   */
  private static List<String> decryptHashFile(Path out) throws Exception {
    File hashFile;
    try (Stream<Path> files = Files.list(out)) {
      List<Path> hashFiles = files.filter(p -> p.getFileName().toString().startsWith("hashes_")).collect(Collectors.toList());
      assertEquals(1, hashFiles.size());
      hashFile = hashFiles.get(0).toFile();
    }
    List<String> rows = new ArrayList<>();
    try (BufferedInputStream stream = new BufferedInputStream(new FileInputStream(hashFile))) {
      EncryptedHashFileMetadata metadata = EncryptedHashFileMetadata.read(stream, privateKey.toFile());
      for (long row = 1; row <= metadata.getNumHashRows(); row++) {
        String[] values = new String[metadata.getNumHashColumns()];
        for (int token = 1; token <= values.length; token++) {
          byte[] block = stream.readNBytes(HASH_BLOCK_SIZE);
          assertEquals(HASH_BLOCK_SIZE, block.length);
          values[token - 1] = (block[0] == 0x00) ? "" : new String(block);
        }
        rows.add(String.join(",", values));
      }
      assertEquals(-1, stream.read(), "The hash file has more blocks than its row count");
    }
    rows.sort(null);
    return rows;
  }

  private static String pem(String type, byte[] der) {
    return String.format("-----BEGIN %s-----\n%s\n-----END %s-----\n", type,
      Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der), type);
  }

  private static String randomHex() {
    byte[] bytes = new byte[32];
    new SecureRandom().nextBytes(bytes);
    return HexFormat.of().formatHex(bytes);
  }
}
