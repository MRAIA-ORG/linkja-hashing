package org.linkja.hashing;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
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

  @ParameterizedTest
  @ValueSource(strings = { "site.salt_file", "aggregator.public_key", "site.private_date", "input.file" })
  void missingRequiredKey_StopsBeforeOutput_NamesKey(String key) throws Exception {
    Path extract = write("standard.csv", STANDARD_EXTRACT);
    Path out = newDir();
    List<String> lines = requiredKeys(extract, out);
    lines.removeIf(line -> line.startsWith(key + "="));
    String config = writeConfig(lines).toString();
    Exception exc = assertThrows(Exception.class, () -> hash("--config", config));
    assertTrue(exc.getMessage().contains(key), exc.getMessage());
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


  // ---- Review round 1 ----

  @Test
  void twoColumnKeysNameOneHeader_StopsTheRun() throws Exception {
    Path extract = write("given-twice.csv", String.join("\n",
      "patient_id,GIVEN,first_name,last_name,dob",
      "P1,Alice,Al,Smith,02/03/2001") + "\n");
    Path out = newDir();
    List<String> lines = requiredKeys(extract, out);
    lines.addAll(List.of("column.first_name=GIVEN", "column.last_name=GIVEN"));
    String config = writeConfig(lines).toString();
    LinkjaException exc = assertThrows(LinkjaException.class, () -> hash("--config", config));
    assertTrue(exc.getMessage().contains("column.first_name"), exc.getMessage());
    assertTrue(exc.getMessage().contains("column.last_name"), exc.getMessage());
    assertTrue(exc.getMessage().contains("\"GIVEN\""), exc.getMessage());
    assertNoOutput(out);
  }

  @Test
  void columnKeyNamesRepeatedHeader_StopsTheRun() throws Exception {
    Path extract = write("repeated-given.csv", String.join("\n",
      "patient_id,GIVEN,GIVEN,last_name,dob",
      "P1,Alice,Bobby,Smith,02/03/2001") + "\n");
    Path out = newDir();
    List<String> lines = requiredKeys(extract, out);
    lines.add("column.first_name=GIVEN");
    String config = writeConfig(lines).toString();
    LinkjaException exc = assertThrows(LinkjaException.class, () -> hash("--config", config));
    assertEquals("The field first_name has more than one column: \"GIVEN\" and \"GIVEN\". "
      + "Keep one column for each field and run again.", exc.getMessage());
    assertNoOutput(out);
  }

  @Test
  void dateFormat_DayFirst_HashesAsIsoDatesByFlags() throws Exception {
    Path extract = write("day-first.csv", String.join("\n",
      "patient_id,first_name,last_name,dob,ssn",
      "P1,Alice,Smith,03/02/2001,123-45-6780",
      "P2,Bobby,Jones,30/11/1975,",
      "P3,Carol,Brown,04/07/1960,987-65-4320") + "\n");
    Path iso = write("iso.csv", String.join("\n",
      "patient_id,first_name,last_name,dob,ssn",
      "P1,Alice,Smith,2001-02-03,123-45-6780",
      "P2,Bobby,Jones,1975-11-30,",
      "P3,Carol,Brown,1960-07-04,987-65-4320") + "\n");
    List<String> lines = requiredKeys(extract, newDir());
    lines.add("input.date_format=dd/MM/uuuu");
    List<String> byConfig = hash("--config", writeConfig(lines).toString());
    assertEquals(3, byConfig.size());
    assertEquals(hash(flagArgs(iso, newDir())), byConfig);
  }

  @Test
  void dateFormat_OtherFormatRow_GoesToInvalidData() throws Exception {
    Path extract = write("mixed.csv", String.join("\n",
      "patient_id,first_name,last_name,dob,ssn",
      "P1,Alice,Smith,2001/02/03,123-45-6780",
      "P2,Bobby,Jones,02/03/2001,") + "\n");
    Path out = newDir();
    List<String> lines = requiredKeys(extract, out);
    lines.add("input.date_format=uuuu/MM/dd");
    assertEquals(1, hash("--config", writeConfig(lines).toString()).size());
    String invalid = readOne(out, "DONOTSEND_invaliddata_");
    assertTrue(invalid.contains("P2"), invalid);
    assertFalse(invalid.contains("P1"), invalid);
  }

  @Test
  void dateFormat_YearWithY_StopsAndSaysUseUuuu() throws Exception {
    Path out = newDir();
    List<String> lines = requiredKeys(write("standard.csv", STANDARD_EXTRACT), out);
    lines.add("input.date_format=yyyy/MM/dd");
    String config = writeConfig(lines).toString();
    Exception exc = assertThrows(Exception.class, () -> hash("--config", config));
    assertTrue(exc.getMessage().contains("uuuu"), exc.getMessage());
    assertTrue(exc.getMessage().contains("input.date_format"), exc.getMessage());
    assertNoOutput(out);
  }

  @Test
  void dateFormat_TwoDigitYear_StopsAndSaysUseUuuu() throws Exception {
    Path out = newDir();
    List<String> lines = requiredKeys(write("standard.csv", STANDARD_EXTRACT), out);
    lines.add("input.date_format=dd/MM/uu");
    String config = writeConfig(lines).toString();
    Exception exc = assertThrows(LinkjaException.class, () -> hash("--config", config));
    assertTrue(exc.getMessage().contains("two-digit year"), exc.getMessage());
    assertTrue(exc.getMessage().contains("uuuu"), exc.getMessage());
    assertNoOutput(out);
  }

  @Test
  void dateFormat_NoDay_StopsAndSaysNoDay() throws Exception {
    List<String> lines = requiredKeys(write("standard.csv", STANDARD_EXTRACT), newDir());
    lines.add("input.date_format=uuuu/MM");
    String config = writeConfig(lines).toString();
    Exception exc = assertThrows(LinkjaException.class, () -> parameters("--config", config));
    assertTrue(exc.getMessage().contains("no day"), exc.getMessage());
  }

  @ParameterizedTest
  @ValueSource(strings = { "dd/MM/uuuu HH:mm", "uuuu-MM-dd'T'HH:mm", "uuuu-MM-dd HH:mm:ss" })
  void dateFormat_WithTimeOfDay_Accepted(String pattern) throws Exception {
    List<String> lines = requiredKeys(write("standard.csv", STANDARD_EXTRACT), newDir());
    lines.add("input.date_format=" + pattern);
    assertNotNull(parameters("--config", writeConfig(lines).toString()).getDateOfBirthFormatter());
  }

  @Test
  void dateFormat_WithTimeOfDay_HashesAsIsoDateByFlags() throws Exception {
    Path extract = write("with-time.csv", String.join("\n",
      "patient_id,first_name,last_name,dob,ssn",
      "P1,Alice,Smith,03/02/2001 00:00,123-45-6780") + "\n");
    Path iso = write("iso.csv", String.join("\n",
      "patient_id,first_name,last_name,dob,ssn",
      "P1,Alice,Smith,2001-02-03,123-45-6780") + "\n");
    List<String> lines = requiredKeys(extract, newDir());
    lines.add("input.date_format=dd/MM/uuuu HH:mm");
    List<String> byConfig = hash("--config", writeConfig(lines).toString());
    assertEquals(1, byConfig.size());
    assertEquals(hash(flagArgs(iso, newDir())), byConfig);
  }

  @Test
  void columnKey_FieldNameCaseIgnored() throws Exception {
    Path extract = write("renamed.csv", String.join("\n",
      "patient_id,GIVEN,last_name,dob,ssn",
      "P1,Alice,Smith,02/03/2001,123-45-6780",
      "P2,Bobby,Jones,11/30/1975,",
      "P3,Carol,Brown,07/04/1960,987-65-4320") + "\n");
    List<String> lines = requiredKeys(extract, newDir());
    lines.add("column.FIRST_NAME=GIVEN");
    List<String> byConfig = hash("--config", writeConfig(lines).toString());
    assertEquals(hash(flagArgs(write("standard.csv", STANDARD_EXTRACT), newDir())), byConfig);
  }

  @Test
  void blankRequiredKey_StopsAndNamesKey() throws Exception {
    List<String> lines = requiredKeys(write("standard.csv", STANDARD_EXTRACT), newDir());
    lines.removeIf(line -> line.startsWith("site.salt_file="));
    lines.add("site.salt_file=");
    String config = writeConfig(lines).toString();
    Exception exc = assertThrows(LinkjaException.class, () -> parameters("--config", config));
    assertTrue(exc.getMessage().contains("site.salt_file"), exc.getMessage());
  }

  @Test
  void lineWithNoSeparator_StopsWithoutPrintingTheLine() throws Exception {
    List<String> lines = requiredKeys(write("standard.csv", STANDARD_EXTRACT), newDir());
    lines.removeIf(line -> line.startsWith("site.private_date="));
    lines.add("site.private_date" + PRIVATE_DATE);
    String config = writeConfig(lines).toString();
    Exception exc = assertThrows(LinkjaException.class, () -> parameters("--config", config));
    assertFalse(exc.getMessage().contains(PRIVATE_DATE), exc.getMessage());
    assertTrue(exc.getMessage().contains("line " + lines.size()), exc.getMessage());
  }

  @Test
  void dataRowAsConfig_StopsWithoutPrintingTheRow() throws Exception {
    Path config = write("wrong-file.csv", "P1,Alice Smith," + PRIVATE_DATE + "\n");
    Exception exc = assertThrows(LinkjaException.class, () -> parameters("--config", config.toString()));
    assertFalse(exc.getMessage().contains("Alice"), exc.getMessage());
    assertTrue(exc.getMessage().contains("line 1"), exc.getMessage());
  }

  @Test
  void runConfigNotUtf8_StopsAndSaysUtf8() throws Exception {
    Path extract = write("standard.csv", STANDARD_EXTRACT);
    Path config = Files.createTempFile(dir, "latin1", ".properties");
    Files.write(config, (String.join("\n", requiredKeys(extract, newDir())) + "\n# caf\u00e9\n")
      .getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
    Exception exc = assertThrows(LinkjaException.class, () -> parameters("--config", config.toString()));
    assertTrue(exc.getMessage().contains("UTF-8"), exc.getMessage());
  }

  @Test
  void runConfigMissing_StopsAndSaysNotFound() throws Exception {
    String missing = dir.resolve("no-such-run.properties").toString();
    Exception exc = assertThrows(LinkjaException.class, () -> parameters("--config", missing));
    assertTrue(exc.getMessage().contains("not found"), exc.getMessage());
    assertTrue(exc.getMessage().contains(missing), exc.getMessage());
  }

  @Test
  void withConfig_IdAndPatientId_ColumnKeyPicksOne_Hashes() throws Exception {
    // The column map is applied before the one-column-per-field check, so naming PATIENT_ID drops ID.
    Path extract = write("id-and-patient-id.csv", String.join("\n",
      "ID,PATIENT_ID,first_name,last_name,dob,ssn",
      "X1,P1,Alice,Smith,02/03/2001,123-45-6780",
      "X2,P2,Bobby,Jones,11/30/1975,",
      "X3,P3,Carol,Brown,07/04/1960,987-65-4320") + "\n");
    List<String> lines = requiredKeys(extract, newDir());
    lines.add("column.patient_id=PATIENT_ID");
    List<String> byConfig = hash("--config", writeConfig(lines).toString());
    assertEquals(hash(flagArgs(write("standard.csv", STANDARD_EXTRACT), newDir())), byConfig);
  }

  @Test
  void unknownKey_StopsBeforeOutput_NamesKey() throws Exception {
    Path out = newDir();
    List<String> lines = requiredKeys(write("standard.csv", STANDARD_EXTRACT), out);
    lines.add("input.date_fromat=dd/MM/uuuu");
    String config = writeConfig(lines).toString();
    Exception exc = assertThrows(Exception.class, () -> hash("--config", config));
    assertTrue(exc.getMessage().contains("input.date_fromat"), exc.getMessage());
    assertNoOutput(out);
  }

  @ParameterizedTest
  @ValueSource(strings = { "\t", "", " " })
  void noConfig_BlankDelimiterFlag_Stops(String delimiter) throws Exception {
    String[] args = flagArgs(write("standard.csv", STANDARD_EXTRACT), newDir());
    String[] withDelimiter = java.util.Arrays.copyOf(args, args.length + 2);
    withDelimiter[args.length] = "--delimiter";
    withDelimiter[args.length + 1] = delimiter;
    Exception exc = assertThrows(LinkjaException.class, () -> parameters(withDelimiter));
    assertEquals("You may specify one non-whitespace character as your delimiter", exc.getMessage());
  }

  @Test
  void blankDelimiterKey_Stops() throws Exception {
    List<String> lines = requiredKeys(write("standard.csv", STANDARD_EXTRACT), newDir());
    lines.add("input.delimiter=");
    String config = writeConfig(lines).toString();
    Exception exc = assertThrows(LinkjaException.class, () -> parameters("--config", config));
    assertEquals("You may specify one non-whitespace character as your delimiter", exc.getMessage());
  }

  @Test
  void byteOrderMark_FirstKeyStillRead() throws Exception {
    Path extract = write("standard.csv", STANDARD_EXTRACT);
    Path config = Files.createTempFile(dir, "bom", ".properties");
    Files.writeString(config, "\uFEFF" + String.join("\n", requiredKeys(extract, newDir())) + "\n");
    assertEquals(saltFile.toFile(), parameters("--config", config.toString()).getSaltFile());
  }

  // ---- Ticket #98: run config messages ----

  @Test
  void lineWithNoSeparator_LettersOnly_NotPrinted() throws Exception {
    Exception exc = assertThrows(LinkjaException.class, () -> loadConfig("site.salt_filesalt\n"));
    assertFalse(exc.getMessage().contains("salt_filesalt"), exc.getMessage());
    assertTrue(exc.getMessage().contains("line 1"), exc.getMessage());
  }

  @ParameterizedTest
  @ValueSource(strings = { "site.private_dat=01/01/2018", "site.private_dat:01/01/2018",
    "site.private_dat = 01/01/2018", "site.private_date2018 01 01", "site.private_date2018\t01 01" })
  void unknownKey_NoTextAfterKeyPrinted(String line) throws Exception {
    Exception exc = assertThrows(LinkjaException.class, () -> loadConfig(line + "\n"));
    assertFalse(exc.getMessage().contains("2018"), exc.getMessage());
    assertFalse(exc.getMessage().contains("01 01"), exc.getMessage());
    assertTrue(exc.getMessage().contains("line 1"), exc.getMessage());
  }

  @Test
  void unknownKey_NamedWithEqualsOrColon() throws Exception {
    assertEquals("The run config key input.date_fromat on line 1 is not a known key. Check its spelling in the README.",
      assertThrows(LinkjaException.class, () -> loadConfig("input.date_fromat=dd/MM/uuuu\n")).getMessage());
    assertTrue(assertThrows(LinkjaException.class, () -> loadConfig("input.date_fromat : dd/MM/uuuu\n"))
      .getMessage().contains("input.date_fromat on line 1"));
  }

  @Test
  void unknownKey_LineNumberIsLineOfThatKey() throws Exception {
    Exception exc = assertThrows(LinkjaException.class, () -> loadConfig("site.salt_file=s.txt\nsite=1\n"));
    assertTrue(exc.getMessage().contains("line 2"), exc.getMessage());
  }

  @Test
  void unknownKey_AfterByteOrderMark_GivesLineNumber() throws Exception {
    Exception exc = assertThrows(LinkjaException.class, () -> loadConfig("\uFEFFinput.date_fromat=dd/MM/uuuu\n"));
    assertTrue(exc.getMessage().contains("input.date_fromat on line 1"), exc.getMessage());
  }

  @Test
  void unknownKey_ContinuedOverTwoLines_GivesFirstLine() throws Exception {
    Exception exc = assertThrows(LinkjaException.class,
      () -> loadConfig("site.salt_file=a\\\n  b\n# note\\\ninput.date_\\\n  fromat=x\n"));
    assertTrue(exc.getMessage().contains("line 4"), exc.getMessage());
  }

  @Test
  void unknownKey_AfterEscapedBackslash_NextLineIsNewEntry() throws Exception {
    Exception exc = assertThrows(LinkjaException.class,
      () -> loadConfig("site.salt_file=C:\\\\\ninput.date_fromat=x\n"));
    assertTrue(exc.getMessage().contains("input.date_fromat on line 2"), exc.getMessage());
  }

  @Test
  void unknownKey_LineAfterContinuedValue_IsNotSearchedAgain() throws Exception {
    Exception exc = assertThrows(LinkjaException.class, () -> loadConfig("site.salt_file=\\\nfoo=1\nfoo=2\n"));
    assertTrue(exc.getMessage().contains("foo on line 3"), exc.getMessage());
  }

  @Test
  void unknownKey_WithLeadingSpaces_IsNamed() throws Exception {
    Exception exc = assertThrows(LinkjaException.class, () -> loadConfig("  input.date_fromat=x\n"));
    assertTrue(exc.getMessage().contains("input.date_fromat on line 1"), exc.getMessage());
  }

  @Test
  void unknownKey_AfterNextLineCharInValue_CountsLinesLikeProperties() throws Exception {
    Exception exc = assertThrows(LinkjaException.class,
      () -> loadConfig("site.salt_file=a\u0085b\ninput.date_fromat=x\n"));
    assertTrue(exc.getMessage().contains("input.date_fromat on line 2"), exc.getMessage());
  }

  @Test
  void unknownKey_NotNamed_MessageReadsCorrectly() throws Exception {
    Exception exc = assertThrows(LinkjaException.class, () -> loadConfig("# a comment\nsite.salt_filesalt\n"));
    assertEquals("The run config has a key on line 2 that is not a known key. Check the spelling of each key in the README.",
      exc.getMessage());
  }

  @Test
  void runConfigIsDirectory_NamesPathAndSaysFile() throws Exception {
    String folder = newDir().toString();
    Exception exc = assertThrows(LinkjaException.class, () -> parameters("--config", folder));
    assertTrue(exc.getMessage().contains(folder), exc.getMessage());
    assertTrue(exc.getMessage().contains("must be a file"), exc.getMessage());
  }

  @Test
  void dateFormat_WithZoneOffset_HashesAsIsoDateByFlags() throws Exception {
    Path extract = write("with-offset.csv", String.join("\n",
      "patient_id,first_name,last_name,dob,ssn",
      "P1,Alice,Smith,2001-02-03 23:30 -05:00,123-45-6780") + "\n");
    Path iso = write("iso.csv", String.join("\n",
      "patient_id,first_name,last_name,dob,ssn",
      "P1,Alice,Smith,2001-02-03,123-45-6780") + "\n");
    List<String> lines = requiredKeys(extract, newDir());
    lines.add("input.date_format=uuuu-MM-dd HH:mm XXX");
    List<String> byConfig = hash("--config", writeConfig(lines).toString());
    assertEquals(1, byConfig.size());
    assertEquals(hash(flagArgs(iso, newDir())), byConfig);
  }

  // ---- Helpers ----

  private static java.util.Properties loadConfig(String text) throws Exception {
    return Runner.loadRunConfig(Files.writeString(Files.createTempFile(dir, "run", ".properties"), text).toString());
  }

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

  private static String readOne(Path out, String prefix) throws Exception {
    try (Stream<Path> files = Files.list(out)) {
      List<Path> matches = files.filter(p -> p.getFileName().toString().startsWith(prefix)).collect(Collectors.toList());
      assertEquals(1, matches.size());
      return Files.readString(matches.get(0));
    }
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
