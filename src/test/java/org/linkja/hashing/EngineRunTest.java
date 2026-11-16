package org.linkja.hashing;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.linkja.core.LinkjaException;
import org.linkja.hashing.steps.HashingStep;

import java.io.InputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.time.LocalDate;
import java.util.Base64;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Runs the Engine on small synthetic extracts.
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

  private static final String ONE_COLUMN_PER_FIELD =
    "patient_id,first_name,last_name,date_of_birth,social_security_number\n" +
    "P001,Alice,Example,1980-01-15,234-56-7890\n" +
    "P002,Robert,Sample,1975-12-02,\n" +
    "P003,Carol,Testcase,2001-07-30,987-65-4320\n";

  @Test
  void run_TwoColumnsForPatientId_StopsBeforeAnyOutput(@TempDir Path dir) throws Exception {
    // ID is unique, PATIENT_ID repeats P001. Both resolve to patient_id.
    String extract =
      "ID,PATIENT_ID,first_name,last_name,date_of_birth\n" +
      "1,P001,Alice,Example,1980-01-15\n" +
      "2,P001,Robert,Sample,1975-12-02\n";
    Path patientFile = dir.resolve("patients.csv");
    Files.writeString(patientFile, extract);
    Path outputDir = Files.createDirectory(dir.resolve("out"));

    EngineParameters parameters = new EngineParameters();
    parameters.setPatientFile(patientFile.toFile());
    parameters.setOutputDirectory(outputDir);
    parameters.setEncryptionKeyFile(writePublicKey(dir).toFile());
    Engine engine = new Engine(parameters, createHashParameters());

    LinkjaException exc = assertThrows(LinkjaException.class, engine::run);
    assertTrue(exc.getMessage().contains(Engine.PATIENT_ID_FIELD), exc.getMessage());
    assertTrue(exc.getMessage().contains("\"ID\""), exc.getMessage());
    assertTrue(exc.getMessage().contains("\"PATIENT_ID\""), exc.getMessage());
    try (Stream<Path> files = Files.list(outputDir)) {
      assertEquals(0, files.count());
    }
  }

  /**
   * The hash file holds createSecureHash(value), and decrypting it gives back the value, so the values compared here
   * are the decrypted hash values. The test computes them on the same path Engine.run uses, short of the secure hash
   * step, which needs the secret build of the crypto library.
   */
  @Test
  void hashValues_OneColumnPerField_Unchanged() throws Exception {
    Set<String> expected = new HashSet<>();
    try (InputStream stream = getClass().getResourceAsStream(EXPECTED_HASHES_RESOURCE)) {
      for (String line : new String(stream.readAllBytes(), StandardCharsets.UTF_8).split("\n")) {
        if (!line.isBlank()) {
          expected.add(line);
        }
      }
    }
    assertEquals(expected, new HashSet<>(hashRows(ONE_COLUMN_PER_FIELD)));
  }

  @SuppressWarnings("unchecked")
  private List<String> hashRows(String extract) throws Exception {
    Engine engine = new Engine(new EngineParameters(), createHashParameters());
    engine.initialize();
    HashMap<String, String> canonicalHeaderNames =
      (HashMap<String, String>) FieldUtils.readStaticField(Engine.class, "canonicalHeaderNames", true);

    CSVParser parser = CSVParser.parse(new StringReader(extract), CSVFormat.DEFAULT.builder().setHeader().get());
    Map<String, Integer> csvHeaderMap = parser.getHeaderMap();
    DataHeaderMap headerMap = new DataHeaderMap().createFromCSVHeader(csvHeaderMap).mergeCanonicalHeaders(canonicalHeaderNames);
    FieldUtils.writeField(engine, "patientDataHeaderMap", headerMap, true);

    List<DataRow> rows = new ArrayList<>();
    for (CSVRecord record : parser) {
      rows.add(engine.csvRecordToDataRow(record));
    }
    rows = new EngineWorkerThread(rows, true, EngineParameters.DEFAULT_RECORD_EXCLUSION_MODE,
      (ArrayList<String>) FieldUtils.readStaticField(Engine.class, "prefixes", true),
      (ArrayList<String>) FieldUtils.readStaticField(Engine.class, "suffixes", true),
      (HashMap<String, String>) FieldUtils.readStaticField(Engine.class, "genericNames", true)).call();

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

  private static Path writePublicKey(Path dir) throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    byte[] der = generator.generateKeyPair().getPublic().getEncoded();
    String pem = "-----BEGIN PUBLIC KEY-----\n" + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der)
      + "\n-----END PUBLIC KEY-----\n";
    return Files.writeString(dir.resolve("public.pem"), pem);
  }

  private static HashParameters createHashParameters() {
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
