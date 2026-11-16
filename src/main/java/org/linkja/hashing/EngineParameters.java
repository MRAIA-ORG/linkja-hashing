package org.linkja.hashing;

import org.linkja.core.*;
import org.linkja.hashing.steps.ValidationFilterStep;
import java.io.File;
import java.io.FileNotFoundException;
import java.nio.file.Path;
import java.security.InvalidParameterException;
import java.text.ParseException;
import java.time.DateTimeException;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.ResolverStyle;
import java.util.Map;

/**
 * This represents a consolidated collection of parameters needed to run the engine.
 */
public class EngineParameters {
  public enum RecordExclusionMode {
    NoExclusions, GenerateExclusions, ExclusionsIncluded
  }

  public static final int MIN_NUM_WORKER_THREADS = 1;
  public static final int MIN_BATCH_SIZE = 100;
  public static final int MIN_SALT_LENGTH = 1;

  public static final char DEFAULT_DELIMITER = ',';
  public static final RecordExclusionMode DEFAULT_RECORD_EXCLUSION_MODE = RecordExclusionMode.NoExclusions;
  public static final int DEFAULT_WORKER_THREADS = 3;
  public static final int DEFAULT_BATCH_SIZE = 1000;
  public static final boolean DEFAULT_RUN_NORMALIZATION_STEP = true;
  public static final int DEFAULT_MIN_SALT_LENGTH = 32;

  public static final DateTimeFormatter PrivateDateFormatter = DateTimeFormatter.ofPattern("MM/dd/yyyy");

  private File encryptionKeyFile;
  private File saltFile;
  private File patientFile;
  private LocalDate privateDate;
  private Path outputDirectory;
  private char delimiter = DEFAULT_DELIMITER;
  private RecordExclusionMode recordExclusionMode = DEFAULT_RECORD_EXCLUSION_MODE;
  private int numWorkerThreads = DEFAULT_WORKER_THREADS;
  private int batchSize = DEFAULT_BATCH_SIZE;
  private boolean runNormalizationStep = DEFAULT_RUN_NORMALIZATION_STEP;
  private FileHelper fileHelper;
  private int minSaltLength = DEFAULT_MIN_SALT_LENGTH;
  private DateTimeFormatter dateOfBirthFormatter = ValidationFilterStep.DATE_OF_BIRTH_FORMATTER;
  // Field name (as written after "column." in the run config) to input extract header. Null when the run has no
  // run config. A run config with no column keys gives an empty map.
  private Map<String, String> columnMap = null;

  public EngineParameters() {
    fileHelper = new FileHelper();
  }

  /**
   * Used for unit testing - use empty constructor otherwise
   * @param helper
   */
  public EngineParameters(FileHelper helper) {
    fileHelper = helper;
  }

  /**
   * Determine if all required parameters are set for the hashing mode
   * @return
   */
  public boolean hashingModeOptionsSet() {
    return getEncryptionKeyFile() != null
            && (getSaltFile() != null)
            && (getPatientFile() != null)
            && (getPrivateDate() != null);
  }

  public File getEncryptionKeyFile() {
    return encryptionKeyFile;
  }

  public void setEncryptionKeyFile(File encryptionKeyFile) throws FileNotFoundException {
    if (encryptionKeyFile != null && !fileHelper.exists(encryptionKeyFile)) {
      throw new FileNotFoundException(String.format("Unable to find encryption key file %s", encryptionKeyFile.toString()));
    }
    this.encryptionKeyFile = encryptionKeyFile;
  }

  public void setEncryptionKeyFile(String encryptionKeyFile) throws FileNotFoundException {
    if (encryptionKeyFile == null || encryptionKeyFile.equals("")) {
      setEncryptionKeyFile((File)null);
      return;
    }
    File file = new File(encryptionKeyFile);
    setEncryptionKeyFile(file);
  }

  /**
   * Helper function to tell us if we should encrypt the hashing results or not.
   * @return
   */
  public boolean isEncryptingOutput() {
    return this.encryptionKeyFile != null;
  }

  public File getSaltFile() {
    return saltFile;
  }

  public void setSaltFile(File saltFile) throws FileNotFoundException {
    if (!fileHelper.exists(saltFile)) {
      throw new FileNotFoundException(String.format("Unable to find encrypted salt file %s", saltFile.toString()));
    }
    this.saltFile = saltFile;
  }

  public void setSaltFile(String saltFile) throws FileNotFoundException {
    File file = new File(saltFile);
    setSaltFile(file);
  }

  public File getPatientFile() {
    return patientFile;
  }

  public void setPatientFile(File patientFile) throws FileNotFoundException {
    if (patientFile != null && !fileHelper.exists(patientFile)) {
      throw new FileNotFoundException(String.format("Unable to find patient data file %s", patientFile.toString()));
    }
    this.patientFile = patientFile;
  }

  public void setPatientFile(String patientFile) throws FileNotFoundException {
    if (patientFile == null || patientFile.equals("")) {
      setPatientFile((File)null);
      return;
    }

    File file = new File(patientFile);
    setPatientFile(file);
  }

  public LocalDate getPrivateDate() {
    return privateDate;
  }

  public void setPrivateDate(LocalDate privateDate) {
    this.privateDate = privateDate;
  }

  public void setPrivateDate(String privateDate) throws ParseException {
    if (privateDate == null || privateDate.equals("")) {
      setPrivateDate((LocalDate)null);
      return;
    }

    LocalDate parsedDate = LocalDate.parse(privateDate, PrivateDateFormatter);
    setPrivateDate(parsedDate);
  }

  public Path getOutputDirectory() {
    return outputDirectory;
  }

  public void setOutputDirectory(Path outputDirectory) throws FileNotFoundException {
    if (!fileHelper.exists(outputDirectory)) {
      throw new FileNotFoundException(String.format("Unable to find output directory %s", outputDirectory.toString()));
    }
    this.outputDirectory = outputDirectory;
  }

  public void setOutputDirectory(String outputDirectory) throws FileNotFoundException {
    Path path = fileHelper.pathFromString(outputDirectory);
    setOutputDirectory(path);
  }

  public char getDelimiter() {
    return delimiter;
  }

  public void setDelimiter(char delimiter) throws LinkjaException {
    String delimiterString = new String(new char[] { delimiter });
    setDelimiter(delimiterString);
  }

  public void setDelimiter(String delimiter) throws LinkjaException {
    if (delimiter == null || delimiter.trim().length() != 1) {
      throw new LinkjaException("You may specify one non-whitespace character as your delimiter");
    }
    this.delimiter = delimiter.trim().charAt(0);
  }

  public RecordExclusionMode getRecordExclusionMode() {
    return recordExclusionMode;
  }

  public void setRecordExclusionMode(RecordExclusionMode recordExclusionMode) {
    this.recordExclusionMode = recordExclusionMode;
  }

  public int getNumWorkerThreads() {
    return numWorkerThreads;
  }

  public void setNumWorkerThreads(int numWorkerThreads) {
    if (numWorkerThreads < MIN_NUM_WORKER_THREADS) {
      throw new InvalidParameterException(String.format("The number of worker threads must be >=%d", MIN_NUM_WORKER_THREADS));
    }
    this.numWorkerThreads = numWorkerThreads;
  }

  public void setNumWorkerThreads(String numWorkerThreads) {
    setNumWorkerThreads((numWorkerThreads == null) ? -1 : Integer.parseInt(numWorkerThreads.trim()));
  }

  public boolean isRunNormalizationStep() {
    return runNormalizationStep;
  }

  public void setRunNormalizationStep(boolean runNormalizationStep) {
    this.runNormalizationStep = runNormalizationStep;
  }

  public void setRunNormalizationStep(String runNormalization) {
    this.runNormalizationStep = (runNormalization == null) ?
            EngineParameters.DEFAULT_RUN_NORMALIZATION_STEP : Boolean.parseBoolean(runNormalization.trim());
  }

  public int getBatchSize() {
    return batchSize;
  }

  public void setBatchSize(int batchSize) {
    if (batchSize < MIN_BATCH_SIZE) {
      throw new InvalidParameterException(String.format("The batch size must be >=%d", MIN_BATCH_SIZE));
    }
    this.batchSize = batchSize;
  }

  public void setBatchSize(String batchSize) {
    setBatchSize((batchSize == null) ? -1 : Integer.parseInt(batchSize.trim()));
  }

  public int getMinSaltLength() {
    return minSaltLength;
  }

  public void setMinSaltLength(int minSaltLength) {
    if (minSaltLength < MIN_SALT_LENGTH) {
      throw new InvalidParameterException(String.format("The minimum allowable salt length must be >=%d", MIN_SALT_LENGTH));
    }
    this.minSaltLength = minSaltLength;
  }

  public void setMinSaltLength(String minSaltLength) {
    setMinSaltLength((minSaltLength == null) ? -1 : Integer.parseInt(minSaltLength.trim()));
  }

  /**
   * Make the birth date parser for one Java date pattern. The pattern needs 'uuuu' for the year, because the parser
   * uses the strict resolver, as the default parser does.
   */
  public static DateTimeFormatter dateOfBirthFormatter(String pattern) {
    return DateTimeFormatter.ofPattern(pattern).withResolverStyle(ResolverStyle.STRICT);
  }

  public DateTimeFormatter getDateOfBirthFormatter() {
    return dateOfBirthFormatter;
  }

  /**
   * @param pattern The input.date_format value. When it is null or empty, the default birth date formats apply.
   * @throws LinkjaException When the pattern cannot read back a full date, e.g. "yyyy/MM/dd", which the strict
   *                         resolver rejects for every date
   */
  public void setDateFormat(String pattern) throws LinkjaException {
    if (pattern == null || pattern.trim().isEmpty()) {
      this.dateOfBirthFormatter = ValidationFilterStep.DATE_OF_BIRTH_FORMATTER;
      return;
    }
    try {
      DateTimeFormatter formatter = dateOfBirthFormatter(pattern.trim());
      LocalDate sample = LocalDate.of(2001, 2, 3);
      LocalDate.parse(sample.format(formatter), formatter);
      this.dateOfBirthFormatter = formatter;
    }
    catch (DateTimeException | IllegalArgumentException exc) {
      throw new LinkjaException(String.format(
        "The input.date_format \"%s\" cannot read a full date. Use uuuu for the year, MM for the month and dd for the day, e.g. uuuu/MM/dd.",
        pattern.trim()));
    }
  }

  public Map<String, String> getColumnMap() {
    return columnMap;
  }

  public void setColumnMap(Map<String, String> columnMap) {
    this.columnMap = columnMap;
  }
}
