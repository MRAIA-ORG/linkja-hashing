package org.linkja.hashing;


import org.linkja.core.*;
import org.apache.commons.cli.*;

import java.io.*;
import java.nio.charset.CharacterCodingException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeMap;

// TODO: Write unit tests for helper methods (everything but main)
public class Runner {
  private static final String COLUMN_KEY_PREFIX = "column.";
  // The run config keys other than "column.<field>". DataHeaderMap checks the field of each column key.
  private static final Set<String> RUN_CONFIG_KEYS = Set.of("site.salt_file", "aggregator.public_key",
    "site.private_date", "input.file", "input.delimiter", "input.date_format", "output.directory");

  public static void main(String[] args) {
    Options options = setUpCommandLine();
    CommandLine cmd = parseCommandLine(options, args);

    // If the command line initialization failed, we will stop the program now.  Displaying instructions to the user
    // is already handled by the setup and parser methods.
    if (cmd == null) {
      System.exit(1);
    }

    if (cmd.hasOption("version")) {
      displayVersion();
      System.exit(0);
    }

    long startTime = System.nanoTime();

    // Our parameters come from the command line, the run config (--config) and a local config.properties file.
    EngineParameters parameters = null;
    try {
      parameters = buildParameters(cmd);
    }
    catch (Exception exc) {
      displayUsage();
      System.out.println();
      if (exc.getMessage() != null) {
        System.out.println(exc.getMessage());
      }
      System.exit(1);
    }

    HashParameters hashParameters = null;
    try {
      hashParameters = parseProjectSalt(parameters.getSaltFile(), parameters.getMinSaltLength());
      hashParameters.setPrivateDate(parameters.getPrivateDate());  // Provide a copy to our hashing parameters collection
    }
    catch (Exception exc) {
      System.out.println("ERROR - We encountered an error when trying to decrypt the salt file using the private key");
      System.out.println(exc.getMessage());
      System.exit(1);
    }

    try {
      Engine engine = new Engine(parameters, hashParameters);
      engine.run();

      String report = String.join("\r\n", engine.getExecutionReport());
      System.out.println(report);
    }
    catch (Exception exc) {
      System.out.println("ERROR - We encountered an error while processing your data file");
      System.out.println(exc.getMessage());
      System.exit(1);
    }

    long endTime = System.nanoTime();

    double elapsedSeconds = (double)(endTime - startTime) / 1_000_000_000.0;
    System.out.printf("Total execution time: %2f sec\n", elapsedSeconds);
  }

  /**
   * Collect the settings of a hashing run from the command line, the run config (--config) and config.properties.
   * A command-line flag wins over the same key in the run config.
   * @param cmd The parsed command line
   * @return The settings for the engine
   * @throws Exception When a required setting is missing or invalid. No output file exists yet at this point.
   */
  public static EngineParameters buildParameters(CommandLine cmd) throws Exception {
    Properties runConfig = cmd.hasOption("config") ? loadRunConfig(cmd.getOptionValue("config")) : null;
    EngineParameters parameters = new EngineParameters();
    parameters.setSaltFile(requiredSetting(cmd, runConfig, "saltFile", "site.salt_file"));
    parameters.setPatientFile(requiredSetting(cmd, runConfig, "patientFile", "input.file"));
    parameters.setPrivateDate(requiredSetting(cmd, runConfig, "privateDate", "site.private_date"));
    parameters.setEncryptionKeyFile(requiredSetting(cmd, runConfig, "encryptionKey", "aggregator.public_key"));
    parameters.setDelimiter(setting(cmd, runConfig, "delimiter", "input.delimiter",
      new String(new char[] { EngineParameters.DEFAULT_DELIMITER })));  // A blank value stops the run, as on develop
    parameters.setRecordExclusionMode(parseRecordExclusionMode(cmd.getOptionValue("exclusionMode")));
    parameters = loadConfig(parameters);
    String outputDirectory = setting(cmd, runConfig, "outDirectory", "output.directory", null);
    if (outputDirectory == null || outputDirectory.trim().isEmpty()) {
      Path path = FileSystems.getDefault().getPath("").toAbsolutePath();
      outputDirectory = path.toString();
      System.out.printf("Results will be written to %s\r\n", outputDirectory);
    }
    parameters.setOutputDirectory(outputDirectory.trim());

    if (runConfig != null) {
      parameters.setDateFormat(runConfig.getProperty("input.date_format"));
      parameters.setColumnMap(columnMap(runConfig));
    }

    if (!parameters.hashingModeOptionsSet()) {
      throw new LinkjaException("Not all of the required parameters were provided");
    }
    return parameters;
  }

  /**
   * Read the run config, a Java Properties (key=value) file in UTF-8. A byte order mark at the start is dropped.
   * @throws LinkjaException When the file is not found or not UTF-8, or a key is not a run config key, e.g. a typo
   *                         such as input.date_fromat
   */
  public static Properties loadRunConfig(String path) throws IOException, LinkjaException {
    String text;
    try {
      text = Files.readString(Paths.get(path));
    }
    catch (NoSuchFileException exc) {
      throw new LinkjaException(String.format("The run config file %s was not found.", path));
    }
    catch (CharacterCodingException exc) {
      throw new LinkjaException(String.format("The run config file %s is not UTF-8. Save it as UTF-8 and run again.", path));
    }
    Properties runConfig = new Properties();
    runConfig.load(new StringReader(text.startsWith("\uFEFF") ? text.substring(1) : text));
    for (String key : runConfig.stringPropertyNames()) {
      if (!key.startsWith(COLUMN_KEY_PREFIX) && !RUN_CONFIG_KEYS.contains(key)) {
        throw new LinkjaException(unknownKeyMessage(text, key));
      }
    }
    return runConfig;
  }

  /**
   * The message for an unknown key. A line with no separator is read as one long key, and that line can hold a
   * value such as the private date. So the key is named only when its line also has a value after it and the key
   * looks like a key name, e.g. not the first part of a data row from a wrong file.
   */
  private static String unknownKeyMessage(String text, String key) {
    String[] lines = text.split("\\R");
    for (int index = 0; index < lines.length; index++) {
      String line = lines[index].strip();
      if (line.startsWith(key)) {
        String named = (line.length() > key.length() && key.matches("[A-Za-z0-9_.]+")) ? key + " on " : "";
        return String.format("The run config key %sline %d is not a known key. Check its spelling in the README.",
          named, index + 1);
      }
    }
    return "The run config has a key that is not a known key. Check the spelling of each key in the README.";
  }

  /**
   * The value of one setting, as given: the command-line flag if given, else the run config key, else the fallback.
   */
  private static String setting(CommandLine cmd, Properties runConfig, String flag, String key, String fallback) {
    String value = cmd.getOptionValue(flag);
    if (value == null && runConfig != null) {
      value = runConfig.getProperty(key);
    }
    return (value == null) ? fallback : value;
  }

  /** A required setting, trimmed. A blank value counts as missing. */
  private static String requiredSetting(CommandLine cmd, Properties runConfig, String flag, String key) throws LinkjaException {
    String value = setting(cmd, runConfig, flag, key, null);
    if (value == null || value.trim().isEmpty()) {
      throw new LinkjaException(String.format("The required setting %s is missing. Set it in the run config, or give --%s.", key, flag));
    }
    return value.trim();
  }

  /**
   * The column keys of the run config: field name (the part after "column.") to input extract header.
   */
  private static Map<String, String> columnMap(Properties runConfig) {
    Map<String, String> columns = new TreeMap<String, String>();
    for (String key : runConfig.stringPropertyNames()) {
      if (key.startsWith(COLUMN_KEY_PREFIX)) {
        columns.put(key.substring(COLUMN_KEY_PREFIX.length()), runConfig.getProperty(key).trim());
      }
    }
    return columns;
  }

  public static HashParameters parseProjectSalt(File saltFile, int minSaltLength) throws Exception {
    SaltFile file = new SaltFile();
    file.setMinSaltLength(minSaltLength);
    file.load(saltFile);

    HashParameters parameters = new HashParameters();
    parameters.setSiteId(file.getSiteID());
    parameters.setSiteName(file.getSiteName());
    parameters.setPrivateSalt(file.getPrivateSalt());
    parameters.setProjectSalt(file.getProjectSalt());
    parameters.setProjectId(file.getProjectName());
    return parameters;
  }

  public static void displayVersion() {
    System.out.printf("linkja-hashing v%s\r\n", Runner.class.getPackage().getImplementationVersion());
    System.out.printf("linkja-crypto signature: %s\r\n", (new org.linkja.crypto.Library()).getLibrarySignature());
  }

  /**
   * Load the configuration properties file for the hashing system, and add the values into the EngineParameters
   * @param parameters The collection of parameters used by the engine
   * @return A modified collection of parameters used by the engine
   * @throws IOException
   */
  public static EngineParameters loadConfig(EngineParameters parameters) throws IOException, LinkjaException {
    InputStream inputStream = null;
    try {
      Properties prop = new Properties();
      inputStream = Runner.class.getClassLoader().getResourceAsStream("config.properties");

      if (inputStream != null) {
        prop.load(inputStream);
      }
      else {
        throw new FileNotFoundException("The properties file 'config.properties' could not be found in the classpath");
      }

      parameters.setRecordExclusionMode(parseRecordExclusionMode(prop.getProperty("recordExclusionMode")));
      parameters.setRunNormalizationStep(prop.getProperty("runNormalizationStep", Boolean.toString(EngineParameters.DEFAULT_RUN_NORMALIZATION_STEP)));
      parameters.setNumWorkerThreads(prop.getProperty("workerThreads", Integer.toString(EngineParameters.DEFAULT_WORKER_THREADS)));
      parameters.setBatchSize(prop.getProperty("batchSize", Integer.toString(EngineParameters.DEFAULT_BATCH_SIZE)));
      parameters.setMinSaltLength(prop.getProperty("minSaltLength", Integer.toString(EngineParameters.DEFAULT_MIN_SALT_LENGTH)));
    }
    finally {
      if (inputStream != null) {
        inputStream.close();
      }
    }

    return parameters;
  }

  /**
   * Utility method to take a string representation of the record exception mode, and convert it to an internal enum
   * @param option The string value to process
   * @return The EngineParameters.RecordExclusionMode enum value
   * @throws LinkjaException
   */
  public static EngineParameters.RecordExclusionMode parseRecordExclusionMode(String option) throws LinkjaException {
    if (option == null || option.isEmpty()) {
      return EngineParameters.DEFAULT_RECORD_EXCLUSION_MODE;
    }

    if (option.equalsIgnoreCase("None")) {
      return EngineParameters.RecordExclusionMode.NoExclusions;
    }
    else if (option.equalsIgnoreCase("Generate")) {
      return EngineParameters.RecordExclusionMode.GenerateExclusions;
    }
    else if (option.equalsIgnoreCase("Included")) {
      return EngineParameters.RecordExclusionMode.ExclusionsIncluded;
    }

    throw new LinkjaException("For the exclusionMode parameter, please specify a value of None, Generate or Included");
  }

  /**
   * Helper method to prepare our command line options
   * @return Collection of options to be used at the command line
   */
  public static Options setUpCommandLine() {
    Options options = new Options();

    Option versionOpt = new Option("v", "version", false, "Display the version of this program");
    versionOpt.setRequired(false);
    options.addOption(versionOpt);

    Option encryptionKeyFileOpt = new Option("key", "encryptionKey", true, "path to public key file to encrypt hashed output");
    encryptionKeyFileOpt.setRequired(false);
    options.addOption(encryptionKeyFileOpt);

    Option saltFileOpt = new Option("salt", "saltFile", true, "path to salt file");
    saltFileOpt.setRequired(false);
    options.addOption(saltFileOpt);

    Option patientFileOpt = new Option("patient", "patientFile", true, "path to the file containing patient data");
    patientFileOpt.setRequired(false);
    options.addOption(patientFileOpt);

    Option privateDateOpt = new Option("date", "privateDate", true, "the private date (as MM/DD/YYYY)");
    privateDateOpt.setRequired(false);
    options.addOption(privateDateOpt);

    Option outputDirectoryOpt = new Option("out", "outDirectory", true, "the base directory to create output.  If not specified, will use the current directory.");
    outputDirectoryOpt.setRequired(false);
    options.addOption(outputDirectoryOpt);

    Option configOpt = new Option("config", "config", true, "path to the run config file (key=value)");
    configOpt.setRequired(false);
    options.addOption(configOpt);

    Option delimiterOpt = new Option("delim", "delimiter", true, "the delimiter used within the patient data file");
    delimiterOpt.setRequired(false);
    options.addOption(delimiterOpt);

    return options;
  }

  /**
   * Helper method to wrap parsing the command line parameters and reconcile them against the required and optional
   * command line options.
   * @param options Allowed options
   * @param args Actual command line arguments
   * @return Reconciled CommandLine container, or null if unable to process
   */
  public static CommandLine parseCommandLine(Options options, String[] args) {
    CommandLineParser parser = new DefaultParser();
    CommandLine cmd = null;
    try {
      cmd = parser.parse(options, args);
    } catch (ParseException e) {
      displayUsage();
      System.out.println();
      System.out.println(e.getMessage());
      return null;
    }

    return cmd;
  }

  /**
   * Helper method to display expected command line parameters
   */
  public static void displayUsage() {
    System.out.println();
    System.out.println("Usage: java -jar Hashing.jar [--version] [--config <run config file>]");
    System.out.println();
    System.out.println("HASHING (Default Mode)");
    System.out.println("-------------");
    System.out.println("Required parameters:");
    System.out.println("  -date,--privateDate <arg>         The private date (as MM/DD/YYYY)");
    System.out.println("  -key,--encryptionKey <arg>        Path to the aggregator's public key file, to");
    System.out.println("                                    encrypt results.");
    System.out.println("  -patient,--patientFile <arg>      Path to the file containing patient data");
    System.out.println("  -salt,--saltFile <arg>            Path to salt file");
    System.out.println();
    System.out.println("Each required parameter can instead come from the run config (--config).");
    System.out.println("A parameter on the command line wins over the same key in the run config.");
    System.out.println();
    System.out.println("Optional parameters:");
    System.out.println("  -config,--config <arg>            Path to the run config file. See the README.");
    System.out.println("  -out,--outDirectory <arg>         The base directory to create output. If not");
    System.out.println("                                    specified, will use the current directory.");
    System.out.println("  -delim,--delimiter <arg>          The delimiter used within the patient data");
    System.out.println("                                    file. Uses a comma \",\" by default.");
    System.out.println();
  }
}
