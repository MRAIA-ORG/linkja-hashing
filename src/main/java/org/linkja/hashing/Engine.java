package org.linkja.hashing;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVPrinter;
import org.apache.commons.csv.CSVRecord;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.linkja.core.crypto.AesEncryptParameters;
import org.linkja.crypto.AesResult;
import org.linkja.crypto.Library;
import org.linkja.hashing.steps.*;
import org.linkja.core.*;

import java.io.*;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

public class Engine {
  public static final int MIN_NUM_FIELDS = 4;

  // Global rules that may be needed across multiple processing steps
  public static final int MIN_NAME_LENGTH = 2;

  public static final int SESSION_KEY_LENGTH = 32;

  private static final String EMPTY_HASH = "";

  // Open options of the output files: a run fails, and does not change the file, when a file of that name is there.
  private static final OpenOption[] NEW_FILE = { StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE };

  // List the canonical names for anticipated fields
  public static final String PATIENT_ID_FIELD = "patient_id";
  public static final String FIRST_NAME_FIELD = "first_name";
  public static final String LAST_NAME_FIELD = "last_name";
  public static final String DATE_OF_BIRTH_FIELD = "date_of_birth";
  public static final String SOCIAL_SECURITY_NUMBER = "social_security_number";
  public static final String EXCLUSION = "exclusion";

  // List other canonical field names, used for output
  public static final String SITE_ID_FIELD = "siteid";
  public static final String PROJECT_ID_FIELD = "projectid";

  // Special fields used for different types of output files
  public static final String INVALID_DATA_ROW_NUMBER_FIELD = "row_number";
  public static final String INVALID_DATA_ERROR_DESCRIPTION_FIELD = "error_description";

  private static final String REQUIRED_COLUMNS_EXCEPTION_MESSAGE = "We require, at a minimum, columns for patient ID, first name, last name, and date of birth.\r\n" +
          "If you have these columns present, please make sure that the column header is specified, and that the column names are in our list of " +
          "recognized values.  Please see the project README for more information.";

  private EngineParameters parameters;
  private static HashParameters hashParameters;
  private DataHeaderMap patientDataHeaderMap;
  private static HashMap<String, String> canonicalHeaderNames = null;
  private static ArrayList<String> prefixes = null;
  private static ArrayList<String> suffixes = null;
  private static HashMap<String, String> genericNames = null;
  private static HashMap<String, String> fieldIds = null;

  private int numSubmittedJobs = 0;
  private int numCompletedJobs = 0;
  private int numInputRows = 0;
  private int numInvalidRows = 0;
  private int numDerivedRows = 0;
  private int outputRowIndex = 0;

  private HashingStep hashingStep = null;

  private ArrayList<String> executionReport = new ArrayList<String>();

  private DateTimeFormatter fileTimestampFormatter = DateTimeFormatter.ofPattern("yyyyMMddHHmmss");


  public Engine(EngineParameters parameters, HashParameters hashParameters) {
    this.parameters = parameters;
    this.hashParameters = hashParameters;
    this.patientDataHeaderMap = new DataHeaderMap();
  }

  /**
   * Performs initialization and setup for the Engine.  This assumes that it has been given all of the parameters.
   * This should be called if any parameters change.
   * @throws IOException
   * @throws URISyntaxException
   * @throws LinkjaException
   */
  public void initialize() throws IOException, URISyntaxException, LinkjaException {
    if (this.canonicalHeaderNames == null) {
      this.canonicalHeaderNames = new HashMap<String, String>();
      try (InputStream csvStream = getClass().getResourceAsStream("/configuration/canonical-header-names.csv")) {
		CSVFormat format = CSVFormat.DEFAULT.builder().setHeader().get();
        CSVParser parser = CSVParser.parse(csvStream, Charset.defaultCharset(), format);
        for (CSVRecord csvRecord : parser) {
          this.canonicalHeaderNames.put(csvRecord.get(0).trim().toLowerCase(), csvRecord.get(1).trim().toLowerCase());
        }
      }
    }

    if (this.prefixes == null) {
      this.prefixes = new ArrayList<String>();
      try (BufferedReader buffer = new BufferedReader(new InputStreamReader(getClass().getResourceAsStream("/configuration/prefixes.txt")))) {
        this.prefixes.addAll(buffer.lines().collect(Collectors.toList()));
      }
    }

    if (this.suffixes == null) {
      this.suffixes = new ArrayList<String>();
      try (BufferedReader buffer = new BufferedReader(new InputStreamReader(getClass().getResourceAsStream("/configuration/suffixes.txt")))) {
        this.suffixes.addAll(buffer.lines().collect(Collectors.toList()));
      }
    }

    if (this.genericNames == null) {
      this.genericNames = new HashMap<String, String>();
      try (InputStream csvStream = getClass().getResourceAsStream("/configuration/generic-names.csv")) {
		CSVFormat format = CSVFormat.DEFAULT.builder().setHeader().get();
        CSVParser parser = CSVParser.parse(csvStream, Charset.defaultCharset(), format);
        for (CSVRecord csvRecord : parser) {
          String name = csvRecord.get(0);
          String match = csvRecord.get(1);
          ExclusionStep.addMatchRuleToCollection(name, match, csvRecord.getRecordNumber(), this.genericNames);
        }
      }
    }

    if (this.fieldIds == null) {
      this.fieldIds = new HashMap<String, String>();
      try (InputStream csvStream = getClass().getResourceAsStream("/configuration/field-ids.csv")) {
		CSVFormat format = CSVFormat.DEFAULT.builder().setHeader().get();
        CSVParser parser = CSVParser.parse(csvStream, Charset.defaultCharset(), format);
        for (CSVRecord csvRecord : parser) {
          // We match our canonical field names as case-insensitive, but note that we want to take the mapped field ID
          // exactly as it is entered (with the exception of leading/trailing whitespace).
          this.fieldIds.put(csvRecord.get(0).trim().toLowerCase(), csvRecord.get(1).trim());
        }
      }
    }

    if (this.hashingStep == null) {
      this.hashingStep = new HashingStep(Engine.hashParameters, this.fieldIds);
    }
  }

  /**
   * Internal conversion method to take a CSVRecord and convert it to a canonical DataRow structure
   * @param csvRecord The CSVRecord to conver
   * @return A DataRow representing the data
   */
  public DataRow csvRecordToDataRow(CSVRecord csvRecord) {
    DataRow row = new DataRow();
    for (DataHeaderMapEntry entry : this.patientDataHeaderMap.getEntries()) {
      row.put(entry.getCanonicalName() == null ? entry.getOriginalName() : entry.getCanonicalName(),
              csvRecord.get(entry.getOriginalName()));
    }
    row.setRowNumber(csvRecord.getRecordNumber());
    return row;
  }

  /**
   * Helper method to attempt closing all of our file writers
   * @param hashStream
   * @param crosswalkWriter
   * @param invalidDataWriter
   * @throws IOException
   */
  private void closeWriters(BufferedOutputStream hashStream, BufferedWriter crosswalkWriter, BufferedWriter invalidDataWriter) throws IOException {
    if (hashStream != null) {
      hashStream.flush();
      hashStream.close();
    }

    if (crosswalkWriter != null) {
      crosswalkWriter.close();
    }

    if (invalidDataWriter != null) {
      invalidDataWriter.close();
    }
  }

  /**
   * Run the hashing pipeline, given the current configuration
   * @throws IOException
   * @throws URISyntaxException
   * @throws LinkjaException
   */
  public void run() throws IOException, URISyntaxException, LinkjaException, InterruptedException {
    initialize();

    try (BufferedReader csvReader = new BufferedReader(new FileReader(parameters.getPatientFile()))) {
      CSVFormat format = CSVFormat.DEFAULT.builder()
							.setHeader()
							.setDelimiter(this.parameters.getDelimiter())
							.get();
	  CSVParser parser = CSVParser.parse(csvReader, format);
      this.patientDataHeaderMap.createFromCSVHeader(parser.getHeaderNames()).mergeCanonicalHeaders(this.canonicalHeaderNames, this.parameters.getColumnMap());
      verifyFields();

      // Because our check for unique patient IDs requires knowing every ID that has been seen, and because our processing
      // steps do not hold state, we are performing this check as we load up our worker queue.
      HashSet<String> uniquePatientIds = new HashSet<>();
      int patientIdIndex = this.patientDataHeaderMap.findIndexOfCanonicalName(PATIENT_ID_FIELD);

      // Build our thread pool and task queue - these are configured with a set number of threads (that the user can define),
      // and will run such that that number of threads is the total amount of work we have queued up.
      ExecutorService threadPool = createThreadPool(parameters.getNumWorkerThreads());
      ExecutorCompletionService<List<DataRow>> taskQueue = new ExecutorCompletionService<List<DataRow>>(threadPool);

      // Open up our output streams for hash results, crosswalks and invalid results.  We may have an optional 4th file
      // for a file mixing hashes and PHI.
      String fileTimestamp = LocalDateTime.now().format(fileTimestampFormatter);
      Path hashPath = Paths.get(this.parameters.getOutputDirectory().toString(),
              String.format("hashes_%s_%s_%s.enc", hashParameters.getSiteId(), hashParameters.getProjectId(), fileTimestamp));
      Path crosswalkPath = Paths.get(this.parameters.getOutputDirectory().toString(),
              String.format("DONOTSEND_crosswalk_%s_%s_%s.csv", hashParameters.getSiteId(), hashParameters.getProjectId(), fileTimestamp));
      Path invalidDataPath = Paths.get(this.parameters.getOutputDirectory().toString(),
              String.format("DONOTSEND_invaliddata_%s_%s_%s.csv", hashParameters.getSiteId(), hashParameters.getProjectId(), fileTimestamp));

      // Each output file is opened only if it is not there yet, so every file in createdPaths is this run's own. If the
      // run does not finish, the finally block below stops the workers, closes the files and removes those files, so a
      // partial file is never taken for a finished one.
      List<Path> createdPaths = new ArrayList<>();
      BufferedOutputStream hashStream = null;
      BufferedWriter crosswalkWriter = null;
      BufferedWriter invalidDataWriter = null;
      boolean finished = false;
      Throwable failure = null;

      // Reset all of our tracking counters right before we begin the processing cycle
      this.numSubmittedJobs = 0;
      this.numCompletedJobs = 0;
      this.numInvalidRows = 0;
      this.numDerivedRows = 0;
      this.numInputRows = 0;
      this.outputRowIndex = 0;

      try {
        try {
          hashStream = new BufferedOutputStream(openOutput(hashPath));
          createdPaths.add(hashPath);
          crosswalkWriter = openWriter(crosswalkPath);
          createdPaths.add(crosswalkPath);
          invalidDataWriter = openWriter(invalidDataPath);
          createdPaths.add(invalidDataPath);
        } catch (FileAlreadyExistsException exc) {
          throw new LinkjaException(String.format("The output file %s is already there. Move it out of the output folder, and run again.", exc.getFile()));
        }
        CSVPrinter crosswalkPrinter = createCrosswalkPrinter(crosswalkWriter);
        CSVPrinter invalidDataPrinter = createInvalidDataPrinter(invalidDataWriter);

        byte[] sessionKey = Library.generateKey(SESSION_KEY_LENGTH);
        EncryptedHashFileMetadata metadata = initializeHashStream(hashStream, sessionKey, parameters.getEncryptionKeyFile());

        int batchSize = this.parameters.getBatchSize();
        int numThreads = this.parameters.getNumWorkerThreads();
        ArrayList<DataRow> batch = new ArrayList<DataRow>(batchSize);  // Pre-allocate the memory
        for (CSVRecord csvRecord : parser) {
          String patientId = csvRecord.get(patientIdIndex).trim();
          // If the patient ID is empty, we're not going to track it (that'd be a false error if there are multiple
          // blank fields on different rows).  Note that we're not throwing out the record as invalid at this point.  We
          // probably could, but we're delegating all of that work to our worker steps.
          if (!patientId.equals("")) {
            if (uniquePatientIds.contains(patientId)) {
              threadPool.shutdownNow();
              throw new LinkjaException(String.format("Patient IDs must be unique within the data file.  A duplicate copy of Patient ID %s was found on row %d.",
                patientId.trim(), csvRecord.getRecordNumber()));
            }
            uniquePatientIds.add(patientId);
          }

          // We want to get our CSV data into a format that we can better act on within the application.  Load it to the
          // data structure we created for this work.
          DataRow row = csvRecordToDataRow(csvRecord);
          batch.add(row);
          this.numInputRows++;

          // Once we have a batch of work to do, create a new processing task.
          if (batch.size() == batchSize) {
            batch.trimToSize();  // Free up unused space
            taskQueue.submit(new EngineWorkerThread(batch, this.parameters.isRunNormalizationStep(),
              this.parameters.getRecordExclusionMode(),
              this.prefixes, this.suffixes, this.genericNames, this.parameters.getDateOfBirthFormatter()));
            batch.clear();  // The worker thread has its copy, so we can clear ours out to start a new batch
            this.numSubmittedJobs++;

            System.out.printf("Loaded %d records for hashing\r\n", csvRecord.getRecordNumber());

            // As we submit a new batch to be worked on, we will look to see if we're exceeding the number of threads we
            // wanted to have running.  If so, we'll start clearing up results (if they are done) and writing them up, which
            // will keep memory usage manageable.
            // A problem here throws, so the finally block below stops the work and removes the files.
            while (((ThreadPoolExecutor) threadPool).getActiveCount() >= numThreads) {
              processPendingWork(taskQueue, hashStream, sessionKey, crosswalkPrinter, invalidDataPrinter, false);
            }
          }
        }

        // If we have a partial batch that was filled, make sure it gets submitted to the work queue
        if (batch.size() > 0) {
          batch.trimToSize();
          taskQueue.submit(new EngineWorkerThread(batch, this.parameters.isRunNormalizationStep(),
            this.parameters.getRecordExclusionMode(),
            this.prefixes, this.suffixes, this.genericNames, this.parameters.getDateOfBirthFormatter()));
          this.numSubmittedJobs++;
        }

        processPendingWork(taskQueue, hashStream, sessionKey, crosswalkPrinter, invalidDataPrinter, true);
        closeWriters(hashStream, crosswalkWriter, invalidDataWriter);

        // Everything worked out okay.  Because it isn't until the end that we know the total number of rows written,
        // this is where we need to update the metadata in our output file to include the total number of rows.
        int totalHashedRows = (this.numInputRows - this.numInvalidRows + this.numDerivedRows);
        if (metadata != null) {
          metadata.setNumHashRows(totalHashedRows);
          metadata.writeUpdatedNumHashRows(hashPath.toFile());
        }

        executionReport.add("Completed processing results:");
        executionReport.add(String.format("  %d data rows read", this.numInputRows));
        executionReport.add(String.format("  %d total hashed rows created", totalHashedRows));
        executionReport.add(String.format("     %d original data rows hashed", (totalHashedRows - this.numDerivedRows)));
        executionReport.add(String.format("     %d derived rows hashed", this.numDerivedRows));
        executionReport.add(String.format("  %d invalid rows", this.numInvalidRows));

        threadPool.shutdown();

        // Ensure at this point (as a final sanity check) that all of our submitted jobs have been tracked to completion
        if (this.numCompletedJobs != this.numSubmittedJobs) {
          throw new LinkjaException(String.format("We are missing %d jobs - expected %d, tracked %d to completion.",
                  (this.numSubmittedJobs - this.numCompletedJobs), this.numSubmittedJobs, this.numCompletedJobs));
        }
        finished = true;
      } catch (Throwable exc) {
        failure = exc;
        throw exc;
      } finally {
        if (!finished) {
          threadPool.shutdownNow();
          removeUnfinishedOutput(new Closeable[] { hashStream, crosswalkWriter, invalidDataWriter }, createdPaths, failure);
        }
      }
    }
  }

  /**
   * Open one new output file. Package-private so that a test can see when a run closes its files, or make a close fail.
   */
  OutputStream openOutput(Path path) throws IOException {
    return Files.newOutputStream(path, NEW_FILE);
  }

  /** A UTF-8 writer on openOutput(path). It is the writer that Files.newBufferedWriter(path, NEW_FILE) gives. */
  private BufferedWriter openWriter(Path path) throws IOException {
    return new BufferedWriter(new OutputStreamWriter(openOutput(path), StandardCharsets.UTF_8.newEncoder()));
  }

  /** The worker thread pool of one run. Package-private so that a test can check that a run shuts it down. */
  ExecutorService createThreadPool(int numThreads) {
    return new ThreadPoolExecutor(numThreads, numThreads, 30, TimeUnit.MINUTES,
            new ArrayBlockingQueue<Runnable>(numThreads), new ThreadPoolExecutor.CallerRunsPolicy());
  }

  /**
   * Close the output files of a run that did not finish, and remove the ones the run made. Each file is closed and
   * removed on its own, so one failure does not stop the others. When the run stopped on an error, a failure here is
   * added to that error as a suppressed exception, so it does not hide it. Otherwise the first failure is thrown.
   */
  private static void removeUnfinishedOutput(Closeable[] files, List<Path> createdPaths, Throwable failure) throws IOException {
    IOException problem = null;
    for (Closeable file : files) {
      try {
        if (file != null) {
          file.close();
        }
      } catch (IOException exc) {
        problem = addProblem(problem, exc, failure);
      }
    }
    for (Path path : createdPaths) {
      try {
        Files.deleteIfExists(path);
      } catch (IOException exc) {
        problem = addProblem(problem, exc, failure);
      }
    }
    if (problem != null) {
      throw problem;
    }
  }

  /** Adds exc to failure when there is one (and returns null), else to problem. Returns the problem to throw. */
  private static IOException addProblem(IOException problem, IOException exc, Throwable failure) {
    if (failure != null) {
      failure.addSuppressed(exc);
      return null;
    }
    if (problem == null) {
      return exc;
    }
    problem.addSuppressed(exc);
    return problem;
  }

  /**
   * Check our queue of submitted work tasks and process the completed rows (writing them to our putput CSV).
   * @param taskQueue
   * @param hashStream
   * @param sessionKey
   * @param crosswalkPrinter
   * @param invalidDataPrinter
   * @param waitUntilComplete
   * @throws LinkjaException When a worker or the writing of a result fails. The message names the failure.
   */
  private void processPendingWork(ExecutorCompletionService<List<DataRow>> taskQueue, BufferedOutputStream hashStream,
                                     byte[] sessionKey, CSVPrinter crosswalkPrinter, CSVPrinter invalidDataPrinter,
                                     boolean waitUntilComplete) throws LinkjaException {
    try {
      // Go through at least once to check the status of our jobs and process pending results.  If the flag has been
      // set to wait until everything is completed, we will stay in a loop checking for completed work.
      do {
        // If we have completed all of the submitted jobs, we are all done.  If we have some outstanding, we are going to
        // set a polling timeout.
        if (this.numCompletedJobs == this.numSubmittedJobs) {
          System.out.println("All jobs have been processed");
          return;
        }

        Future<List<DataRow>> task = taskQueue.poll(500, TimeUnit.MILLISECONDS);
        while (task != null) {
          writeDataRowResults(task.get(), hashStream, sessionKey, crosswalkPrinter, invalidDataPrinter);
          this.numCompletedJobs++;
          task = taskQueue.poll(500, TimeUnit.MILLISECONDS);
        }

        // We will sleep briefly just so we're not churning waiting for work to finish.
        if (waitUntilComplete) {
          System.out.println("Waiting for all working threads to complete...");
          Thread.sleep(1000);
        }
      } while (waitUntilComplete);
    }
    catch (Exception exc) {
      if (exc instanceof InterruptedException) {
        Thread.currentThread().interrupt();  // Keep the interrupt for the caller
      }
      // A worker failure comes wrapped in an ExecutionException. Name the failure inside it. An Error, e.g. a
      // LinkageError of the crypto C library, is thrown as it is, the same as when the run thread throws it.
      Throwable cause = (exc instanceof ExecutionException && exc.getCause() != null) ? exc.getCause() : exc;
      if (cause instanceof Error) {
        throw (Error) cause;
      }
      String reason = (cause.getMessage() != null) ? cause.getMessage() : cause.toString();
      LinkjaException stop = new LinkjaException("The run stopped while writing the results: " + reason);
      stop.initCause(exc);
      throw stop;
    }
  }

  /**
   * Utility method to create the CSVPrinter object with the appropriate header columns (based on parameters on how
   * the Engine should run)
    * @param hashStream An open file writer to connect the CSVPrinter to
   * @return The instantiated CSVPrinter object
   * @throws IOException
   */
  private EncryptedHashFileMetadata initializeHashStream(BufferedOutputStream hashStream, byte[] sessionKey, File rsaPublicKey) throws IOException, LinkjaException {
    EncryptedHashFileMetadata metadata = new EncryptedHashFileMetadata(this.hashParameters.getSiteId(), this.hashParameters.getProjectId(), 11, 0, sessionKey, Library.getLibrarySignature());
    metadata.write(hashStream, rsaPublicKey);
    return metadata;
  }

  private void writeEncryptedHashHeader(BufferedOutputStream hashStream, AesEncryptParameters encryptParameters, String header) throws LinkjaException, IOException {
    writeEncryptedString(hashStream, encryptParameters, header, 128);
  }

  private void writeEncryptedString(BufferedOutputStream hashStream, AesEncryptParameters encryptParameters, String data, int padLength) throws LinkjaException, IOException {
    AesResult encryptResult = Library.aesEncrypt(StringUtils.rightPad(data, padLength).getBytes(), encryptParameters.getAad(), encryptParameters.getKey(), encryptParameters.getIv());
    if (encryptResult == null) {
      throw new LinkjaException("Failed to encrypt string");
    }
    hashStream.write(ArrayUtils.addAll(encryptResult.data, encryptResult.tag));
  }

  /**
   * Creates a CSVPrinter object to be used for creating our crosswalk data
   * @param writer
   * @return
   * @throws IOException
   */
  private CSVPrinter createCrosswalkPrinter(BufferedWriter writer) throws IOException {
	CSVFormat format = CSVFormat.DEFAULT.builder()
						.setHeader(Engine.PATIENT_ID_FIELD, HashingStep.PIDHASH_FIELD)
						.get();  
    return new CSVPrinter(writer, format);
  }

  /**
   * Creates a CSVPrinter object to be used for creating our invalid data file
   * @param writer
   * @return
   * @throws IOException
   */
  private CSVPrinter createInvalidDataPrinter(BufferedWriter writer) throws IOException {
	  CSVFormat format = CSVFormat.DEFAULT.builder()
						  .setHeader(
						    Engine.INVALID_DATA_ROW_NUMBER_FIELD,
							Engine.PATIENT_ID_FIELD,
							Engine.FIRST_NAME_FIELD,
							Engine.LAST_NAME_FIELD,
							Engine.DATE_OF_BIRTH_FIELD,
							Engine.SOCIAL_SECURITY_NUMBER,
							Engine.INVALID_DATA_ERROR_DESCRIPTION_FIELD
							)
						  .get();  
      return new CSVPrinter(writer, format);
  }

  /**
   * Write out a collection of DataRow results
   * @param hashStream
   * @param crosswalkPrinter
   * @param invalidDataPrinter
   * @param rows
   * @throws IOException
   */
  private void writeDataRowResults(List<DataRow> rows, BufferedOutputStream hashStream, byte[] sessionKey,
                                   CSVPrinter crosswalkPrinter, CSVPrinter invalidDataPrinter) throws LinkjaException, IOException {
    if (rows == null) {
      return;
    }

    for (DataRow row : rows) {
      writeDataRowResult(row, hashStream, sessionKey, crosswalkPrinter, invalidDataPrinter);
    }
  }

  /**
   * Create our secured (pseudo-encrypted) hash given the current hash string and the position
   * of the hash in the output file.
   * @param hash
   * @param rowId
   * @param tokenId
   * @return
   */
  private String getSecureHashString(String hash, byte[] sessionKey, String rowId, String tokenId) {
    if (hash == null || hash == "") {
      return "";
    }

    return createSecureHash(hash, sessionKey, rowId, tokenId).toUpperCase();
  }

  private byte[] getSecureHash(String hash, byte[] sessionKey, String rowId, String tokenId) {
    if (hash == null || hash == "") {
      return new byte[64];
    }

    return createSecureHash(hash, sessionKey, rowId, tokenId).toUpperCase().getBytes();
  }

  /**
   * The two calls below need the secret build of linkja-crypto. They are their own methods so that a test can run
   * the whole engine with the public build, which is the build CI has.
   */
  String createSecureHash(String hash, byte[] sessionKey, String rowId, String tokenId) {
    return Library.createSecureHash(hash, sessionKey, rowId, tokenId);
  }

  String revertSecureHash(String secureHash, byte[] sessionKey, String rowId, String tokenId) {
    return Library.revertSecureHash(secureHash, sessionKey, rowId, tokenId);
  }

  /**
   * Utility method to write out the appropriate columns for a data row.
   * @param hashStream
   * @param crosswalkPrinter
   * @param invalidDataPrinter
   * @param row
   * @throws IOException
   */
  private void writeDataRowResult(DataRow row, BufferedOutputStream hashStream, byte[] sessionKey,
                                  CSVPrinter crosswalkPrinter, CSVPrinter invalidDataPrinter) throws IOException {
    if (row == null) {
      return;
    }

    // If the SSN is not set, we write out a blank string.  Although we can generate a hash with a blank SSN, it's
    // potentially misleading during the matching phase, so we choose instead to not provide output for SSN-related hashes.
    boolean hasSsn = !(row.get(Engine.SOCIAL_SECURITY_NUMBER) == null || row.get(Engine.SOCIAL_SECURITY_NUMBER).equals(""));
    boolean shouldProcess = row.shouldProcess();
    if (shouldProcess) {
      // We only do hashing outside of our worker threads because we need to know the order the rows are being written
      // to the output file.
      hashingStep.run(row);
      shouldProcess = row.shouldProcess(); // Update status in case hashing failed
      if (shouldProcess) {
        this.outputRowIndex++;
        String rowIdString = Long.toString(this.outputRowIndex);

        String securePidHash = getSecureHashString(safeGetRowField(row, HashingStep.PIDHASH_FIELD), sessionKey, rowIdString, "1");
        String auditablePidHash = revertSecureHash(securePidHash, sessionKey, rowIdString, "1").toUpperCase();
        crosswalkPrinter.printRecord(row.get(Engine.PATIENT_ID_FIELD), auditablePidHash);

        hashStream.write(securePidHash.getBytes());
        hashStream.write(getSecureHash(safeGetRowField(row, HashingStep.FNAMELNAMEDOBSSN_FIELD, hasSsn), sessionKey, rowIdString, "2"));
        hashStream.write(getSecureHash(safeGetRowField(row, HashingStep.LNAMEFNAMEDOBSSN_FIELD, hasSsn), sessionKey, rowIdString, "3"));
        hashStream.write(getSecureHash(safeGetRowField(row, HashingStep.FNAMELNAMEDOB_FIELD), sessionKey, rowIdString, "4"));
        hashStream.write(getSecureHash(safeGetRowField(row, HashingStep.LNAMEFNAMEDOB_FIELD), sessionKey, rowIdString, "5"));
        hashStream.write(getSecureHash(safeGetRowField(row, HashingStep.FNAMELNAMETDOBSSN_FIELD, hasSsn), sessionKey, rowIdString, "6"));
        hashStream.write(getSecureHash(safeGetRowField(row, HashingStep.FNAMELNAMETDOB_FIELD), sessionKey, rowIdString, "7"));
        hashStream.write(getSecureHash(safeGetRowField(row, HashingStep.FNAME3LNAMEDOBSSN_FIELD, hasSsn), sessionKey, rowIdString, "8"));
        hashStream.write(getSecureHash(safeGetRowField(row, HashingStep.FNAME3LNAMEDOB_FIELD), sessionKey, rowIdString, "9"));
        hashStream.write(getSecureHash(safeGetRowField(row, HashingStep.FNAMELNAMEDOBDSSN_FIELD, hasSsn), sessionKey, rowIdString, "10"));
        hashStream.write(getSecureHash(safeGetRowField(row, HashingStep.FNAMELNAMEDOBYSSN_FIELD, hasSsn), sessionKey, rowIdString, "11"));

        // Process all derived rows as well
        if (row.hasDerivedRows()) {
          for (DataRow derivedRow : row.getDerivedRows()) {
            this.numDerivedRows++;
            writeDataRowResult(derivedRow, hashStream, sessionKey, crosswalkPrinter, invalidDataPrinter);
          }
        }
      }
    }

    if (!shouldProcess) {
      this.numInvalidRows++;
      invalidDataPrinter.printRecord(
              row.getRowNumber(),
              row.get(Engine.PATIENT_ID_FIELD),
              row.get(Engine.FIRST_NAME_FIELD),
              row.get(Engine.LAST_NAME_FIELD),
              row.get(Engine.DATE_OF_BIRTH_FIELD),
              hasSsn ? row.get(Engine.SOCIAL_SECURITY_NUMBER) : "",
              row.getInvalidReason().replaceAll("\r\n", "|"));
    }
  }

  private String safeGetRowField(DataRow row, String rowName) {
    return safeGetRowField(row, rowName, true);
  }

  private String safeGetRowField(DataRow row, String rowName, boolean shouldProcess) {
    if (!shouldProcess || !row.containsKey(rowName)) {
      return EMPTY_HASH;
    }
    return (String)row.get(rowName);
  }

  /**
   * Utility method for development purposes only.  This writes a given data row
   * to the console.
   * @param row The DataRow to write out
   */
  private void dumpRow(DataRow row) {
    dumpRow(row, 0);
  }

  /**
   * Utility method for development purposes only.  This writes a given data row
   * to the console.
   * @param row The DataRow to write out
   * @param indentLevel The number of spaces to indent output (used for nested derived rows)
   */
  private void dumpRow(DataRow row, int indentLevel) {
    String indentString = new String(new char[indentLevel*2]).replace("\0", " ");
    for (Map.Entry<String,Object> entry : row.entrySet()) {
      System.out.printf("%s%s - %s\r\n", indentString, entry.getKey(), entry.getValue());
    }
    if (row.getInvalidReason() != null && !row.getInvalidReason().equals("")) {
      System.out.printf("%sINVALID REASON: - %s\r\n", indentString, row.getInvalidReason());
    }
    if (row.hasDerivedRows()) {
      System.out.printf("%sDERIVED ROWS:\r\n", indentString);
      for (DataRow derivedRow : row.getDerivedRows()) {
        dumpRow(derivedRow, indentLevel+1);
      }
    }
    System.out.println();
  }

  /**
   * Ensures that the data fields loaded meet our minimum expectations regarding number of fields, and inclusion of
   * required fields
   * @throws LinkjaException
   */
  public void verifyFields() throws LinkjaException {
    if (this.patientDataHeaderMap == null || this.patientDataHeaderMap.size() < MIN_NUM_FIELDS) {
      throw new LinkjaException(REQUIRED_COLUMNS_EXCEPTION_MESSAGE);
    }

    if (!this.patientDataHeaderMap.containsCanonicalColumn(PATIENT_ID_FIELD)
      || !this.patientDataHeaderMap.containsCanonicalColumn(FIRST_NAME_FIELD)
      || !this.patientDataHeaderMap.containsCanonicalColumn(LAST_NAME_FIELD)
      || !this.patientDataHeaderMap.containsCanonicalColumn(DATE_OF_BIRTH_FIELD)) {
      throw new LinkjaException(REQUIRED_COLUMNS_EXCEPTION_MESSAGE);
    }
  }

  public EngineParameters getParameters() {
    return parameters;
  }

  public ArrayList<String> getExecutionReport() {
    return executionReport;
  }
}
