package org.linkja.hashing;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Ticket #99. The exit code and the output of Runner.runEngine, which Runner.main passes to System.exit. A failed run
 * must exit not 0 and print one "ERROR - " line that says what failed.
 */
class RunnerTest {
  private static final String ERROR_PREFIX = "ERROR - ";

  @Test
  void runEngine_FailsMidRun_ExitsNotZeroWithOneErrorLine(@TempDir Path dir) throws Exception {
    Path outputDir = Files.createDirectory(dir.resolve("out"));
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    int exitCode = Runner.runEngine(EngineRunTest.midRunFailingEngine(dir, outputDir), new PrintStream(out, true, StandardCharsets.UTF_8));

    assertNotEquals(0, exitCode);
    assertEquals(List.of("ERROR - The run failed: The run stopped while writing the results: secure hash failed"),
      errorLines(out));
    // The run removed its files, so the output names no output file.
    assertEquals(Set.of(), EngineRunTest.listFiles(outputDir));
    assertFalse(out.toString(StandardCharsets.UTF_8).toLowerCase().contains("output file"), out.toString(StandardCharsets.UTF_8));
  }

  @Test
  void runEngine_LibraryCannotLoad_ExitsNotZeroWithOneErrorLine(@TempDir Path dir) throws Exception {
    Path outputDir = Files.createDirectory(dir.resolve("out"));
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    int exitCode = Runner.runEngine(EngineRunTest.failingEngine(dir, outputDir, true), new PrintStream(out, true, StandardCharsets.UTF_8));

    assertNotEquals(0, exitCode);
    assertEquals(List.of("ERROR - The crypto C library could not be loaded: secure hash failed"), errorLines(out));
    assertEquals(Set.of(), EngineRunTest.listFiles(outputDir));
  }

  @Test
  void runEngine_Succeeds_ExitsZeroWithThreeFiles(@TempDir Path dir) throws Exception {
    Path outputDir = Files.createDirectory(dir.resolve("out"));
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    Engine engine = new Engine(EngineRunTest.runParameters(dir, outputDir), EngineRunTest.createHashParameters()) {
      @Override
      String createSecureHash(String hash, byte[] sessionKey, String rowId, String tokenId) {
        return hash;
      }
    };

    int exitCode = Runner.runEngine(engine, new PrintStream(out, true, StandardCharsets.UTF_8));

    assertEquals(0, exitCode);
    assertEquals(List.of(), errorLines(out));
    assertTrue(out.toString(StandardCharsets.UTF_8).startsWith("Completed processing results:"), out.toString(StandardCharsets.UTF_8));
    assertEquals(3, EngineRunTest.listFiles(outputDir).size());
  }

  /** Ticket #101. A LinkageError inside a worker thread keeps the library message, as on the run thread. */
  @Test
  void runEngine_LibraryCannotLoadInWorker_ExitsNotZeroWithLibraryMessage(@TempDir Path dir) throws Exception {
    Path outputDir = Files.createDirectory(dir.resolve("out"));
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    Engine engine = EngineRunTest.workerFailingEngine(dir, outputDir, () -> { throw new UnsatisfiedLinkError("library message"); });

    int exitCode = Runner.runEngine(engine, new PrintStream(out, true, StandardCharsets.UTF_8));

    assertNotEquals(0, exitCode);
    assertEquals(List.of("ERROR - The crypto C library could not be loaded: library message"), errorLines(out));
    assertEquals(Set.of(), EngineRunTest.listFiles(outputDir));
  }

  /** Ticket #101. Each of the 3 output files fails to close. The output has one "Also failed" line for each. */
  @Test
  void runEngine_CloseFails_PrintsOneAlsoFailedLinePerFile(@TempDir Path dir) throws Exception {
    Path outputDir = Files.createDirectory(dir.resolve("out"));
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    int exitCode = Runner.runEngine(EngineRunTest.closeFailingEngine(dir, outputDir), new PrintStream(out, true, StandardCharsets.UTF_8));

    assertNotEquals(0, exitCode);
    assertEquals(List.of("  Also failed: close failed", "  Also failed: close failed", "  Also failed: close failed"),
      out.toString(StandardCharsets.UTF_8).lines().filter(line -> line.startsWith("  Also failed: ")).collect(Collectors.toList()));
  }

  /**
   * Ticket #101. Runner.main in its own JVM, on a run that fails in Engine.run (two columns for patient_id). The process
   * must exit not 0 and print the ERROR line.
   */
  @Test
  void main_RunFails_ExitsNotZero(@TempDir Path dir) throws Exception {
    Path outputDir = Files.createDirectory(dir.resolve("out"));
    EngineParameters parameters = EngineRunTest.runParameters(dir, outputDir,
      "ID,PATIENT_ID,first_name,last_name,date_of_birth\n1,P001,Alice,Example,1980-01-15\n");
    byte[] salt = new byte[32];
    Path saltFile = Files.writeString(dir.resolve("salt.txt"), String.format("001,Test Site,%s,%s,Test Project\n",
      HexFormat.of().formatHex(salt), HexFormat.of().formatHex(salt)));

    Process process = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
      "-cp", System.getProperty("java.class.path"), Runner.class.getName(),
      "--saltFile", saltFile.toString(), "--encryptionKey", parameters.getEncryptionKeyFile().toString(),
      "--privateDate", "01/01/2018", "--patientFile", parameters.getPatientFile().toString(),
      "--outDirectory", outputDir.toString())
      .redirectErrorStream(true).start();
    String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    assertTrue(process.waitFor(60, TimeUnit.SECONDS), output);

    assertEquals(1, process.exitValue(), output);
    assertTrue(output.contains("ERROR - The run failed: The field patient_id has more than one column"), output);
    assertEquals(Set.of(), EngineRunTest.listFiles(outputDir));
  }

  private static List<String> errorLines(ByteArrayOutputStream out) {
    return out.toString(StandardCharsets.UTF_8).lines().filter(line -> line.startsWith(ERROR_PREFIX)).collect(Collectors.toList());
  }
}
