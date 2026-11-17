package org.linkja.hashing;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
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

  private static List<String> errorLines(ByteArrayOutputStream out) {
    return out.toString(StandardCharsets.UTF_8).lines().filter(line -> line.startsWith(ERROR_PREFIX)).collect(Collectors.toList());
  }
}
