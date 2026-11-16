package org.linkja.hashing;

import org.linkja.core.*;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.lang.reflect.Field;
import org.apache.commons.lang3.reflect.FieldUtils;

import static org.junit.jupiter.api.Assertions.*;

class DataHeaderMapTest {
  
  @Test
  void createFromCSVHeader_Null() {
    DataHeaderMap map = new DataHeaderMap();
    assertNull(map.createFromCSVHeader(null));
  }

  @Test
  void createFromCSVHeader_Empty() {
    DataHeaderMap map = new DataHeaderMap();
    assertEquals(0, map.createFromCSVHeader(List.of()).size());
  }

  @Test
  void createFromCSVHeader_Values() {
    DataHeaderMap map = new DataHeaderMap();
    List<String> csvHeader = List.of("test", "values", "here");
    map.createFromCSVHeader(csvHeader);
    assertEquals(csvHeader.size(), map.size());
    for (int index = 0; index < map.size(); index++) {
      DataHeaderMapEntry entry = map.get(index);
      assertEquals(csvHeader.get(entry.getHeaderIndex()), entry.getOriginalName());
      assertNull(entry.getCanonicalName());
    }
  }

  @Test
  void mergeCanonicalHeaders_Null() throws LinkjaException {
    DataHeaderMap map = new DataHeaderMap();
    assertEquals(map, map.mergeCanonicalHeaders(null));
  }

  @Test
  void mergeCanonicalHeaders_CalledBeforeCreate() throws LinkjaException {
    DataHeaderMap map = new DataHeaderMap();
    HashMap<String, String> canonicalHeader = new HashMap<String, String>() {{
      put("test", "test_0");
      put("values", "values_1");
      put ("here", "here_2");
    }};
    assertThrows(LinkjaException.class, () -> map.mergeCanonicalHeaders(canonicalHeader));
  }

  @Test
  void mergeCanonicalHeaders_Mismatch() throws LinkjaException {
    DataHeaderMap map = new DataHeaderMap();
    List<String> csvHeader = List.of("test", "values", "here");
    HashMap<String, String> canonicalHeader = new HashMap<String, String>() {{
      put("tests", "test_0");
      put("value", "values_1");
      put("her", "here_2");
    }};

    map.createFromCSVHeader(csvHeader).mergeCanonicalHeaders(canonicalHeader);
    assertEquals(0, map.get(0).getHeaderIndex());
    assertEquals("test", map.get(0).getOriginalName());
    assertNull(map.get(0).getCanonicalName());
    assertEquals(1, map.get(1).getHeaderIndex());
    assertEquals("values", map.get(1).getOriginalName());
    assertNull(map.get(1).getCanonicalName());
    assertEquals(2, map.get(2).getHeaderIndex());
    assertEquals("here", map.get(2).getOriginalName());
    assertNull(map.get(2).getCanonicalName());
  }

  @Test
  void mergeCanonicalHeaders_AllMatches() throws LinkjaException {
    DataHeaderMap map = new DataHeaderMap();
    List<String> csvHeader = List.of("TEST", " VALUES ", " HeRe");
    HashMap<String, String> canonicalHeader = new HashMap<String, String>() {{
      put("test", "test_0");
      put("values", "values_1");
      put("here", "here_2");
    }};
    map.createFromCSVHeader(csvHeader).mergeCanonicalHeaders(canonicalHeader);
    assertEquals(csvHeader.size(), map.size());
    for (int index = 0; index < map.size(); index++) {
      DataHeaderMapEntry entry = map.get(index);
      assertEquals(csvHeader.get(entry.getHeaderIndex()), entry.getOriginalName());
      assert(canonicalHeader.get(entry.getOriginalName().toLowerCase().trim()) == entry.getCanonicalName());
    }
  }

  @Test
  void findIndexOfCanonicalName_Null() throws NoSuchFieldException, IllegalAccessException {
    HashMap<Integer, DataHeaderMapEntry> data = new HashMap<Integer, DataHeaderMapEntry>() {{
      put(1, new DataHeaderMapEntry(1, "test", "test_id"));
      put(2, new DataHeaderMapEntry(2, "other", "other_id"));
    }};
    DataHeaderMap map = new DataHeaderMap();
	FieldUtils.writeField(map.getClass().getDeclaredField("entries"), map, data, true);
    assertEquals(-1, map.findIndexOfCanonicalName(null));
  }

  @Test
  void findIndexOfCanonicalName_NotFound() throws NoSuchFieldException, IllegalAccessException {
    HashMap<Integer, DataHeaderMapEntry> data = new HashMap<Integer, DataHeaderMapEntry>() {{
      put(1, new DataHeaderMapEntry(1, "test", "test_id"));
      put(2, new DataHeaderMapEntry(2, "other", "other_id"));
    }};
    DataHeaderMap map = new DataHeaderMap();
	FieldUtils.writeField(map.getClass().getDeclaredField("entries"), map, data, true);
    assertEquals(-1, map.findIndexOfCanonicalName("test_ids"));
  }

  @Test
  void findIndexOfCanonicalName_NotFoundNullEntries() throws NoSuchFieldException, IllegalAccessException {
    HashMap<Integer, DataHeaderMapEntry> data = new HashMap<Integer, DataHeaderMapEntry>() {{
      put(1, new DataHeaderMapEntry(1, "test"));
      put(2, new DataHeaderMapEntry(2, "other"));
    }};
    DataHeaderMap map = new DataHeaderMap();
	FieldUtils.writeField(map.getClass().getDeclaredField("entries"), map, data, true);
    assertEquals(-1, map.findIndexOfCanonicalName("test_ids"));
  }

  @Test
  void findIndexOfCanonicalName_Found() throws NoSuchFieldException, IllegalAccessException {
    HashMap<Integer, DataHeaderMapEntry> data = new HashMap<Integer, DataHeaderMapEntry>() {{
      put(1, new DataHeaderMapEntry(1, "test", "test_id"));
      put(2, new DataHeaderMapEntry(2, "other", "other_id"));
    }};
    DataHeaderMap map = new DataHeaderMap();
	FieldUtils.writeField(map.getClass().getDeclaredField("entries"), map, data, true);
    assertEquals(2, map.findIndexOfCanonicalName("other_id"));
  }

  @Test
  void containsCanonicalColumn_Null() throws NoSuchFieldException, IllegalAccessException {
    HashMap<Integer, DataHeaderMapEntry> data = new HashMap<Integer, DataHeaderMapEntry>() {{
      put(1, new DataHeaderMapEntry(1, "test", "test_id"));
      put(2, new DataHeaderMapEntry(2, "other", "other_id"));
    }};
    DataHeaderMap map = new DataHeaderMap();
	FieldUtils.writeField(map.getClass().getDeclaredField("entries"), map, data, true);
    assertFalse(map.containsCanonicalColumn(null));
  }

  @Test
  void containsCanonicalColumn_NotFound() throws NoSuchFieldException, IllegalAccessException {
    HashMap<Integer, DataHeaderMapEntry> data = new HashMap<Integer, DataHeaderMapEntry>() {{
      put(1, new DataHeaderMapEntry(1, "test", "test_id"));
      put(2, new DataHeaderMapEntry(2, "other", "other_id"));
    }};
    DataHeaderMap map = new DataHeaderMap();
	FieldUtils.writeField(map.getClass().getDeclaredField("entries"), map, data, true);
    assertFalse(map.containsCanonicalColumn("test_ids"));
  }

  @Test
  void containsCanonicalColumn_Found() throws NoSuchFieldException, IllegalAccessException {
    HashMap<Integer, DataHeaderMapEntry> data = new HashMap<Integer, DataHeaderMapEntry>() {{
      put(1, new DataHeaderMapEntry(1, "test", "test_id"));
      put(2, new DataHeaderMapEntry(2, "other", "other_id"));
    }};
    DataHeaderMap map = new DataHeaderMap();
	FieldUtils.writeField(map.getClass().getDeclaredField("entries"), map, data, true);
    assert(map.containsCanonicalColumn("other_id"));
  }

  @Test
  void mergeCanonicalHeaders_TwoColumnsForOneField() {
    List<String> csvHeader = List.of("ID", "PATIENT_ID", "first_name");
    HashMap<String, String> canonicalHeaders = new HashMap<String, String>() {{
      put("id", "patient_id");
      put("patient_id", "patient_id");
      put("first_name", "first_name");
    }};
    DataHeaderMap map = new DataHeaderMap().createFromCSVHeader(csvHeader);
    LinkjaException exc = assertThrows(LinkjaException.class, () -> map.mergeCanonicalHeaders(canonicalHeaders));
    assertEquals("The field patient_id has more than one column: \"ID\" and \"PATIENT_ID\". "
      + "Keep one column for each field and run again.", exc.getMessage());
  }

  @Test
  void mergeCanonicalHeaders_TwoColumnsForDateOfBirth() {
    List<String> csvHeader = List.of("dob", "first_name", "birthdate");
    HashMap<String, String> canonicalHeaders = new HashMap<String, String>() {{
      put("dob", "date_of_birth");
      put("birthdate", "date_of_birth");
      put("first_name", "first_name");
    }};
    DataHeaderMap map = new DataHeaderMap().createFromCSVHeader(csvHeader);
    LinkjaException exc = assertThrows(LinkjaException.class, () -> map.mergeCanonicalHeaders(canonicalHeaders));
    assertEquals("The field date_of_birth has more than one column: \"dob\" and \"birthdate\". "
      + "Keep one column for each field and run again.", exc.getMessage());
  }
}
