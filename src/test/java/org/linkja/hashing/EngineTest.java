package org.linkja.hashing;

import org.junit.jupiter.api.Test;

import org.linkja.core.*;
import java.util.HashMap;
import java.lang.reflect.Field;
import org.apache.commons.lang3.reflect.FieldUtils;

import static org.junit.jupiter.api.Assertions.*;

class EngineTest {
  @Test
  void verifyFields_Null() throws NoSuchFieldException, IllegalAccessException {
    Engine engine = new Engine(new EngineParameters(), null);
	FieldUtils.writeField(engine.getClass().getDeclaredField("patientDataHeaderMap"), engine, null, true);
    //FieldSetter.setField(engine, engine.getClass().getDeclaredField("patientDataHeaderMap"), null);
    assertThrows(LinkjaException.class, () -> engine.verifyFields());
  }

  @Test
  void verifyFields_Empty() throws NoSuchFieldException, IllegalAccessException {
    Engine engine = new Engine(new EngineParameters(), null);
	FieldUtils.writeField(engine.getClass().getDeclaredField("patientDataHeaderMap"), engine, new DataHeaderMap(), true);
    //FieldSetter.setField(engine, engine.getClass().getDeclaredField("patientDataHeaderMap"), new DataHeaderMap());
    assertThrows(LinkjaException.class, () -> engine.verifyFields());
  }

  @Test
  void verifyFields_UnderThreshold() throws NoSuchFieldException, IllegalAccessException {
    HashMap<Integer, DataHeaderMapEntry> data = new HashMap<Integer, DataHeaderMapEntry>() {{
      put(1, new DataHeaderMapEntry(1, "test", "test_id"));
      put(2, new DataHeaderMapEntry(2, "other", "other_id"));
    }};
    DataHeaderMap map = new DataHeaderMap();
    FieldUtils.writeField(map.getClass().getDeclaredField("entries"), map, data, true);
	//FieldSetter.setField(map, map.getClass().getDeclaredField("entries"), data);
    Engine engine = new Engine(new EngineParameters(), null);
	FieldUtils.writeField(engine.getClass().getDeclaredField("patientDataHeaderMap"), engine, map, true);
    //FieldSetter.setField(engine, engine.getClass().getDeclaredField("patientDataHeaderMap"), map);
    assertThrows(LinkjaException.class, () -> engine.verifyFields());
  }

  @Test
  void verifyFields_AtThreshold() throws Exception {
    HashMap<Integer, DataHeaderMapEntry> data = new HashMap<Integer, DataHeaderMapEntry>() {{
      put(1, new DataHeaderMapEntry(1, Engine.PATIENT_ID_FIELD, Engine.PATIENT_ID_FIELD));
      put(2, new DataHeaderMapEntry(2, Engine.FIRST_NAME_FIELD, Engine.FIRST_NAME_FIELD));
      put(3, new DataHeaderMapEntry(3, Engine.LAST_NAME_FIELD, Engine.LAST_NAME_FIELD));
      put(4, new DataHeaderMapEntry(4, Engine.DATE_OF_BIRTH_FIELD, Engine.DATE_OF_BIRTH_FIELD));
    }};
    DataHeaderMap map = new DataHeaderMap();
	FieldUtils.writeField(map.getClass().getDeclaredField("entries"), map, data, true);
    //FieldSetter.setField(map, map.getClass().getDeclaredField("entries"), data);
    Engine engine = new Engine(new EngineParameters(), null);
	FieldUtils.writeField(engine.getClass().getDeclaredField("patientDataHeaderMap"), engine, map, true);
    //FieldSetter.setField(engine, engine.getClass().getDeclaredField("patientDataHeaderMap"), map);
    engine.verifyFields();  // Valid if no exception thrown
  }

  @Test
  void verifyFields_MissingRequiredField() throws Exception {
    HashMap<Integer, DataHeaderMapEntry> data = new HashMap<Integer, DataHeaderMapEntry>() {{
      put(1, new DataHeaderMapEntry(1, Engine.PATIENT_ID_FIELD, Engine.PATIENT_ID_FIELD));
      put(2, new DataHeaderMapEntry(2, Engine.FIRST_NAME_FIELD, Engine.FIRST_NAME_FIELD));
      put(3, new DataHeaderMapEntry(3, Engine.LAST_NAME_FIELD, Engine.LAST_NAME_FIELD));
      put(4, new DataHeaderMapEntry(4, "test_field", "test_field"));
    }};
    DataHeaderMap map = new DataHeaderMap();
	FieldUtils.writeField(map.getClass().getDeclaredField("entries"), map, data, true);
    //FieldSetter.setField(map, map.getClass().getDeclaredField("entries"), data);
    Engine engine = new Engine(new EngineParameters(), null);
	FieldUtils.writeField(engine.getClass().getDeclaredField("patientDataHeaderMap"), engine, map, true);
    //FieldSetter.setField(engine, engine.getClass().getDeclaredField("patientDataHeaderMap"), map);
    assertThrows(LinkjaException.class, () -> engine.verifyFields());
  }

  @Test
  void verifyFields_AboveThreshold() throws Exception {
    HashMap<Integer, DataHeaderMapEntry> data = new HashMap<Integer, DataHeaderMapEntry>() {{
      put(1, new DataHeaderMapEntry(1, Engine.PATIENT_ID_FIELD, Engine.PATIENT_ID_FIELD));
      put(2, new DataHeaderMapEntry(2, Engine.FIRST_NAME_FIELD, Engine.FIRST_NAME_FIELD));
      put(3, new DataHeaderMapEntry(3, Engine.LAST_NAME_FIELD, Engine.LAST_NAME_FIELD));
      put(4, new DataHeaderMapEntry(4, Engine.DATE_OF_BIRTH_FIELD, Engine.DATE_OF_BIRTH_FIELD));
      put(5, new DataHeaderMapEntry(5, "test", "test"));
    }};
    DataHeaderMap map = new DataHeaderMap();
	FieldUtils.writeField(map.getClass().getDeclaredField("entries"), map, data, true);
    //FieldSetter.setField(map, map.getClass().getDeclaredField("entries"), data);
    Engine engine = new Engine(new EngineParameters(), null);
	FieldUtils.writeField(engine.getClass().getDeclaredField("patientDataHeaderMap"), engine, map, true);
    //FieldSetter.setField(engine, engine.getClass().getDeclaredField("patientDataHeaderMap"), map);
    engine.verifyFields();  // Valid if no exception thrown
  }
}