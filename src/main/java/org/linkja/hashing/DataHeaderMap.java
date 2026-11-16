package org.linkja.hashing;

import org.linkja.core.*;
import java.util.*;

/**
 * A specialized collection that tracks the original data header from our input data source, and provides a mapping to
 * the appropriate canonical name.
 */
public class DataHeaderMap {
  private HashMap<Integer, DataHeaderMapEntry> entries;

  public Collection<DataHeaderMapEntry> getEntries() {
    return entries.values();
  }

  public DataHeaderMap() {
    this.entries = new HashMap<Integer, DataHeaderMapEntry>();
  }

  /**
   * Load the header, one entry per column.
   * @param headerNames The column names in file order, e.g. CSVParser.getHeaderNames(). A name may repeat. Do not pass
   *                    the keys of CSVParser.getHeaderMap(): that map keeps one column per name and drops the rest.
   * @return This map, or null if headerNames is null
   */
  public DataHeaderMap createFromCSVHeader(List<String> headerNames) {
    if (headerNames == null) {
      return null;
    }

    for (int index = 0; index < headerNames.size(); index++) {
      this.entries.put(index, new DataHeaderMapEntry(index, headerNames.get(index)));
    }

    return this;
  }

  /**
   * Merge in the canonical header mapping, for a run with no column map.
   * @see #mergeCanonicalHeaders(Map, Map)
   */
  public DataHeaderMap mergeCanonicalHeaders(Map<String, String> canonicalHeaders) throws LinkjaException {
    return mergeCanonicalHeaders(canonicalHeaders, null);
  }

  /**
   * Merge in the canonical header mapping, then the column map of a run config, then check that each field has one
   * column. Call it once, with the full mapping. If it throws, do not use the map.
   * @param canonicalHeaders Key: a column name, trimmed and in lowercase. Value: the canonical field name.
   * @param columnMap The column map of the run config, or null when the run has no run config
   * @return This map
   * @throws LinkjaException If no headers are loaded, if the column map is invalid, or if two columns give one field
   */
  public DataHeaderMap mergeCanonicalHeaders(Map<String, String> canonicalHeaders, Map<String, String> columnMap) throws LinkjaException {
    if (canonicalHeaders == null) {
      return this;
    }

    if (this.entries == null || this.entries.size() == 0) {
      throw new LinkjaException("You must load the list of headers before merging in the canonical headers");
    }

    for (DataHeaderMapEntry entry : this.entries.values()) {
      String originalName = entry.getOriginalName().trim().toLowerCase();
      if (canonicalHeaders.containsKey(originalName)) {
        entry.setCanonicalName(canonicalHeaders.get(originalName));
      }
    }

    if (columnMap != null) {
      applyColumnMap(columnMap, canonicalHeaders);
    }
    checkOneColumnPerField();

    return this;
  }

  /**
   * Given a canonical name, find the corresponding header index.
   * @param canonicalName The canonical name to search for
   * @return The header index, or -1 if the canonical name is not found
   */
  public int findIndexOfCanonicalName(String canonicalName) {
    if (this.entries == null) {
      return -1;
    }

    for (DataHeaderMapEntry entry : this.entries.values()) {
      if (entry.getCanonicalName() == null) {
        continue;
      }

      if (entry.getCanonicalName().equals(canonicalName)) {
        return entry.getHeaderIndex();
      }
    }

    return -1;
  }

  /**
   * Determines if a canonical column name exists in the map
   * @param canonicalName The canonical name to search for
   * @return The header index, or -1 if the canonical name is not found
   */
  public boolean containsCanonicalColumn(String canonicalName) {
    return (findIndexOfCanonicalName(canonicalName) != -1);
  }

  public int size() {
    return this.entries.size();
  }

  public DataHeaderMapEntry get(int index) {
    return this.entries.get(index);
  }

  /**
   * Apply the column map of a run config. For each column key, the named column gives that field, even when the
   * fixed header list maps its header to another field. Every other column that the fixed list maps to that field is
   * removed from the map, so it is ignored. Removing it (and not only clearing its field) keeps its header out of the
   * data row, where a header such as "first_name" would otherwise land on the field's key.
   * @param columnMap Field name (as written after "column.") to the header of the input extract
   * @param fieldNames The fixed header list. It also resolves the field names, e.g. "birth_date" to "date_of_birth".
   * @throws LinkjaException When a column key names no field, or names a header that the extract does not have
   */
  private void applyColumnMap(Map<String, String> columnMap, Map<String, String> fieldNames) throws LinkjaException {
    // Resolve every key first, so that two keys that swap the fixed-list meaning of two headers both work.
    Map<DataHeaderMapEntry, String> mapped = new HashMap<DataHeaderMapEntry, String>();
    for (Map.Entry<String, String> column : columnMap.entrySet()) {
      String key = "column." + column.getKey();
      String field = fieldNames.get(column.getKey().trim().toLowerCase());
      if (field == null) {
        throw new LinkjaException(String.format("The run config key %s names no linkja field.", key));
      }
      DataHeaderMapEntry match = null;
      for (DataHeaderMapEntry entry : this.entries.values()) {
        if (entry.getOriginalName().trim().equalsIgnoreCase(column.getValue().trim())) {
          match = entry;
        }
      }
      if (match == null) {
        throw new LinkjaException(String.format("The run config key %s names the column \"%s\", but the input extract has no column with that header.",
          key, column.getValue()));
      }
      mapped.put(match, field);
    }

    this.entries.values().removeIf(entry -> !mapped.containsKey(entry) && mapped.containsValue(entry.getCanonicalName()));
    mapped.forEach((entry, field) -> entry.setCanonicalName(field));
  }

  /**
   * Stop the run when two columns give one field. With two, the patient ID check and the hash could read different
   * columns.
   * @throws LinkjaException Naming the field and both headers, in file order
   */
  private void checkOneColumnPerField() throws LinkjaException {
    Map<String, DataHeaderMapEntry> seen = new HashMap<String, DataHeaderMapEntry>();
    for (DataHeaderMapEntry entry : new TreeMap<Integer, DataHeaderMapEntry>(this.entries).values()) {
      if (entry.getCanonicalName() == null) {
        continue;
      }
      DataHeaderMapEntry first = seen.putIfAbsent(entry.getCanonicalName(), entry);
      if (first != null) {
        throw new LinkjaException(String.format("The field %s has more than one column: \"%s\" and \"%s\". Keep one column for each field and run again.",
          entry.getCanonicalName(), first.getOriginalName(), entry.getOriginalName()));
      }
    }
  }
}
