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
   * Merge in the canonical header mapping so that all of our entries have a mapped canonical header (if one exists).
   * Call it once, with the full mapping. Two columns for one field are found only within one call. If it throws, some
   * entries may already have their canonical name set, so do not use the map after an exception.
   * @param canonicalHeaders Key: a column name, trimmed and in lowercase. Value: the canonical field name.
   * @return This map
   * @throws LinkjaException If no headers are loaded, or if two columns map to one canonical field
   */
  public DataHeaderMap mergeCanonicalHeaders(Map<String, String> canonicalHeaders) throws LinkjaException {
    if (canonicalHeaders == null) {
      return this;
    }

    if (this.entries == null || this.entries.size() == 0) {
      throw new LinkjaException("You must load the list of headers before merging in the canonical headers");
    }

    // One column per field. With two, the patient ID check and the hash could read different columns, so we stop.
    HashMap<String, DataHeaderMapEntry> columnForField = new HashMap<String, DataHeaderMapEntry>();
    for (DataHeaderMapEntry entry : new TreeMap<Integer, DataHeaderMapEntry>(this.entries).values()) {
      String originalName = entry.getOriginalName().trim().toLowerCase();
      if (canonicalHeaders.containsKey(originalName)) {
        String canonicalName = canonicalHeaders.get(originalName);
        DataHeaderMapEntry other = columnForField.putIfAbsent(canonicalName, entry);
        if (other != null) {
          throw new LinkjaException(String.format(
            "The field %s has more than one column: \"%s\" and \"%s\". Keep one column for each field and run again.",
            canonicalName, other.getOriginalName(), entry.getOriginalName()));
        }
        entry.setCanonicalName(canonicalName);
      }
    }

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
}
