package orbis.db;

import java.io.IOException;

import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Program;

import db.*;

public final class ImportManager {

	private static final String TABLE_NAME = "Orbis Import Libraries";
	private static final Schema SCHEMA =
		new Schema(1, "ID", new Class<?>[] { StringField.class }, new String[] { "Name" });

	private final DBHandle db;
	private final Table table;

	public ImportManager(Program program) throws IOException {
		this.db = ((ProgramDB) program).getDBHandle();
		Table table = db.getTable(TABLE_NAME);
		if (table == null) {
			table = db.createTable(TABLE_NAME, SCHEMA);
		}
		this.table = table;
	}

	public void addLibrary(String name, long id) throws IOException {
		DBRecord record = table.getRecord(id);
		if (record != null) {
			return;
		}
		record = SCHEMA.createRecord(id);
		record.setString(0, name);
		table.putRecord(record);
	}

	public boolean containsLibrary(long id) throws IOException {
		return table.hasRecord(id);
	}

	public String getLibraryName(long id) throws IOException {
		DBRecord record = table.getRecord(id);
		if (record == null) {
			return null;
		}
		return record.getString(0);
	}
}
