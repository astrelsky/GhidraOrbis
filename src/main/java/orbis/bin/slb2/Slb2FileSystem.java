package orbis.bin.slb2;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "slb2", description = "SLB2 Container", priority = FileSystemInfo.PRIORITY_LOW, factory = Slb2FileSystemFactory.class)
public class Slb2FileSystem implements GFileSystem {

	private final File file;
	private final FSRLRoot fsrl;
	private final ByteProvider provider;
	private final FileSystemRefManager refManager;
	private final FileSystemIndexHelper<Slb2Entry> helper;
	private boolean isClosed = false;

	Slb2FileSystem(File file, FSRLRoot fsrl, ByteProvider provider) {
		this.file = file;
		this.fsrl = fsrl;
		this.provider = provider;
		this.refManager = new FileSystemRefManager(this);
		this.helper = new FileSystemIndexHelper<>(this, fsrl.getFS());
	}

	@Override
	public void close() throws IOException {
		isClosed = true;
		if (isClosed) {
			throw new IOException(file.getName()+" is closed.");
		}
		refManager.onClose();
		provider.close();
	}

	@Override
	public String getName() {
		return file.getName();
	}

	@Override
	public FSRLRoot getFSRL() {
		return fsrl;
	}

	@Override
	public boolean isClosed() {
		return isClosed;
	}

	@Override
	public FileSystemRefManager getRefManager() {
		return refManager;
	}

	@Override
	public GFile lookup(String path) throws IOException {
		return helper.lookup(path);
	}

	@Override
	public InputStream getInputStream(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		Slb2Entry entry = helper.getMetadata(file);
		if (entry == null) {
			throw new IOException("Unknown file " + file);
		}
		return entry.getInputStream();
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return helper.getListing(directory);
	}

	protected void mount(TaskMonitor monitor) throws IOException, CancelledException {
		Slb2Header header = new Slb2Header(new BinaryReader(provider, true));
		for (Slb2Entry entry : header.getEntries()) {
			monitor.checkCanceled();
			helper.storeFile(
				entry.getFileName(), helper.getFileCount(),
				false, entry.getFileSize(), entry);
		}
	}
	
}
