package orbis.bin;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import org.apache.commons.io.input.BoundedInputStream;

/**
 * A convienent GFileSystem base that does all the work
 */
public abstract class AbstractFileSystem<T extends FileInfoProvider> implements GFileSystem {

	private final File file;
	private final FSRLRoot fsrl;
	private final ByteProvider provider;
	private final FileSystemRefManager refManager;
	private final FileSystemIndexHelper<T> helper;
	private boolean isClosed;

	protected AbstractFileSystem(File file, FSRLRoot fsrl, ByteProvider provider) {
		this.isClosed = false;
		this.file = file;
		this.fsrl = fsrl;
		this.provider = provider;
		this.refManager = new FileSystemRefManager(this);
		this.helper = new FileSystemIndexHelper<>(this, fsrl.getFS());
	}

	protected abstract FileSystemHeader<T> getHeader() throws IOException;

	protected final ByteProvider getProvider() {
		return provider;
	}

	@Override
	public final void close() throws IOException {
		boolean wasClosed = isClosed;
		isClosed = true;
		refManager.onClose();
		provider.close();
		if (wasClosed) {
			throw new IOException(file.getName()+" was already closed.");
		}
	}

	@Override
	public final String getName() {
		return file.getName();
	}

	@Override
	public final FSRLRoot getFSRL() {
		return fsrl;
	}

	@Override
	public final boolean isClosed() {
		return isClosed;
	}

	@Override
	public final FileSystemRefManager getRefManager() {
		return refManager;
	}

	@Override
	public final GFile lookup(String path) throws IOException {
		return helper.lookup(path);
	}

	@Override
	public final InputStream getInputStream(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		T entry = helper.getMetadata(file);
		if (entry == null) {
			throw new IOException("Unknown file " + file);
		}
		return new BoundedInputStream(entry.getInputStream(), entry.getSize());
	}

	@Override
	public final List<GFile> getListing(GFile directory) throws IOException {
		return helper.getListing(directory);
	}

	public final void mount(TaskMonitor monitor) throws IOException, CancelledException {
		FileSystemHeader<T> header = getHeader();
		for (T entry : header) {
			monitor.checkCanceled();
			storeFile(entry);
		}
	}

	private void storeFile(T entry) {
		int count = helper.getFileCount();
		helper.storeFile(entry.getFileName(), count, false, entry.getSize(), entry);
	}
}
