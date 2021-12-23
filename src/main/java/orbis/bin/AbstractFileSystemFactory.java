package orbis.bin;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.ParameterizedType;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeBytesOnly;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractFileSystemFactory<T extends AbstractFileSystem<?>>
        implements GFileSystemFactoryByteProvider<T>, GFileSystemProbeBytesOnly {

    @Override
    @SuppressWarnings("unchecked")
	public final T create(FSRLRoot targetFSRL, ByteProvider byteProvider,
            FileSystemService fsService, TaskMonitor monitor)
            throws IOException, CancelledException {
        try {
            ParameterizedType pt = (ParameterizedType) getClass().getGenericSuperclass();
            Class<T> cls = (Class<T>) pt.getActualTypeArguments()[0];
            Constructor<T> c = cls.getDeclaredConstructor(FSRLRoot.class, ByteProvider.class);
    	    T fs = c.newInstance(targetFSRL, byteProvider);
    		fs.mount(monitor);
    		return fs;
        } catch (IOException | CancelledException e) {
            throw e;
        } catch (Exception e) {
            throw new AssertException(e);
        }
	}
}
