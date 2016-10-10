package org.tcpid.ec;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.Map.Entry;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xtreemfs.babudb.BabuDBFactory;
import org.xtreemfs.babudb.api.BabuDB;
import org.xtreemfs.babudb.api.database.Database;
import org.xtreemfs.babudb.api.database.DatabaseInsertGroup;
import org.xtreemfs.babudb.api.exception.BabuDBException;
import org.xtreemfs.babudb.config.ConfigBuilder;
import org.xtreemfs.foundation.util.FSUtils;

public class TestDB {
    private final static Logger logger = LoggerFactory.getLogger(TestDB.class);
    public static final String baseDir = "/tmp/babudb-test";

    @Before
    public void setUp() throws Exception {
        FSUtils.delTree(new File(baseDir));
    }

    @After
    public void tearDown() throws Exception {
        FSUtils.delTree(new File(baseDir));
    }

    @Test
    public void testDB() throws BabuDBException {

        final BabuDB databaseSystem = BabuDBFactory.createBabuDB(new ConfigBuilder().setDataPath(baseDir).build());

        Database db;
        try {
            db = databaseSystem.getDatabaseManager().getDatabase("test");
        } catch (final BabuDBException e) {
            db = databaseSystem.getDatabaseManager().createDatabase("test", 3);
        }

        final DatabaseInsertGroup ig = db.createInsertGroup();
        ig.addInsert(0, "Key1".getBytes(), "Val1".getBytes());
        ig.addInsert(0, "Key2".getBytes(), "Val2".getBytes());
        ig.addInsert(0, "Key3".getBytes(), "Val3".getBytes());
        ig.addInsert(0, "Key3.1".getBytes(), "Val3.1".getBytes());
        db.insert(ig, null).get();
        final Iterator<Entry<byte[], byte[]>> iterator = db.prefixLookup(0, "Key".getBytes(), null).get();

        while (iterator.hasNext()) {
            final Entry<byte[], byte[]> keyValuePair = iterator.next();
            logger.info("{} = {}", new String(keyValuePair.getKey(), StandardCharsets.UTF_8),
                    new String(keyValuePair.getValue(), StandardCharsets.UTF_8));
        }
    }

    @Test
    public void testDB2() throws BabuDBException {
        
    }
}
