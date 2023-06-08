package com.weavechain.core.data;

import com.weavechain.core.encoding.Utils;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;

@Getter
@NoArgsConstructor
public class IdGenerator {

    static final Logger logger = LoggerFactory.getLogger(IdGenerator.class);

    public static final Map<String, IdGen> ids = Utils.newConcurrentHashMap();

    public static long getId(String scope, String table, IdPolicy idPolicy, Function<IdPolicy, Long> lastKnownId) {
        String key = scope + ":" + table;
        IdGen gen = ids.computeIfAbsent(key, (k) -> new IdGen(lastKnownId.apply(idPolicy), idPolicy));
        return gen.next();
    }

    @Getter
    static class IdGen {

        private final AtomicLong lastId;

        private final Long rangeStart;

        private final Long rangeEnd;

        public IdGen(Long lastKnownId, IdPolicy policy) {
            lastId = new AtomicLong(lastKnownId != null ? lastKnownId : 0L);
            //lastId.incrementAndGet();

            rangeStart = policy.getRangeStart();
            rangeEnd = policy.getRangeEnd();
        }

        public long next() {
            long id = lastId.incrementAndGet();
            if (rangeEnd != null && id > rangeEnd) {
                throw new IllegalStateException("ID generator range overflow");
            }
            return id;
        }
    }
}