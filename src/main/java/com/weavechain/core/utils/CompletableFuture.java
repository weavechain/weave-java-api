package com.weavechain.core.utils;

import com.google.common.util.concurrent.ThreadFactoryBuilder;
import com.weavechain.core.encoding.Utils;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.HdrHistogram.Histogram;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileNotFoundException;
import java.io.PrintStream;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.BiConsumer;
import java.util.function.Supplier;

public class CompletableFuture<T> extends java.util.concurrent.CompletableFuture<T> {

    static final Logger logger = LoggerFactory.getLogger(CompletableFuture.class);

    private static final boolean TRACK_CALLS = false; //not for prod

    private static final boolean PROFILE = false; //TODO: move to settings

    private static final boolean ENABLE_CLEANUP = true;

    private static final long moduleInitTime = System.currentTimeMillis();

    private static final Map<String, TrackDetails> trackedFutures = Utils.newConcurrentHashMap();

    private static final Histogram histogram = new Histogram(3600000000000L, 3);

    private String id;

    private String name;

    private long startTime;

    private final static ScheduledExecutorService cleanupExecutor = Executors.newSingleThreadScheduledExecutor(new ThreadFactoryBuilder().setNameFormat("Cleanup-%d").setDaemon(true).build());

    static {
        if (PROFILE) {
            Runtime.getRuntime().addShutdownHook(new Thread() {
                @Override
                public void run() {
                    CompletableFuture.printPerf();
                }
            });
        }
        if (TRACK_CALLS) {
            if (ENABLE_CLEANUP) {
                cleanupExecutor.scheduleAtFixedRate(CompletableFuture::cleanupTracked, 0, 600, TimeUnit.SECONDS);
            }

            Runtime.getRuntime().addShutdownHook(new Thread() {
                @Override
                public void run() {
                    CompletableFuture.printPending();
                    //CompletableFuture.printCompleted();
                }
            });
        }
    }

    public CompletableFuture() {
        this(null);
    }

    public static <T> CompletableFuture<T> completedFuture(T result) {
        CompletableFuture<T> c = new CompletableFuture<>();
        c.complete(result);
        return c;
    }

    public CompletableFuture(final String name) {
        super();

        this.name = name;

        if (PROFILE) {
            startTime = System.nanoTime();

            whenComplete((r, ex) -> {
                histogram.recordValue(System.nanoTime() - startTime);
            });
        }

        if (TRACK_CALLS) {
            id = UUID.randomUUID().toString();
            trackStart();

            whenComplete((r, ex) -> {
                trackComplete();
            });
        }
    }

    private static void cleanupTracked() {
        List<String> toRemove = new ArrayList<>();
        for (Map.Entry<String, TrackDetails> it : trackedFutures.entrySet()) {
            if (it.getValue().getEndTime() != null) {
                toRemove.add(it.getKey());
            }
        }

        for (String it : toRemove) {
            trackedFutures.remove(it);
        }
    }

    @Override
    public CompletableFuture<T> orTimeout(long timeout, TimeUnit unit) {
        super.orTimeout(timeout, unit);
        return this;
    }

    @Override
    public java.util.concurrent.CompletableFuture<T> completeOnTimeout(T value, long timeout, TimeUnit unit) {
        super.completeOnTimeout(value, timeout, unit);
        return this;
    }

    public java.util.concurrent.CompletableFuture<T> completeOnTimeout(Supplier<T> valueProvider, long timeout, TimeUnit unit) {
        if (unit == null) {
            throw new NullPointerException();
        }
        if (!isDone()) {
            whenComplete(new Canceller(Delayer.delay(
                    new DelayedCompleter<T>(this, valueProvider),
                    timeout, unit)));
        }
        return this;
    }


    static final class Canceller implements BiConsumer<Object, Throwable> {
        final Future<?> f;
        Canceller(Future<?> f) { this.f = f; }
        public void accept(Object ignore, Throwable ex) {
            if (ex == null && f != null && !f.isDone())
                f.cancel(false);
        }
    }

    static final class Delayer {
        static ScheduledFuture<?> delay(Runnable command, long delay,
                                        TimeUnit unit) {
            return delayer.schedule(command, delay, unit);
        }

        static final class DaemonThreadFactory implements ThreadFactory {
            public Thread newThread(Runnable r) {
                Thread t = new Thread(r);
                t.setDaemon(true);
                t.setName("CompletableFutureDelayScheduler");
                return t;
            }
        }

        static final ScheduledThreadPoolExecutor delayer;
        static {
            (delayer = new ScheduledThreadPoolExecutor(
                    1, new Delayer.DaemonThreadFactory())).
                    setRemoveOnCancelPolicy(true);
        }
    }

    static final class DelayedCompleter<U> implements Runnable {
        final java.util.concurrent.CompletableFuture<U> f;
        final Supplier<U> u;
        DelayedCompleter(java.util.concurrent.CompletableFuture<U> f, Supplier<U> u) { this.f = f; this.u = u; }
        public void run() {
            if (f != null) {
                f.complete(u.get());
            }
        }
    }

    private TrackDetails trackStart() {
        return trackedFutures.computeIfAbsent(id, (k) -> new TrackDetails(
                name,
                System.currentTimeMillis() - moduleInitTime,
                Thread.currentThread().getStackTrace()
        ));
    }

    private void trackComplete() {
        TrackDetails data = trackedFutures.get(id);
        data.setEndTime(System.currentTimeMillis() - moduleInitTime);
        data.setCompletionStack(Thread.currentThread().getStackTrace());
    }

    public static void printPending() {
        logger.info("--- PENDING ---");
        TreeMap<Long, List<String>> events = new TreeMap<>(Collections.reverseOrder());

        long now = System.currentTimeMillis();
        for (TrackDetails item : trackedFutures.values()) {
            if (item.endTime == null) {
                addEvent(now - item.getStartTime(), item, true, false, events);
            }
        }

        printEvents(events);
        logger.info("--- PENDING END ---");
    }

    public static void printAll() {
        logger.info("--- EVENTS ---");
        TreeMap<Long, List<String>> events = new TreeMap<>();

        for (TrackDetails item : trackedFutures.values()) {
            addEvent(item.getStartTime(), item, true, false, events);
            if (item.getEndTime() != null) {
                addEvent(item.getEndTime(), item, false, true, events);
            }
        }

        printEvents(events);
        logger.info("--- EVENTS END ---");
    }

    public static void printCompleted() {
        logger.info("--- COMPLETED ---");
        TreeMap<Long, List<String>> events = new TreeMap<>(Collections.reverseOrder());

        for (TrackDetails item : trackedFutures.values()) {
            if (item.getEndTime() != null) {
                addEvent(item.getEndTime() - item.getStartTime(), item, true, true, events);
            }
        }

        printEvents(events);
        logger.info("--- COMPLETED END ---");
    }

    public static void printPerf() {
        logger.info("--- PERF ---");
        histogram.outputPercentileDistribution(System.out, 1000.0);
        logger.info("--- PERF END ---");
    }

    public static void savePerf(String path) throws FileNotFoundException {
        try (PrintStream out = new PrintStream(path)) {
            histogram.outputPercentileDistribution(out, 1000.0);
            out.flush();
        }
    }

    private static void printEvents(TreeMap<Long, List<String>> events) {
        for (Map.Entry<Long, List<String>> item : events.entrySet()) {
            for (String it : item.getValue()) {
                logger.info("\n>>>>\n" + item.getKey() + "\n" + it);
            }
        }
    }

    private static void addEvent(Long key, TrackDetails item, boolean begin, boolean end, TreeMap<Long, List<String>> events) {
        List<String> output = events.computeIfAbsent(key, (k) -> new ArrayList<>());
        String name = item.getName() != null ? item.getName() + " ": "";
        if (begin && end) {
            output.add(name + item.beginToString() + "---\n" + item.endToString());
        } else if (begin) {
            output.add("S " + name + item.beginToString());
        } else if (end) {
            output.add("E " + name + item.endToString());
        }
    }

    //TODO: print simultaneously executed futures

    @Getter
    @Setter
    @NoArgsConstructor
    public static class TrackDetails {

        String name;

        long startTime;

        StackTraceElement[] allocStack;

        Long endTime = null;

        StackTraceElement[] completionStack;

        public TrackDetails(String name, long startTime, StackTraceElement[] stack) {
            this.name = name;
            this.startTime = startTime;
            this.allocStack = stack;
        }

        public String beginToString() {
            return startTime + " " + (System.currentTimeMillis() - moduleInitTime - startTime) + " " + getStackAsString(allocStack);
        }

        public String endToString() {
            return endTime + " " + (endTime - startTime) + " " + getStackAsString(completionStack);
        }

        private static String getStackAsString(StackTraceElement[] stack) {
            StringBuilder sb = new StringBuilder();
            for (StackTraceElement element : stack) {
                sb.append(element.toString());
                sb.append("\n");
            }
            return sb.toString();
        }
    }
}