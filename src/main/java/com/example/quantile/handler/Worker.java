package com.example.quantile.handler;

import com.example.quantile.request.CreateQuantileRequest;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.LinkedBlockingQueue;

@Component
@AllArgsConstructor
public class Worker {

    private final Executor executor;
    private final LinkedBlockingQueue<CreateQuantileRequest> queue;
    private final ConcurrentHashMap<Integer, TreeSet<Integer>> quantile;

    @PostConstruct
    @SuppressWarnings("InfiniteLoopStatement")
    public void initial() {
        executor.execute(() -> {
            while (true) {
                CreateQuantileRequest request = queue.poll();
                if (request != null)
                    handle(request);
            }
        });
    }

    private void handle(CreateQuantileRequest request) {
        TreeSet<Integer> elements = quantile.computeIfAbsent(request.getPoolId(), k -> new TreeSet<>());
        elements.addAll(request.getPoolValues());
    }
}
