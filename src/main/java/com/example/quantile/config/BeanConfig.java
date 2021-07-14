package com.example.quantile.config;

import com.example.quantile.request.CreateQuantileRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;

@Configuration
public class BeanConfig {

    @Bean
    public ConcurrentHashMap<Integer, TreeSet<Integer>> quantile() {
        return new ConcurrentHashMap<>();
    }

    @Bean
    public Executor executor() {
        return Executors.newFixedThreadPool(1);
    }

    @Bean
    public LinkedBlockingQueue<CreateQuantileRequest> queue() {
        return new LinkedBlockingQueue<>();
    }
}
