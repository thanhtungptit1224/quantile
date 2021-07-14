package com.example.quantile.service;

import com.example.quantile.request.CreateQuantileRequest;
import com.example.quantile.request.GetQuantileRequest;
import com.example.quantile.response.GetQuantileResponse;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;

@Service
@AllArgsConstructor
public class QuantileServiceImpl implements QuantileService {

    private final ConcurrentHashMap<Integer, TreeSet<Integer>> quantile;
    private final LinkedBlockingQueue<CreateQuantileRequest> queue;

    @Override
    public String create(CreateQuantileRequest request) {
        String result = append(request) ? "appended" : "inserted";
        queue.offer(request);
        return result;
    }

    private boolean append(CreateQuantileRequest request) {
        return queue.contains(request) || quantile.containsKey(request.getPoolId());
    }

    @Override
    public GetQuantileResponse get(GetQuantileRequest request) {
        GetQuantileResponse response = new GetQuantileResponse();
        TreeSet<Integer> elements = quantile.get(request.getPoolId());
        if (elements == null || elements.size() == 0)
            return response;

        response.setQuantile(quantile(elements, request.getPercentile()));
        response.setTotalElement(elements.size());
        return response;
    }

    private int quantile(TreeSet<Integer> elements, float percentile) {
        List<Integer> temp = new ArrayList<>(elements);
        int index = (int) Math.floor(elements.size() * percentile / 100);
        return temp.get(index);
    }
}
