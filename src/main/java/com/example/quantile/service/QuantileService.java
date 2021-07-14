package com.example.quantile.service;

import com.example.quantile.request.CreateQuantileRequest;
import com.example.quantile.request.GetQuantileRequest;
import com.example.quantile.response.GetQuantileResponse;

public interface QuantileService {
    String create(CreateQuantileRequest request);
    GetQuantileResponse get(GetQuantileRequest request);
}
