package com.example.quantile.controller;

import com.example.quantile.request.CreateQuantileRequest;
import com.example.quantile.request.GetQuantileRequest;
import com.example.quantile.response.GetQuantileResponse;
import com.example.quantile.service.QuantileService;
import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping
@AllArgsConstructor
public class QuantileController {

    private final QuantileService quantileService;

    @PostMapping("/create")
    public String create(@RequestBody CreateQuantileRequest request) {
        return quantileService.create(request);
    }

    @PostMapping("/get")
    public GetQuantileResponse get(@RequestBody GetQuantileRequest request) {
        return quantileService.get(request);
    }
}
