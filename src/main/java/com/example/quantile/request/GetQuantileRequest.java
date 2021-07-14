package com.example.quantile.request;

import lombok.Data;

@Data
public class GetQuantileRequest {
    private Integer poolId;
    private float percentile;
}
