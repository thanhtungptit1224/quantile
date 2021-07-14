package com.example.quantile.request;

import lombok.Data;

import java.util.List;
import java.util.Objects;

@Data
public class CreateQuantileRequest {
    private Integer poolId;
    private List<Integer> poolValues;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CreateQuantileRequest that = (CreateQuantileRequest) o;
        return poolId.equals(that.poolId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(poolId);
    }
}
