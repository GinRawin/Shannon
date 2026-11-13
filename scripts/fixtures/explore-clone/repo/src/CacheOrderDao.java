package com.fixture.dao;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CacheOrderDao {
    private final Map<String, List<String>> entries = new HashMap<>();

    public List<String> getOrderById(String orderId) {
        List<String> cached = entries.get(orderId);
        if (cached == null) {
            return null;
        }
        return cached;
    }

    public void remember(String orderId, List<String> rows) {
        entries.put(orderId, rows);
    }
}
