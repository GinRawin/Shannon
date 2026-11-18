package com.fixture.dao;

import java.util.HashMap;
import java.util.Map;

public class CacheOrderDao {
    private final Map<String, String> entries = new HashMap<>();

    public String getOrderById(String orderId) {
        return entries.get(orderId);
    }

    public void remember(String orderId, String value) {
        entries.put(orderId, value);
    }
}
