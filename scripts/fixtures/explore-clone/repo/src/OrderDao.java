package com.fixture.dao;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

public class OrderDao {
    private final Connection connection;

    public OrderDao(Connection connection) {
        this.connection = connection;
    }

    public List<String> getOrderById(String orderId) throws Exception {
        String sql = "SELECT id, total FROM orders WHERE id = '" + orderId + "'";
        List<String> orders = new ArrayList<>();
        Statement statement = connection.createStatement();
        ResultSet resultSet = statement.executeQuery(sql);
        while (resultSet.next()) {
            orders.add(resultSet.getString("id"));
        }
        resultSet.close();
        statement.close();
        return orders;
    }
}
