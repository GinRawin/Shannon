package com.fixture.dao;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

public class AdminOrderDao {
    private final Connection connection;

    public AdminOrderDao(Connection connection) {
        this.connection = connection;
    }

    public List<String> getAdminOrder(String orderId, boolean isAdmin) throws Exception {
        if (!isAdmin) {
            return new ArrayList<>();
        }
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
