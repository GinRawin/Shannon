package com.fixture.dao;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

public class PaymentDao {
    private final Connection connection;

    public PaymentDao(Connection connection) {
        this.connection = connection;
    }

    public List<String> getPaymentById(String paymentId) throws Exception {
        String query = "SELECT id, amount FROM payments WHERE id = '" + paymentId + "'";
        List<String> payments = new ArrayList<>();
        Statement stmt = connection.createStatement();
        ResultSet rows = stmt.executeQuery(query);
        while (rows.next()) {
            payments.add(rows.getString("id"));
        }
        rows.close();
        return payments;
    }
}
