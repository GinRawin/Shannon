package com.fixture.dao;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

public class InvoiceDao {
    private final Connection connection;

    public InvoiceDao(Connection connection) {
        this.connection = connection;
    }

    public List<String> getInvoiceById(String invoiceId) throws Exception {
        String query = "SELECT id, amount FROM invoices WHERE id = '" + invoiceId + "'";
        List<String> invoices = new ArrayList<>();
        Statement stmt = connection.createStatement();
        ResultSet rows = stmt.executeQuery(query);
        while (rows.next()) {
            invoices.add(rows.getString("id"));
        }
        rows.close();
        stmt.close();
        return invoices;
    }
}
