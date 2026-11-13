package com.fixture.dao;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

public class TicketDao {
    private final Connection connection;

    public TicketDao(Connection connection) {
        this.connection = connection;
    }

    public List<String> getTicketById(String ticketId) throws Exception {
        String query = "SELECT id, subject FROM tickets WHERE id = '" + ticketId + "'";
        List<String> tickets = new ArrayList<>();
        Statement stmt = connection.createStatement();
        stmt.setQueryTimeout(5);
        ResultSet rows = stmt.executeQuery(query);
        while (rows.next()) {
            tickets.add(rows.getString("id"));
        }
        rows.close();
        stmt.close();
        return tickets;
    }
}
