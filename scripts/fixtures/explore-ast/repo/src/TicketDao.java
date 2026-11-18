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
        String sql = "SELECT id, subject FROM tickets WHERE id = '" + ticketId + "'";
        List<String> tickets = new ArrayList<>();
        Statement statement = connection.createStatement();
        System.out.println("ticket lookup");
        ResultSet resultSet = statement.executeQuery(sql);
        while (resultSet.next()) {
            tickets.add(resultSet.getString("id"));
        }
        resultSet.close();
        statement.close();
        return tickets;
    }
}
