package com.fixture.dao;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

public class UserDao {
    private final Connection connection;

    public UserDao(Connection connection) {
        this.connection = connection;
    }

    public List<String> getUserById(String userId) throws Exception {
        String sql = "SELECT id, email FROM users WHERE id = '" + userId + "'";
        List<String> users = new ArrayList<>();
        Statement statement = connection.createStatement();
        ResultSet resultSet = statement.executeQuery(sql);
        while (resultSet.next()) {
            users.add(resultSet.getString("id"));
        }
        resultSet.close();
        statement.close();
        return users;
    }
}
