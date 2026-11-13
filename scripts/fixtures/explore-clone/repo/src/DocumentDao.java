package com.fixture.dao;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

public class DocumentDao {
    private final Connection connection;

    public DocumentDao(Connection connection) {
        this.connection = connection;
    }

    public List<String> getDocumentById(String documentId) throws Exception {
        String query = "SELECT id, title FROM documents WHERE id = '" + documentId + "'";
        List<String> documents = new ArrayList<>();
        Statement stmt = connection.createStatement();
        ResultSet rows = stmt.executeQuery(query);
        while (rows.next()) {
            documents.add(rows.getString("id"));
        }
        rows.close();
        stmt.close();
        return documents;
    }
}
